# -*- coding: utf-8 -*-
"""
risk_output.json + cluster 리포트(+선택 events) -> LLM 스토리텔링 JSON
- LLM 필수 호출 (fallback 없음)
- 429/쿼터 초과 시: 모델 폴백 + 입력 축소 + 백오프 재시도

기본값:
  --risk "risk_output.json"
  --cluster "message (1).txt"
  --events "sample log2.txt"
  --out "story_output.json"
  --backend gemini
  --model "gemini-1.5-flash"   # 가벼운 모델 기본
"""
from __future__ import annotations
import json, argparse, re, time
from pathlib import Path
from typing import Dict, Any, List, Optional

from cluster_adapter import load_cluster_report
from story_llm import chat_completion  # Gemini/OpenAI/Ollama 호출

SYSTEM_PROMPT = """당신은 보안 관제 분석가입니다.
- 주어진 위험도 결과와 클러스터링 분석 결과, 이벤트 요약을 바탕으로 사건 스토리를 '반드시' 유효한 JSON으로 작성하세요.
- 과장 금지, 사실 위주, 표준 보안용어 사용.
- 출력은 아래 스키마 '딱 하나의 JSON 객체'만 포함하세요. 코드블록/마크다운/설명 추가 금지.
"""

USER_PROMPT = """[요청 스키마]
{{
  "overall_assessment": {{
    "highest_risk_level": "Critical|High|Medium|Low|Info",
    "key_findings": ["문장", "..."],
    "attack_hypothesis": "가설 2~4문장",
    "time_window": {{"start":"ISO8601","end":"ISO8601"}}
  }},
  "incidents": [
    {{
      "cluster_id": "문자열(있으면)",
      "title": "짧은 사건명",
      "severity": "Critical|High|Medium|Low|Info",
      "actors": {{"users": ["..."], "src_ips": ["..."], "dst_ips": ["..."]}},
      "timeline": [
        {{"ts":"ISO8601","event":"무슨 일","evidence":"메시지/근거"}}
      ],
      "impact": "영향 요약",
      "recommended_actions": ["즉시 조치 3~6개"]
    }}
  ],
  "next_steps": ["추가 조사 3~5개"],
  "assumptions_and_limits": ["가정/제약"]
}}

[위험도 요약(top-k)]
{risk_summary}

[클러스터링 요약]
{cluster_summary}

[이벤트 샘플(선택)]
{events_summary}

지침:
- 타임라인은 위험도 요약의 first_seen/last_seen 및 sample_msgs, 클러스터링 상세(있다면) 근거로 구성
- 데이터가 적을 경우 'assumptions_and_limits'에 명시
- '유효한 JSON 객체'만 출력 (문자열 시작부터 끝까지 JSON 하나만)
"""

def _load_json(path: Optional[str]) -> Optional[dict]:
    if not path: return None
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))

def _time_window_from_risk(risk: dict) -> Dict[str, str]:
    groups = risk.get("groups", [])
    firsts, lasts = [], []
    for g in groups:
        ctx = g.get("group_context", {})
        if ctx.get("first_seen"): firsts.append(ctx["first_seen"])
        if ctx.get("last_seen"): lasts.append(ctx["last_seen"])
    first = min(firsts) if firsts else ""
    last = max(lasts) if lasts else ""
    return {"start": first, "end": last}

def _summarize_risk(risk: dict, top_k: int = 5) -> Dict[str, Any]:
    groups = sorted(risk.get("groups", []), key=lambda g: g.get("risk_score", 0), reverse=True)[:top_k]
    sm = []
    for g in groups:
        ctx = g.get("group_context", {})
        key = ctx.get("key", {})
        sm.append({
            "cluster_id": g.get("cluster_id"),
            "risk_score": g.get("risk_score"),
            "risk_level": g.get("risk_level"),
            "count": ctx.get("count"),
            "first_seen": ctx.get("first_seen"),
            "last_seen": ctx.get("last_seen"),
            "user": key.get("user"),
            "src_ip": key.get("src_ip"),
            "dst_ip": key.get("dst_ip"),
            "event_type_hint": key.get("event_type_hint"),
            "sample_msgs": ctx.get("sample_msgs", []),
            "factors": g.get("factors", {})
        })
    return {"top_groups": sm, "policy_version": risk.get("policy_version"), "time_window": _time_window_from_risk(risk)}

def _summarize_events(events_json: dict, max_items: int = 50) -> List[Dict[str, Any]]:
    items = (events_json or {}).get("events", [])
    out = []
    for e in items[:max_items]:
        out.append({
            "event_id": e.get("event_id") or e.get("ingest_id"),
            "ts": e.get("ts"),
            "type": e.get("event_type_hint"),
            "severity": e.get("severity_hint"),
            "src_ip": e.get("src_ip"),
            "dst_ip": e.get("dst_ip"),
            "users": (e.get("entities") or {}).get("users", []),
            "msg": e.get("msg"),
        })
    return out

def _summarize_cluster(cluster_data: dict) -> Dict[str, Any]:
    if not cluster_data or not isinstance(cluster_data, dict):
        return {}
    parsed = cluster_data.get("parsed")
    if parsed and isinstance(parsed, dict):
        ar = parsed.get("analysis_result", {}) if isinstance(parsed, dict) else {}
        return {
            "metrics": ar.get("metrics"),
            "attack_scenario": ar.get("attack_scenario"),
            "priority_level": (ar.get("priority_level") or ar.get("risk_level")),
            "detailed_analysis": ar.get("detailed_analysis"),
            "recommendations": ar.get("recommendations"),
            "timestamp": parsed.get("timestamp"),
            "analysis_version": parsed.get("analysis_version"),
        }
    else:
        return {"raw_head": cluster_data.get("summary_lines", [])[:30]}

def _first_json_object(text: str) -> str:
    """응답 문자열에서 첫 번째 JSON 객체 블록만 추출."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text[text.find("\n")+1:]
        if "```" in text:
            text = text[:text.rfind("```")]
    start_idxs = [m.start() for m in re.finditer(r"\{", text)]
    for s in start_idxs:
        stack = 0
        for i in range(s, len(text)):
            ch = text[i]
            if ch == "{": stack += 1
            elif ch == "}":
                stack -= 1
                if stack == 0:
                    candidate = text[s:i+1]
                    if len(candidate) >= 10:
                        return candidate
    return text

def _validate_story_json(obj: dict) -> None:
    if not isinstance(obj, dict):
        raise ValueError("top-level JSON must be an object")
    for k in ["overall_assessment", "incidents", "next_steps", "assumptions_and_limits"]:
        if k not in obj:
            raise ValueError(f"missing key: {k}")
    oa = obj["overall_assessment"]
    if not isinstance(oa, dict):
        raise ValueError("overall_assessment must be an object")
    for k in ["highest_risk_level", "key_findings", "attack_hypothesis", "time_window"]:
        if k not in oa:
            raise ValueError(f"overall_assessment missing key: {k}")
    if not isinstance(obj["incidents"], list):
        raise ValueError("incidents must be an array")

def main():
    # ── 기본값 (네 프로젝트 구조 기준) ───────────────────────────
    default_risk = "risk_output.json"
    default_cluster = "message (1).txt"
    default_events = "sample log2.txt"
    default_out = "story_output.json"
    default_backend = "gemini"
    default_model = "gemini-1.5-flash"   # <= 가벼운 모델로 기본값 변경

    ap = argparse.ArgumentParser()
    ap.add_argument("--risk", default=default_risk)
    ap.add_argument("--cluster", default=default_cluster)
    ap.add_argument("--events", default=default_events)
    ap.add_argument("--out", default=default_out)
    ap.add_argument("--backend", default=default_backend, choices=["ollama","openai","gemini"])
    ap.add_argument("--model", default=default_model)
    ap.add_argument("--endpoint", default=None)
    ap.add_argument("--temperature", type=float, default=0.2)
    ap.add_argument("--max_retries", type=int, default=3)  # 재시도 3회로 상향
    args = ap.parse_args()

    # 입력 로드
    risk = _load_json(args.risk)
    events_json = _load_json(args.events) if args.events else None
    cluster_loaded = load_cluster_report(args.cluster)

    # 1차 요약 (baseline)
    risk_summary = _summarize_risk(risk, top_k=5)
    cluster_summary = _summarize_cluster(cluster_loaded)
    events_summary = _summarize_events(events_json, max_items=50) if events_json else []

    def build_messages(rk: dict, cl: dict, ev: List[dict]) -> List[dict]:
        user_prompt = USER_PROMPT.format(
            risk_summary=json.dumps(rk, ensure_ascii=False, indent=2),
            cluster_summary=json.dumps(cl, ensure_ascii=False, indent=2),
            events_summary=json.dumps(ev, ensure_ascii=False, indent=2),
        )
        return [
            {"role":"system","content": SYSTEM_PROMPT},
            {"role":"user","content": user_prompt},
        ]

    messages = build_messages(risk_summary, cluster_summary, events_summary)

    # ── 429/쿼터 초과 대비: 모델 폴백 + 입력 축소 재시도 ─────────────
    fallback_models = []
    if args.backend == "gemini":
        fallback_models = [args.model, "gemini-1.5-flash", "gemini-1.5-flash-8b"]  # 순차 폴백

    last_err = None
    for attempt in range(args.max_retries + 1):
        try:
            model_to_use = fallback_models[min(attempt, len(fallback_models)-1)] if fallback_models else args.model
            text = chat_completion(
                backend=args.backend,
                model=model_to_use,
                messages=messages,
                temperature=args.temperature,
                endpoint=args.endpoint
            )
            cand = _first_json_object(text)
            obj = json.loads(cand)
            _validate_story_json(obj)
            Path(args.out).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"✅ wrote {args.out} (model={model_to_use})")
            return
        except Exception as e:
            last_err = e
            err_str = str(e)
            # 429/쿼터/토큰 초과 신호 → 입력 축소 + 백오프 + 다음 모델 폴백
            if "429" in err_str or "quota" in err_str.lower() or "token" in err_str.lower():
                # 입력 축소: risk top_k ↓, events ↓, 최후엔 events 제거
                if attempt == 0:
                    risk_summary = _summarize_risk(risk, top_k=3)
                    events_summary = events_summary[:20]
                elif attempt == 1:
                    risk_summary = _summarize_risk(risk, top_k=2)
                    events_summary = events_summary[:10]
                else:
                    risk_summary = _summarize_risk(risk, top_k=1)
                    events_summary = []  # events 완전 제거

                messages = build_messages(risk_summary, cluster_summary, events_summary)
                # 프롬프트 엄격화
                messages[0]["content"] = SYSTEM_PROMPT + "\n반드시 JSON만 출력하세요. 코드블록/설명/여분 텍스트 금지."
                time.sleep(1.5)  # 백오프
            else:
                time.sleep(0.8)

    raise SystemExit(f"❌ LLM 응답 JSON 처리 실패: {last_err}")

if __name__ == "__main__":
    main()

