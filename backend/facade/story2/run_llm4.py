# -*- coding: utf-8 -*-
"""
risk_output.json + cluster 리포트(+선택 events) -> 기술 분석 기반의 JSON + 요약 동시 출력
- 수정된 출력 스키마:
{
  "LLM 응답": [
    {
      "현재상황": "현장감 있는 서술 (1~2문단)",
      "권장대응": ["1. ...", "2. ..."],
      "주요_위협_지표": {
          "IP": ["192.168.1.1", "192.168.1.2"],
          "계정": ["admin", "johndoe"],
          "파일/경로": ["/var/log/access.log"]
      },
      "종합_위험도": "높음"
    }
  ],
  "예상_시나리오": {
    "시나리오_명": "내부 계정 탈취를 통한 측면 이동 공격",
    "공격_단계별_분석": [
      {
        "단계": "Initial Access & Privilege Escalation",
        "기술": "T1078 (Valid Accounts)",
        "설명": "공격자가 어떤 방식으로든 'admin' 계정 정보를 탈취하여 내부 네트워크(192.168.1.1)에서 시스템에 정상적으로 로그인함.",
        "관련_로그": ["인증 로그", "시스템 로그"]
      },
      ...
    ]
  }
}
"""

from __future__ import annotations
import json, argparse, re, time
from pathlib import Path
from typing import Dict, Any, List, Optional

from cluster_adapter2 import load_cluster_report
from story_llm2 import chat_completion  # Gemini/OpenAI/Ollama 호출

# ──────────────────────────────────────────────────────────────
# 프롬프트 (--- 변경된 부분 ---)
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """당신은 보안 관제 센터의 시니어 분석가입니다.
아래 정보를 바탕으로 **MITRE ATT&CK 프레임워크를 활용한 기술 기반의 사이버 공격 분석 보고서**를 작성하세요.
반드시 아래에 지정된 JSON 스키마 하나만 출력해야 합니다.
- 'LLM 응답'에는 현재상황, 권장대응, 주요 위협 지표(IoC), 종합 위험도를 포함합니다.
- '예상_시나리오'에는 공격 단계를 MITRE ATT&CK 기술과 매핑하여 구체적으로 분석합니다.
- 과장하지 말고, 근거가 약한 부분은 '가능성', '추정' 등으로 표현하세요.
- 한국어로 작성하고, 출력은 JSON 객체 하나만 허용됩니다. (코드블록, 서론, 후기 금지)
"""

STORY_PROMPT = """
[참고 데이터]
- 위험도 요약: {risk_summary}
- 클러스터링 요약: {cluster_summary}
- 이벤트 샘플: {events_summary}

[출력 스키마]
{{
  "LLM 응답": [
    {{
      "현재상황": "소설처럼 현장감 있는 한두 문단. 시간, 장소, 행위자, 대상 자산을 명확하게 서술.",
      "권장대응": ["1. 즉시 관리자 계정 잠금 및 비밀번호 변경", "2. 의심 IP 주소 네트워크 접근 차단", "3. 관련 시스템 로그 및 파일 백업 후 포렌식 분석 개시"],
      "주요_위협_지표": {{
          "IP": ["의심스러운 출발지/목적지 IP 주소 배열"],
          "계정": ["관련된 사용자 계정 배열"],
          "파일/경로": ["접근/수정된 파일 또는 경로 배열"]
      }},
      "종합_위험도": "높음 (High) / 중간 (Medium) / 낮음 (Low) 중 하나로 평가"
    }}
  ],
  "예상_시나리오": {{
    "시나리오_명": "공격 시나리오의 핵심을 요약한 이름 (예: 웹 취약점을 통한 내부망 침투 및 데이터 유출)",
    "공격_단계별_분석": [
      {{
        "단계": "Initial Access (초기 침투)",
        "기술": "T1190 - Exploit Public-Facing Application (공개용 애플리케이션 악용)",
        "설명": "공격자가 외부에 노출된 웹 서버의 알려진 취약점을 이용하여 시스템에 최초로 접근했을 가능성이 있습니다.",
        "관련_로그": ["웹 서버 접근 로그", "WAF 로그", "방화벽 로그"]
      }},
      {{
        "단계": "Privilege Escalation (권한 상승)",
        "기술": "T1548 - Abuse Elevation Control Mechanism (권한 상승 제어 메커니즘 악용)",
        "설명": "침투 후, 공격자는 시스템 내 취약점을 이용해 일반 사용자 권한에서 관리자(root) 권한으로 상승을 시도합니다.",
        "관련_로그": ["시스템 로그", "인증 로그"]
      }},
      {{
        "단계": "Discovery (정보 수집)",
        "기술": "T1083 - File and Directory Discovery (파일 및 디렉터리 검색)",
        "설명": "관리자 권한을 획득한 공격자는 추가 공격 및 측면 이동을 위해 시스템의 주요 파일 및 로그(/var/log/access.log)를 탐색합니다.",
        "관련_로그": ["파일 접근 로그", "시스템 명령어 실행 로그"]
      }}
    ]
  }}
}}

[지침]
- '권장대응'은 각 항목이 '1. ', '2. '처럼 번호로 시작하는 문자열 배열이어야 합니다.
- '공격_단계별_분석'의 '기술' 필드는 가급적 MITRE ATT&CK의 T-code 형식(예: T1078)을 포함하여 작성하세요.
- 반드시 위 JSON 스키마 '그대로' 출력하세요.
"""

# ──────────────────────────────────────────────────────────────
# 헬퍼들
# ──────────────────────────────────────────────────────────────

def _load_json(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))

def _time_window_from_risk(risk: dict) -> Dict[str, str]:
    groups = risk.get("groups", [])
    firsts, lasts = [], []
    for g in groups:
        ctx = g.get("group_context", {})
        if ctx.get("first_seen"):
            firsts.append(ctx["first_seen"])
        if ctx.get("last_seen"):
            lasts.append(ctx["last_seen"])
    first = min(firsts) if firsts else ""
    last = max(lasts) if lasts else ""
    return {"start": first, "end": last}

def _summarize_risk(risk: dict, top_k: int = 8) -> Dict[str, Any]:
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
            "factors": g.get("factors", {}),
        })
    return {"top_groups": sm, "policy_version": risk.get("policy_version"), "time_window": _time_window_from_risk(risk)}

def _summarize_events(events_json: dict, max_items: int = 80) -> List[Dict[str, Any]]:
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
        return {"raw_head": cluster_data.get("summary_lines", [])[:40]}

def _first_json(text: str) -> str:
    """문자열에서 첫 번째 JSON 객체/배열만 추출 (코드블록 안전 제거 포함)."""
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if "\n" in t:
            t = t[t.find("\n")+1:]
        if "```" in t:
            t = t[:t.rfind("```")]
    # 객체/배열 시작 문자 위치 찾기
    for m in re.finditer(r"[\{\[]", t):
        s = m.start()
        stack = 0
        for i in range(s, len(t)):
            ch = t[i]
            if ch in "{[":
                stack += 1
            elif ch in "}]":
                stack -= 1
                if stack == 0:
                    return t[s:i+1]
    return t

# --- 변경된 부분: 유효성 검사 함수 ---
def _validate_analysis_json(obj: dict) -> None:
    """새로운 스키마에 대한 유효성을 검사하는 함수"""
    if not isinstance(obj, dict):
        raise ValueError("최상위는 JSON 객체여야 합니다.")
    
    # 1. 'LLM 응답' 키 검사
    if "LLM 응답" not in obj:
        raise ValueError("최상위 키 'LLM 응답'이 누락되었습니다.")
    
    arr = obj["LLM 응답"]
    if not isinstance(arr, list) or len(arr) == 0:
        raise ValueError("'LLM 응답'은 비어있지 않은 배열이어야 합니다.")
    
    it = arr[0]
    if not isinstance(it, dict):
        raise ValueError("'LLM 응답'의 첫 번째 항목은 객체여야 합니다.")
    
    required_keys_llm = ["현재상황", "권장대응", "주요_위협_지표", "종합_위험도"]
    for k in required_keys_llm:
        if k not in it:
            raise ValueError(f"'LLM 응답' 객체에 '{k}' 키가 누락되었습니다.")
            
    if not isinstance(it["권장대응"], list) or not all(isinstance(x, str) and (x.strip().startswith("1.") or x.strip()[0].isdigit()) for x in it["권장대응"]):
        raise ValueError("'권장대응'은 번호가 포함된 문자열 배열이어야 합니다.")

    if not isinstance(it["주요_위협_지표"], dict):
        raise ValueError("'주요_위협_지표'는 객체여야 합니다.")

    # 2. '예상_시나리오' 키 검사
    if "예상_시나리오" not in obj:
        raise ValueError("최상위 키 '예상_시나리오'가 누락되었습니다.")
        
    scenario = obj["예상_시나리오"]
    if not isinstance(scenario, dict):
        raise ValueError("'예상_시나리오'는 객체여야 합니다.")
        
    if "시나리오_명" not in scenario or "공격_단계별_분석" not in scenario:
        raise ValueError("'예상_시나리오' 객체에 '시나리오_명' 또는 '공격_단계별_분석' 키가 누락되었습니다.")
        
    analysis_steps = scenario["공격_단계별_분석"]
    if not isinstance(analysis_steps, list) or len(analysis_steps) == 0:
        raise ValueError("'공격_단계별_분석'은 비어있지 않은 배열이어야 합니다.")
        
    required_keys_step = ["단계", "기술", "설명", "관련_로그"]
    for i, step in enumerate(analysis_steps):
        if not isinstance(step, dict):
            raise ValueError(f"'공격_단계별_분석'의 {i}번째 항목이 객체가 아닙니다.")
        for k in required_keys_step:
            if k not in step:
                raise ValueError(f"'공격_단계별_분석'의 {i}번째 항목에 '{k}' 키가 누락되었습니다.")

# ──────────────────────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────────────────────

def main():
    default_risk = "risk_output.json"
    default_cluster = "message (1).txt"
    default_events = "sample log2.txt"   # 이름 수정 및 선택사항 명시
    default_out = "analysis_output.json" # 출력 파일 이름 변경
    default_backend = "gemini"
    default_model = "gemini-1.5-flash"

    ap = argparse.ArgumentParser()
    ap.add_argument("--risk", default=default_risk)
    ap.add_argument("--cluster", default=default_cluster)
    ap.add_argument("--events", default=default_events)
    ap.add_argument("--out", default=default_out)
    ap.add_argument("--backend", default=default_backend, choices=["ollama","openai","gemini"])
    ap.add_argument("--model", default=default_model)
    ap.add_argument("--endpoint", default=None)
    ap.add_argument("--temperature", type=float, default=0.1)
    ap.add_argument("--max_retries", type=int, default=3)
    args = ap.parse_args()

    # 입력 로드
    risk = _load_json(args.risk)
    events_json = _load_json(args.events) if args.events else None
    cluster_loaded = load_cluster_report(args.cluster)

    # 요약 생성
    risk_summary = _summarize_risk(risk, top_k=8)
    cluster_summary = _summarize_cluster(cluster_loaded)
    events_summary = _summarize_events(events_json, max_items=80) if events_json else []

    def build_messages(rk: dict, cl: dict, ev: List[dict]) -> List[dict]:
        user_prompt = STORY_PROMPT.format(
            risk_summary=json.dumps(rk, ensure_ascii=False, indent=2),
            cluster_summary=json.dumps(cl, ensure_ascii=False, indent=2),
            events_summary=json.dumps(ev, ensure_ascii=False, indent=2),
        )
        return [
            {"role":"system","content": SYSTEM_PROMPT},
            {"role":"user","content": user_prompt},
        ]

    messages = build_messages(risk_summary, cluster_summary, events_summary)

    fallback_models = []
    if args.backend == "gemini":
        fallback_models = [args.model, "gemini-1.5-flash"]

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
            cand = _first_json(text)
            obj = json.loads(cand)
            _validate_analysis_json(obj) # --- 변경된 부분: 새로운 유효성 검사 함수 호출 ---

            Path(args.out).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"✅ wrote {args.out} (model={model_to_use})")
            return

        except Exception as e:
            last_err = e
            err_str = str(e)
            if "429" in err_str or "quota" in err_str.lower() or "token" in err_str.lower():
                if attempt == 0:
                    risk_summary_local = _summarize_risk(risk, top_k=5)
                    events_summary_local = events_summary[:40]
                elif attempt == 1:
                    risk_summary_local = _summarize_risk(risk, top_k=3)
                    events_summary_local = events_summary[:20]
                else:
                    risk_summary_local = _summarize_risk(risk, top_k=1)
                    events_summary_local = []
                messages = build_messages(risk_summary_local, cluster_summary, events_summary_local)
                messages[0]["content"] = SYSTEM_PROMPT + "\n반드시 지정된 JSON 스키마 하나만 출력하세요. 다른 설명은 절대 추가하지 마세요."
                time.sleep(1.2)
            else:
                time.sleep(0.8)

    raise SystemExit(f"❌ LLM 응답 처리 실패: {last_err}")

if __name__ == "__main__":
    main()