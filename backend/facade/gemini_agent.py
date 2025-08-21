from __future__ import annotations
import json, argparse, re, time
from pathlib import Path
from typing import Dict, Any, List, Optional

from facade.story.cluster_adapter import load_cluster_report
from facade.story.story_llm import chat_completion

class GeminiAgent:
    def __init__(self):

        # 시스템 프롬프트 설정
        self.SYSTEM_PROMPT = """당신은 보안 관제 센터의 시니어 분석가입니다.
        아래 정보를 바탕으로 **현장감 있는 사이버 공격 상황 요약**을 작성하되, 반드시 지정된 JSON 스키마 하나만 출력하세요.
        - '현재상황'은 지금 관찰된 팩트(이벤트/로그) 중심의 현장 묘사.
        - '예상시나리오'는 기술/ATT&CK 기반 **단정적** 기술(불확실/추측/가능성 표현 금지).
        - '권장대응'은 번호가 포함된 문자열 배열(예: '1. ...','2. ...').
        - '근거' 배열에 타임스탬프/출처/참조ID를 명시.
        - 과장/허위 금지, 한국어로 작성.
        - 출력은 JSON 객체 하나만. 코드블록/서론/후기 금지.
        """

        # 사용자 프롬프트 설정
        self.STORY_PROMPT = """
        [참고 데이터]
        - 위험도 요약: {risk_summary}
        - 클러스터링 요약: {cluster_summary}
        - 이벤트 샘플: {events_summary}

        [스키마]
        {{
        "LLM 응답": [
            {{
            "현재상황": "팩트 기반 현장 묘사 (1~2문단)",
            "예상시나리오": "기술/ATT&CK 기반으로 단정적으로 기술 (불확실/추측 표현 금지)",
            "심각도": "Critical|High|Medium|Low|Info",
            "위험도점수": 0.0,
            "추정정확도": 0.0,
            "영향범위": ["...","..."],
            "근거": [
                {{"시간":"ISO8601","출처":"risk|cluster|event","요약":"한 줄","참조":{{"cluster_id":"...","event_id":"..."}}}}
            ],
            "권장대응": ["1. ...","2. ...","3. ..."]
            }}
        ]
        }}

        [지침]
        - '현재상황'은 시각/원본 IP/대상 자산/행동을 구체적으로. (예: "새벽 02:00, 192.168.1.1에서 admin 계정 로그인 직후 ...")
        - '예상시나리오'에는 가능하면 ATT&CK 전술/기법 코드를 대괄호로 명시 (예: [TA0006, T1078]).
        - '심각도'와 '위험도점수(0~10)'는 입력 지표에 비례해 보수적으로 책정.
        - '영향범위'는 시스템/계정/데이터 등 실제 영향 대상 중심.
        - '권장대응'은 즉시 실행 가능한 조치 위주(계정 잠금, IP 차단, 로그 보존, 세그멘테이션, 접근권한 재검토 등).
        - **불확실/추측/가능성/추가 조사 필요** 등의 표현 금지. 단정적 문장만 사용.
        """
    
    def request(self):
        # 기본 경로 및 파라미터 직접 지정
        project_root = Path(__file__).parent.parent
        default_risk = project_root / "facade" / "data" / "risk_output.json"
        default_cluster = project_root / "facade" / "data" / "cluster_output_2.json"
        default_events = ""  # 없으면 빈 문자열
        default_out = project_root / "facade" / "data" / "story_output.json"
        default_backend = "gemini"
        default_model = "gemini-1.5-flash"

        max_retries = 3
        temperature = 0.7
        endpoint = None

        # 입력 로드
        risk = self._load_json(default_risk)
        events_json = self._load_json(default_events) if default_events else None
        cluster_loaded = load_cluster_report(default_cluster)

        # 요약 생성
        risk_summary = self._summarize_risk(risk, top_k=8)
        cluster_summary = self._summarize_cluster(cluster_loaded)
        events_summary = self._summarize_events(events_json, max_items=120) if events_json else []
        
        def build_messages(rk: dict, cl: dict, ev: List[dict]) -> List[dict]:
            user_prompt = self.STORY_PROMPT.format(
                risk_summary=json.dumps(rk, ensure_ascii=False, indent=2),
                cluster_summary=json.dumps(cl, ensure_ascii=False, indent=2),
                events_summary=json.dumps(ev, ensure_ascii=False, indent=2),
            )
            return [
                {"role":"system","content": self.SYSTEM_PROMPT},
                {"role":"user","content": user_prompt},
            ]

        messages = build_messages(risk_summary, cluster_summary, events_summary)

        # 폴백 후보 (예: Gemini 계열)
        fallback_models = [default_model, "gemini-1.5-flash", "gemini-1.5-flash-8b"] \
            if default_backend == "gemini" else []

        last_err = None
        for attempt in range(max_retries + 1):
            try:
                model_to_use = fallback_models[min(attempt, len(fallback_models)-1)] if fallback_models else default_model
                text = chat_completion(
                    backend=default_backend,
                    model=model_to_use,
                    messages=messages,
                    temperature=temperature,
                    endpoint=endpoint
                )
                cand = self._first_json(text)
                obj = json.loads(cand)
                self._validate_response_json(obj)

                Path(default_out).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
                print(f"✅ wrote {default_out} (model={model_to_use})")
                return

            except Exception as e:
                last_err = e
                err_str = str(e)
                # 429/쿼터/토큰 초과 → 입력 축소 + 프롬프트 엄격화 + 다음 모델 폴백
                if "429" in err_str or "quota" in err_str.lower() or "token" in err_str.lower():
                    if attempt == 0:
                        risk_summary_local = self._summarize_risk(risk or {}, top_k=5)
                        events_summary_local = events_summary[:60]
                    elif attempt == 1:
                        risk_summary_local = self._summarize_risk(risk or {}, top_k=3)
                        events_summary_local = events_summary[:30]
                    else:
                        risk_summary_local = self._summarize_risk(risk or {}, top_k=1)
                        events_summary_local = []
                    messages = build_messages(risk_summary_local, cluster_summary, events_summary_local)
                    messages[0]["content"] = self.SYSTEM_PROMPT + "\n반드시 위 JSON 스키마 하나만 출력. 불확실/가능성 표현 금지."
                    time.sleep(1.2)
                else:
                    time.sleep(0.8)

        raise SystemExit(f"❌ LLM 응답 처리 실패: {last_err}")

    # ──────────────────────────────────────────────────────────────
    # 헬퍼들
    # ──────────────────────────────────────────────────────────────

    def _load_json(self, path: Optional[str]) -> Optional[dict]:
        if not path:
            return None
        p = Path(path)
        return json.loads(p.read_text(encoding="utf-8"))

    def _time_window_from_risk(self, risk: dict) -> Dict[str, str]:
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

    def _summarize_risk(self, risk: dict, top_k: int = 8) -> Dict[str, Any]:
        if not risk:
            return {}
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
        return {"top_groups": sm, "policy_version": risk.get("policy_version"), "time_window": self._time_window_from_risk(risk)}

    def _summarize_events(self, events_json: dict, max_items: int = 120) -> List[Dict[str, Any]]:
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

    def _summarize_cluster(self, cluster_data: dict) -> Dict[str, Any]:
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

    def _first_json(self, text: str) -> str:
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

    def _validate_response_json(self, obj: dict) -> None:
        if not isinstance(obj, dict):
            raise ValueError("최상위는 JSON 객체여야 합니다.")
        if "LLM 응답" not in obj:
            raise ValueError("'LLM 응답' 키가 필요합니다.")
        arr = obj["LLM 응답"]
        if not isinstance(arr, list) or len(arr) == 0:
            raise ValueError("'LLM 응답'은 비어있지 않은 배열이어야 합니다.")
        for i, it in enumerate(arr):
            for k in ["현재상황","예상시나리오","심각도","위험도점수","추정정확도","영향범위","근거","권장대응"]:
                if k not in it:
                    raise ValueError(f"LLM 응답[{i}] 누락 키: {k}")
            if not isinstance(it["권장대응"], list) or not all(isinstance(x, str) and (x.strip().startswith("1.") or x.strip()[0].isdigit()) for x in it["권장대응"]):
                raise ValueError(f"LLM 응답[{i}].권장대응은 번호 포함 문자열 배열이어야 합니다.")
            if not isinstance(it["영향범위"], list):
                raise ValueError(f"LLM 응답[{i}].영향범위는 배열이어야 합니다.")
            if not isinstance(it["근거"], list) or len(it["근거"]) == 0:
                raise ValueError(f"LLM 응답[{i}].근거는 비어있지 않은 배열이어야 합니다.")
            if not (isinstance(it["위험도점수"], (int,float)) and 0.0 <= float(it["위험도점수"]) <= 10.0):
                raise ValueError(f"LLM 응답[{i}].위험도점수는 0~10 사이 수치여야 합니다.")
            if not (isinstance(it["추정정확도"], (int,float)) and 0.0 <= float(it["추정정확도"]) <= 1.0):
                raise ValueError(f"LLM 응답[{i}].추정정확도는 0.0~1.0 사이 수치여야 합니다.")