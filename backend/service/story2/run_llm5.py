# -*- coding: utf-8 -*-
"""
risk_output.json + cluster 리포트(+선택 events)
→ '현재상태(관측 사실) + 예상_시나리오(가설 분기) + 대응책' 스키마로 스토리텔링 JSON 생성

실행 예:
  python run_llm6.py --risk risk_output.json --cluster "message (1).txt" --events "sample log2.txt" \
    --out output2.json --backend gemini --model gemini-1.5-flash
"""

from __future__ import annotations
import json, argparse, re, time
from pathlib import Path
from typing import Dict, Any, List, Optional

from cluster_adapter2 import load_cluster_report       # 프로젝트 내 모듈
from story_llm2 import chat_completion                 # 프로젝트 내 모듈

# ──────────────────────────────────────────────────────────────
# 프롬프트
# ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """당신은 보안 관제 센터의 시니어 분석가입니다.
아래 정보를 바탕으로, 관측된 사실(현재상태)과 그로부터 파생 가능한 '예상 시나리오(가설 분기)'를 명확히 구분하여 작성하세요.
반드시 아래 지정된 JSON 스키마(단 하나)만 출력해야 합니다. (코드블록, 서론, 후기는 금지)

핵심 원칙
- '현재상태'는 로그/요약에서 직접 관측된 사실만 기술합니다(추정 금지).
- '예상_시나리오'는 2~3개의 '가설' 분기로 작성하며, 각 가설마다 근거/ATT&CK 매핑/확신도/추가 관찰 신호/무력화 조건을 포함합니다.
- '대응책'은 공통 즉시/중장기 조치 + (선택) 분기별 추가조치를 포함합니다.
- 과장 금지. 근거가 약한 부분은 '가능성', '추정' 등으로 표현하세요.
- 한국어로 작성하고, 출력은 JSON 객체 하나만 허용됩니다.
"""

# str.format 충돌 방지를 위해 리터럴 중괄호는 {{ }} 로 이스케이프
STORY_PROMPT = """
[참고 데이터]
- 위험도 요약: {risk_summary}
- 클러스터링 요약: {cluster_summary}
- 이벤트 샘플: {events_summary}

[출력 스키마]
{{
  "현재상태": {{
    "요약": "관측된 사실 기반 한두 문단. 시간/행위자/대상 자산/이벤트 종류를 명확히. 추정 금지.",
    "주요_증거": {{
      "타임라인": [
        "YYYY-MM-DD HH:MM:SS - admin이 192.168.1.1에서 로그인 (authentication)",
        "YYYY-MM-DD HH:MM:SS - johndoe가 /var/log/access.log 접근 (file_access)"
      ],
      "IoC": {{
        "IP": ["192.168.1.1", "192.168.1.2"],
        "계정": ["admin", "johndoe"],
        "파일/경로": ["/var/log/access.log"]
      }}
    }}
  }},
  "예상_시나리오": [
    {{
      "가설명": "내부 계정 탈취 통한 측면 이동",
      "근거": ["관리자 계정 로그인 직후 타 계정의 민감 로그 접근", "단시간 내 다수 IP 사용"],
      "ATT&CK": ["T1078 Valid Accounts", "T1021 Remote Services"],
      "상대확신도": "중간",
      "관찰_필요_신호": ["동일 출발지에서 다른 서버로의 인증 성공/시도", "관리자/서비스 계정의 비정상 시간대 로그인"],
      "무력화_조건": ["다계정 사용의 합법적 업무 패턴 확인", "접근 경로가 정상 Bastion/Jumphost로 검증됨"]
    }},
    {{
      "가설명": "운영상 오탑재/권한 오구성으로 인한 과도 권한 접근",
      "근거": ["일반 사용자 계정이 민감 로그 파일 접근", "WAF/IDS 경보 미동반"],
      "ATT&CK": ["T1069 Permission Groups Discovery"],
      "상대확신도": "보통",
      "관찰_필요_신호": ["동일 사용자/그룹의 다른 민감 경로 접근", "권한 변경 이벤트 로그"],
      "무력화_조건": ["RBAC/ACL 점검 결과 정상 권한으로 확인", "변경 이력에 따라 합법적 승인 존재"]
    }}
  ],
  "대응책": {{
    "즉시 조치": [
      "1. 관련 계정(admin, johndoe) 임시잠금 또는 추가 인증 강제(MFA)",
      "2. 의심 IP(192.168.1.1, 192.168.1.2) 세그먼트 격리 또는 차단 룰 일시 적용",
      "3. /var/log/access.log 및 관련 시스템 로그 백업 후 무결성 보존(포렌식 준비)"
    ],
    "중장기 조치": [
      "1. 최소권한 원칙 재적용 및 RBAC/ACL 정비",
      "2. 고위험 자산 접근에 대한 Just-In-Time 권한/승인 워크플로 도입",
      "3. 이상행위 탐지 룰/WAF 정책 강화 및 주기적 모의훈련"
    ],
    "분기별_추가조치": [
      {{
        "대상_가설": "내부 계정 탈취 통한 측면 이동",
        "추가조치": [
          "1. 의심 세션 토큰/키 폐기 및 전체 강제 재인증",
          "2. Lateral Movement 징후(새로운 자산 인증/SMB/RDP/SSH 시도) 핫워치 룰 적용"
        ]
      }},
      {{
        "대상_가설": "운영상 오탑재/권한 오구성으로 인한 과도 권한 접근",
        "추가조치": [
          "1. 민감 로그 경로 접근 정책 재정의(읽기 전용 서비스 계정 분리)",
          "2. 변경관리(CMDB)와 권한 변경 이력 자동 대조 파이프라인 구축"
        ]
      }}
    ]
  }}
}}

[지침]
- '현재상태'에는 추정/가정 표현을 넣지 마세요(오직 관측 사실).
- '예상_시나리오'는 최소 2개 가설을 제시하고, 각 항목을 채우세요.
- '대응책'의 항목은 '1. '처럼 번호로 시작하는 문자열 배열이어야 하며, '분기별_추가조치'는 선택적으로 포함합니다.
"""

# ──────────────────────────────────────────────────────────────
# 헬퍼
# ──────────────────────────────────────────────────────────────

def _load_json(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def _time_window_from_risk(risk: dict) -> Dict[str, str]:
    groups = (risk or {}).get("groups", [])
    firsts, lasts = [], []
    for g in groups:
        ctx = g.get("group_context", {}) or {}
        if ctx.get("first_seen"):
            firsts.append(ctx["first_seen"])
        if ctx.get("last_seen"):
            lasts.append(ctx["last_seen"])
    first = min(firsts) if firsts else ""
    last = max(lasts) if lasts else ""
    return {"start": first, "end": last}

def _summarize_risk(risk: dict, top_k: int = 8) -> Dict[str, Any]:
    groups = sorted((risk or {}).get("groups", []), key=lambda g: g.get("risk_score", 0), reverse=True)[:top_k]
    sm = []
    for g in groups:
        ctx = g.get("group_context", {}) or {}
        key = ctx.get("key", {}) or {}
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
    return {
        "top_groups": sm,
        "policy_version": (risk or {}).get("policy_version"),
        "time_window": _time_window_from_risk(risk or {})
    }

def _summarize_events(events_json: dict, max_items: int = 80) -> List[Dict[str, Any]]:
    items = (events_json or {}).get("events", []) or []
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
    if not text:
        return "{}"
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if "\n" in t:
            t = t[t.find("\n")+1:]
        if "```" in t:
            t = t[:t.rfind("```")]
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

# ──────────────────────────────────────────────────────────────
# 스키마 유효성 검사 (현재상태 + 예상_시나리오 + 대응책)
# ──────────────────────────────────────────────────────────────

def _validate_analysis_json(obj: dict) -> None:
    if not isinstance(obj, dict):
        raise ValueError("최상위는 JSON 객체여야 합니다.")
    for k in ["현재상태", "예상_시나리오", "대응책"]:
        if k not in obj:
            raise ValueError(f"최상위 키 '{k}'가 누락되었습니다.")

    # 현재상태
    cs = obj["현재상태"]
    if not isinstance(cs, dict):
        raise ValueError("'현재상태'는 객체여야 합니다.")
    for k in ["요약", "주요_증거"]:
        if k not in cs:
            raise ValueError(f"'현재상태'에 '{k}' 키가 누락되었습니다.")
    ev = cs["주요_증거"]
    if not isinstance(ev, dict):
        raise ValueError("'현재상태.주요_증거'는 객체여야 합니다.")
    if "타임라인" not in ev or "IoC" not in ev:
        raise ValueError("'현재상태.주요_증거'에 '타임라인' 또는 'IoC'가 누락되었습니다.")
    if not isinstance(ev["타임라인"], list):
        raise ValueError("'타임라인'은 배열이어야 합니다.")
    if not isinstance(ev["IoC"], dict):
        raise ValueError("'IoC'는 객체여야 합니다.")

    # 예상_시나리오
    hyps = obj["예상_시나리오"]
    if not isinstance(hyps, list) or len(hyps) < 1:
        raise ValueError("'예상_시나리오'는 1개 이상 항목의 배열이어야 합니다.")
    req_h = ["가설명", "근거", "ATT&CK", "상대확신도", "관찰_필요_신호", "무력화_조건"]
    for i, h in enumerate(hyps):
        if not isinstance(h, dict):
            raise ValueError(f"'예상_시나리오[{i}]'는 객체여야 합니다.")
        for k in req_h:
            if k not in h:
                raise ValueError(f"'예상_시나리오[{i}]'에 '{k}' 키가 누락되었습니다.")
        for arr_key in ["근거", "ATT&CK", "관찰_필요_신호", "무력화_조건"]:
            if not isinstance(h[arr_key], list):
                raise ValueError(f"'예상_시나리오[{i}].{arr_key}'는 배열이어야 합니다.")

    # 대응책
    act = obj["대응책"]
    if not isinstance(act, dict):
        raise ValueError("'대응책'은 객체여야 합니다.")
    for k in ["즉시 조치", "중장기 조치"]:
        if k not in act:
            raise ValueError(f"'대응책'에 '{k}' 키가 누락되었습니다.")
        arr = act[k]
        if not isinstance(arr, list) or len(arr) == 0:
            raise ValueError(f"'{k}'은 비어있지 않은 배열이어야 합니다.")
        if not all(isinstance(x, str) and x.strip()[0].isdigit() and x.strip()[1:2] == "." for x in arr):
            raise ValueError(f"'{k}'의 각 항목은 '1. ...'처럼 번호로 시작하는 문자열이어야 합니다.")
    # 선택: 분기별_추가조치
    if "분기별_추가조치" in act:
        b = act["분기별_추가조치"]
        if not isinstance(b, list):
            raise ValueError("'분기별_추가조치'는 배열이어야 합니다.")
        for i, item in enumerate(b):
            if not isinstance(item, dict):
                raise ValueError(f"'분기별_추가조치[{i}]'는 객체여야 합니다.")
            if "대상_가설" not in item or "추가조치" not in item:
                raise ValueError(f"'분기별_추가조치[{i}]'에 '대상_가설' 또는 '추가조치' 누락.")
            if not isinstance(item["추가조치"], list) or not all(
                isinstance(x, str) and x.strip()[0].isdigit() and x.strip()[1:2] == "."
                for x in item["추가조치"]
            ):
                raise ValueError(f"'분기별_추가조치[{i}].추가조치'의 각 항목은 번호로 시작하는 문자열이어야 합니다.")

# ──────────────────────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────────────────────

def main():
    default_risk = "risk_output.json"
    default_cluster = "message (1).txt"
    default_events = "sample log2.txt"        # 선택사항
    default_out = "output2.json"
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
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    messages = build_messages(risk_summary, cluster_summary, events_summary)

    # 백엔드별 폴백 모델 설정
    fallback_models = []
    if args.backend == "gemini":
        fallback_models = [args.model, "gemini-1.5-flash"]
    elif args.backend == "openai":
        fallback_models = [args.model]
    elif args.backend == "ollama":
        fallback_models = [args.model]

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
            _validate_analysis_json(obj)

            Path(args.out).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"✅ wrote {args.out} (model={model_to_use})")
            return

        except Exception as e:
            last_err = e
            err_str = str(e)
            # 재시도: 토큰/쿼터/429 등일 때 페이로드 축소 + 지침 강화
            if any(k in err_str.lower() for k in ["429", "quota", "token", "rate"]):
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
                time.sleep(1.0)
            else:
                time.sleep(0.6)

    raise SystemExit(f"❌ LLM 응답 처리 실패: {last_err}")

if __name__ == "__main__":
    main()

