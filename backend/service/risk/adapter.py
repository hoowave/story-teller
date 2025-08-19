# adapter.py
from urllib.parse import urlparse
from datetime import timezone
import re

def _guess_event_type(e):
    # Stage-1의 hint를 최대한 그대로 활용
    h = (e.get("event_type_hint") or "").lower()
    msg = (e.get("msg") or "").lower()

    if h in {"web_sqli", "sqli"}:
        return "sqli"
    if h in {"authentication", "auth"}:
        # 실패로그가 연속으로 발생하면 bruteforce로 해석(클러스터링에서 volume로 반영)
        return "bruteforce" if "failed" in msg or "fail" in msg else "auth_bypass"
    if "db_sensitive_read" in h:
        return "db_sensitive_read"
    if "exfil" in h:
        return "data_exfil"
    return "other"

def _guess_target_asset(e):
    st = (e.get("source_type") or "").lower()
    path = ""
    # 파일 경로나 URL이 있으면 사용
    files = (e.get("entities") or {}).get("files") or []
    if files:
        path = files[0]
    else:
        path = (e.get("msg") or "")

    path_l = path.lower()

    if st in {"web","waf"}:
        if re.search(r"/(login|signin|auth|session)", path_l):
            return "auth"
        if re.search(r"/(admin|manage)", path_l):
            return "admin"
        return "public_static"
    if st in {"db","database"}:
        return "db"
    if st in {"auth","system_auth"}:
        return "auth"
    return "other"

def _hints(e):
    hs = []
    h = (e.get("event_type_hint") or "").lower()
    if h == "web_sqli":
        hs.append("web_sqli")
    if "db_sensitive_read" in h:
        hs.append("db_sensitive_read")
    if "exfil" in h:
        hs.append("data_exfil")
    # 웹 메시지에 SQLi 패턴이 보이면 힌트 추가
    if " or '1'='1" in (e.get("msg") or "").lower():
        hs.append("web_sqli")
    # WAF/IDS가 차단/탐지했다고 meta에 표시된 경우
    action = ((e.get("meta") or {}).get("Action") or "").upper()
    if action in {"BLOCK","WAF_BLOCK","DETECT_SQLI","DETECT","DENY"}:
        hs.append("waf_block")
    return list(dict.fromkeys(hs))  # 중복 제거

def _action(e):
    # meta.Action이나 severity를 이용해 대략 매핑
    act = ((e.get("meta") or {}).get("Action") or "").upper()
    if act in {"BLOCK","DENY","DROP"}:
        return "block"
    if act in {"ALLOW","PERMIT"}:
        return "allow"
    if "DETECT" in act:
        return "alert"
    # 없으면 severity로 추정
    sev = (e.get("severity_hint") or "").lower()
    if sev in {"high","critical"}:
        return "alert"
    return "allow"  # 보수적으로

def _confidence(e):
    # parsing_confidence(0~1) → 기본 확신도로 사용
    pc = e.get("parsing_confidence")
    try:
        return float(pc) if pc is not None else 0.7
    except:
        return 0.7

def adapt_stage1_event(e):
    """Stage-1 1건을 RiskScorer 입력 포맷으로 변환"""
    return {
        "event_id": f"{e.get('ingest_id')}::{e.get('ts')}",
        "ts": (e.get("ts") or "").replace("Z","+00:00"),
        "source_type": (e.get("source_type") or "").lower(),
        "event_type": _guess_event_type(e),
        "src_ip": e.get("src_ip"),
        "target_asset": _guess_target_asset(e),
        "auth_context": "failed" if "fail" in (e.get("msg") or "").lower() else "unknown",
        "action": _action(e),
        "confidence": _confidence(e),       # 0.0~1.0
        "hints": _hints(e),
        "meta": e.get("meta") or {},
        # cluster_id는 없으면 4단계에서 휴리스틱으로 묶음
    }

def adapt_stage1_batch(payload):
    """ingest/lines 응답 전체에서 sample/lines 배열을 4단계 입력으로 변환"""
    lines = payload.get("lines") or payload.get("sample") or []
    return [adapt_stage1_event(e) for e in lines]
