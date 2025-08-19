# iso(), safe_ip(), extract_entities(), infer_hints()

import re
from ipaddress import ip_address
from dateutil import parser as dt
from typing import Optional, Tuple, List, Dict, Any
from .schema import Entities

IP_RX   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RX = re.compile(r'user:(\w+)|user\s*=\s*(\w+)|for\s+(\w+)', re.I)
FILE_RX = re.compile(r'(/[^ \t\n\r]+)')
PROC_RX = re.compile(r'(?:exe:|process:)\s*([^\s]+)', re.I)

def iso(s: str) -> Optional[str]:
    try:
        return dt.parse(s).astimezone().isoformat()
    except Exception:
        return None

def safe_ip(s: str) -> Optional[str]:
    try:
        ip_address(s); return s
    except Exception:
        return None

def extract_entities(msg: str) -> Entities:
    msg = msg or ""
    ips: List[str] = [m for m in IP_RX.findall(msg) if safe_ip(m)]
    users_raw = [next((g for g in tup if g), None) for tup in USER_RX.findall(msg) if any(tup)]
    users: List[str] = [u for u in users_raw if u]
    files: List[str] = [f for f in FILE_RX.findall(msg) if f != '/']
    procs: List[str] = [p for p in PROC_RX.findall(msg)]
    dedup = lambda xs: list(dict.fromkeys(xs))
    return Entities(ips=dedup(ips), users=dedup(users), files=dedup(files), processes=dedup(procs))

def infer_hints(
    msg: str,
    log_type: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[str], Optional[str]]:
    """
    간단 룰 기반 힌트 + 로그 타입 컨텍스트 이용.
    """
    m = (msg or "").lower()
    meta = meta or {}

    # 공통(기존)
    if "failed login" in m or "failed password" in m:
        return "authentication", "warning"
    if "successful login" in m:
        return "authentication", "info"
    if "/etc/passwd" in m or "file accessed" in m:
        return "file_access", "warning"
    if "nc.exe" in m or "reverse shell" in m:
        return "process", "critical"

    # web/waf: SQLi 패턴/툴
    if log_type in ("web", "waf"):
        if "sqlmap" in m or " or '1'='1" in m or "union select" in m:
            return "web_sqli", "high"
        if log_type == "waf" and ("block" in m or meta.get("Action") == "BLOCK"):
            return "waf_block", "high"

    # auth: 반복 실패(여기선 단건 힌트만)
    if log_type == "auth":
        if "failed password" in m:
            return "authentication", "warning"

    # proxy: 대용량 업로드(간이 임계값)
    if log_type == "proxy":
        try:
            size = float(meta.get("Size(MB)") or 0)
            if meta.get("Action") == "UPLOAD" and size >= 40:
                return "data_exfil", "critical"
        except Exception:
            pass

    # db: 민감 테이블 접근
    if log_type == "db":
        if any(k in m for k in ["credit_card", "credit cards", "ssn", "pii"]):
            return "db_sensitive_read", "high"

    return None, None
