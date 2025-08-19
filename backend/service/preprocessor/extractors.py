# backend/service/preprocessor/extractors.py
import re
from ipaddress import ip_address
from dateutil import parser as dt
from typing import Optional, Tuple, List, Dict, Any
from .schema import Entities

IP_RX   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RX = re.compile(r'user:(\w+)|user\s*=\s*(\w+)|for\s+(\w+)', re.I)
FILE_RX = re.compile(r'(/[^ \t\n\r]+)')
# 기존 exe: 또는 process: 패턴 + 일반 exe 파일명
PROC_RX = re.compile(r'(?:exe:|process:)\s*([^\s]+)', re.I)
PROC_NAME_RX = re.compile(r'\b[\w.-]+\.exe\b', re.I)
# 도메인 추출 (간단)
DOM_RX = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.I)

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

def _dedup(xs: List[str]) -> List[str]:
    return list(dict.fromkeys(xs))

def extract_entities(msg: str) -> Entities:
    msg = msg or ""
    ips: List[str] = [m for m in IP_RX.findall(msg) if safe_ip(m)]
    users_raw = [next((g for g in tup if g), None) for tup in USER_RX.findall(msg) if any(tup)]
    users: List[str] = [u for u in users_raw if u]
    files: List[str] = [f for f in FILE_RX.findall(msg) if f != '/']

    procs: List[str] = [p for p in PROC_RX.findall(msg)]
    procs += PROC_NAME_RX.findall(msg)

    domains: List[str] = DOM_RX.findall(msg)

    return Entities(
        ips=_dedup(ips),
        users=_dedup(users),
        files=_dedup(files),
        processes=_dedup(procs),
        domains=_dedup(domains),
    )

def infer_hints(
    msg: str,
    log_type: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[str], Optional[str]]:
    m = (msg or "").lower()
    meta = meta or {}

    # 공통
    if "failed login" in m or "failed password" in m:
        return "authentication", "warning"
    if "accepted password" in m or "successful login" in m:
        return "authentication", "info"
    if "/etc/passwd" in m or "file accessed" in m:
        return "file_access", "warning"
    if "reverse shell" in m:
        return "process", "critical"

    # web / waf
    if log_type in ("web", "waf"):
        ua = (meta.get("User-Agent") or "").lower()
        if "sqlmap" in m or "sqlmap" in ua or " or '1'='1" in m or "union select" in m:
            return "web_sqli", "high"
        if log_type == "waf" and ((meta.get("Action") or "").upper() == "BLOCK" or "block" in m):
            return "waf_block", "high"

    # proxy
    if log_type == "proxy":
        try:
            size = float(meta.get("Size(MB)") or meta.get("Size") or 0)
            if (meta.get("Action") == "UPLOAD") and size >= 40:
                return "data_exfil", "critical"
        except Exception:
            pass

    # db
    if log_type == "db":
        if any(k in m for k in ["credit_card", "credit cards", "ssn", "pii"]):
            return "db_sensitive_read", "high"

    # dns
    if log_type == "dns":
        q = (meta.get("Query") or "").lower()
        if any(s in q for s in ["c2", "badhost", "malware", "beacon"]):
            return "dns_c2", "high"
        return "dns_query", "info"

    # edr
    if log_type == "edr":
        if "powershell" in m and "encodedcommand" in m:
            return "edr_suspicious_powershell", "critical"
        if ".exe" in m and ("suspicious" in m or "unknown" in m):
            return "edr_suspicious_binary", "high"

    # firewall
    if log_type == "firewall":
        if (meta.get("Action") or "").upper() == "BLOCK":
            return "fw_block", "medium"

    return None, None
