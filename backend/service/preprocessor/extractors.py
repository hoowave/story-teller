# iso(), safe_ip(), extract_entities(), infer_hints()

import re
from ipaddress import ip_address
from dateutil import parser as dt
from typing import Optional, Tuple, List
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
    # 중복 제거(입력 순서 유지)
    dedup = lambda xs: list(dict.fromkeys(xs))
    return Entities(
        ips=dedup(ips), users=dedup(users), files=dedup(files), processes=dedup(procs)
    )

def infer_hints(msg: str) -> Tuple[Optional[str], Optional[str]]:
    m = (msg or "").lower()
    if "failed login" in m or "failed password" in m:
        return "authentication", "warning"
    if "successful login" in m:
        return "authentication", "info"
    if "/etc/passwd" in m or "file accessed" in m:
        return "file_access", "warning"
    if "nc.exe" in m or "reverse shell" in m:
        return "process", "critical"
    return None, None
