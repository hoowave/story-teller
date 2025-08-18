# iso(), safe_ip(), extract_entities(), infer_hints()

import re
from ipaddress import ip_address
from dateutil import parser as dt
from .schema import Entities

# IPv4, 사용자, 파일경로, 프로세스 패턴(간이)
IP_RX   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
USER_RX = re.compile(r'user:(\w+)|user\s*=\s*(\w+)|for\s+(\w+)', re.I)
FILE_RX = re.compile(r'(/[^ \t\n\r]+)')               # 공백 아닌 /path
PROC_RX = re.compile(r'(?:exe:|process:)\s*([^\s]+)', re.I)

def iso(s: str) -> str | None:
    """아무 날짜 문자열을 ISO8601 로 변환(실패 시 None)"""
    try:
        return dt.parse(s).astimezone().isoformat()
    except Exception:
        return None

def safe_ip(s: str) -> str | None:
    """ip 문자열 검증(유효하면 그대로 반환)"""
    try:
        ip_address(s); return s
    except Exception:
        return None

def extract_entities(msg: str) -> Entities:
    """메시지에서 ip/유저/파일/프로세스 등을 추출"""
    msg = msg or ""
    ips   = [m for m in IP_RX.findall(msg) if safe_ip(m)]
    users = [next((g for g in tup if g), None) for tup in USER_RX.findall(msg) if any(tup)]
    files = [f for f in FILE_RX.findall(msg) if f != '/']
    procs = [p for p in PROC_RX.findall(msg)]
    return Entities(ips=ips, users=users, files=files, processes=procs)

def infer_hints(msg: str) -> tuple[str | None, str | None]:
    """간단한 규칙 기반 이벤트/심각도 힌트"""
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
