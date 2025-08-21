# 엔티티(IPS/USER/FILES/PROCESSES/DOMAINS) 추출 + 이벤트 힌트 추론
import re
from ipaddress import ip_address
from dateutil import parser as dt
from typing import Optional, Tuple, List, Dict, Any
from .schema import Entities

# IPv4 주소 패턴 (간단 버전)
IP_RX   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# 사용자명 패턴: "user:admin", "user=admin", "for admin" 형태 지원
USER_RX = re.compile(r'user:(\w+)|user\s*=\s*(\w+)|for\s+(\w+)', re.I)
# 파일 경로 패턴: 공백으로 끊기지 않는 절대경로 토큰
FILE_RX = re.compile(r'(/[^ \t\n\r]+)')
# 프로세스/실행파일: "exe:" 또는 "process:" 키, + 일반 *.exe 파일명
PROC_RX = re.compile(r'(?:exe:|process:)\s*([^\s]+)', re.I)
PROC_NAME_RX = re.compile(r'\b[\w.-]+\.exe\b', re.I)
# 도메인(간단) ex) sub.example.com
DOM_RX = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.I)

def iso(s: str) -> Optional[str]:
    """문자열 시각을 ISO8601(로컬 타임존)로 변환. 실패 시 None."""
    try:
        return dt.parse(s).astimezone().isoformat()
    except Exception:
        return None

def safe_ip(s: str) -> Optional[str]:
    """ipaddress로 검증 성공 시 IP 그대로 반환, 실패 시 None."""
    try:
        ip_address(s); return s
    except Exception:
        return None

def _dedup(xs: List[str]) -> List[str]:
    """등장 순서를 유지하며 중복 제거."""
    return list(dict.fromkeys(xs))

def extract_entities(msg: str) -> Entities:
    """
    자유 텍스트(message)에서 엔티티 후보를 추출.
    - IP/USER/FILE/PROCESS/DOMAIN을 가벼운 정규식으로 수집
    - 주의: 'User admin logged in' 같은 문장은 USER_RX에 걸리지 않을 수 있음
            (이 경우는 추후 규칙을 추가할 수 있음)
    """
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
    """
    메시지/로그타입/메타 기반의 가벼운 이벤트 힌트 추론.
    - 결과: (event_type_hint, severity_hint)
    - 규칙은 휴리스틱이며 보강 가능.
    """
    m = (msg or "").lower()
    meta = meta or {}

    # 공통 규칙
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
        # 흔한 SQLi 페이로드 키워드
        if "sqlmap" in m or "sqlmap" in ua or " or '1'='1" in m or "union select" in m:
            return "web_sqli", "high"
        if log_type == "waf" and ((meta.get("Action") or "").upper() == "BLOCK" or "block" in m):
            return "waf_block", "high"

    # proxy (대용량 업로드 → 유출 추정)
    if log_type == "proxy":
        try:
            size = float(meta.get("Size(MB)") or meta.get("Size") or 0)
            if (meta.get("Action") == "UPLOAD") and size >= 40:
                return "data_exfil", "critical"
        except Exception:
            pass

    # db (민감정보 키워드 탐색)
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
