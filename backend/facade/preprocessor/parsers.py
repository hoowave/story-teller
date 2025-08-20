# CSV/텍스트/ZIP 파서: 다양한 소스 필드를 표준 키로 매핑
import io, csv, json, zipfile
from typing import List, Dict, Any, Optional
from .extractors import iso

def _int_or_none(x: Optional[str]) -> Optional[int]:
    """정수로 변환 가능하면 int, 아니면 None."""
    try:
        return int(x) if x not in (None, "") else None
    except Exception:
        return None

def _lower_map(fieldnames: List[str]) -> Dict[str, str]:
    """원본 필드명을 소문자 키로 매핑 (케이스 민감도 완화용)."""
    return {k.lower(): k for k in fieldnames}

def _has(fmap: Dict[str, str], *keys) -> bool:
    """필수 키(대소문자 무시)가 모두 존재하는지 확인."""
    return all(k.lower() in fmap for k in keys)

def _detect_log_type(fieldnames: List[str]) -> str:
    """
    CSV 헤더를 기반으로 로그 타입 추정.
    - firewall/web/waf/proxy/db/auth/dns/edr 를 먼저 시도, 실패 시 'csv' 반환
    """
    f = _lower_map(fieldnames)

    # firewall
    if _has(f, "protocol", "source ip", "destination ip", "source port", "destination port"):
        return "firewall"
    # web (두 가지 케이스 지원)
    if _has(f, "request") or _has(f, "client ip", "method", "url"):
        return "web"
    # waf (Client IP를 쓰는 케이스 지원)
    if _has(f, "target", "action", "reason") and ("client ip" in f or "source ip" in f):
        return "waf"
    # proxy
    if _has(f, "destination ip", "action") and any(k in f for k in ["size(mb)", "size"]):
        return "proxy"
    # db
    if _has(f, "db host", "query"):
        return "db"
    # auth (Host 대신 PC 를 쓰는 케이스)
    if ("result" in f) and ("host" in f or "pc" in f):
        return "auth"
    # dns
    if _has(f, "pc", "query"):
        return "dns"
    # edr
    if _has(f, "pc", "event"):
        return "edr"

    return "csv"  # fallback (일반 CSV)

def parse_text(lines: List[str]) -> List[Dict[str, Any]]:
    """
    텍스트(.log/.txt) 한 줄당 하나의 레코드로 단순 파싱.
    - 첫 1~2 토큰을 시각으로 가정하여 ISO로 파싱 시도
    """
    rows: List[Dict[str, Any]] = []
    for line in lines:
        s = (line or "").strip()
        if not s:
            continue
        parts = s.split()
        ts = iso(" ".join(parts[:2])) or iso(parts[0])  # "YYYY-MM-DD HH:MM:SS" 또는 "ISO" 단일 토큰
        rows.append({"ts": ts, "msg": s, "raw": s, "log_type": "text"})
    return rows

def parse_csv(text: str) -> List[Dict[str, Any]]:
    """
    CSV를 DictReader로 읽고, 로그 타입을 감지한 뒤 표준 키로 변환.
    공통 표준 키: ts, src_ip, dst_ip, src_port, dst_port, proto, msg, raw(json), log_type, meta
    """
    rows: List[Dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(text))
    fieldnames = reader.fieldnames or []
    log_type = _detect_log_type(fieldnames)

    for r in reader:
        meta = dict(r)  # 원본 보존
        ts = iso(r.get("ts") or r.get("timestamp") or r.get("time") or r.get("Timestamp") or "")

        std: Dict[str, Any] = {
            "ts": ts,
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "proto": None, "msg": None,
            "raw": json.dumps(r, ensure_ascii=False),
            "log_type": log_type,
            "meta": meta,
        }

        # 공통 alias helper (대소문자·공백·표기 흔들림 보정)
        def G(key: str) -> Optional[str]:
            for k in (key, key.title(), key.upper(), key.lower()):
                if k in r: return r.get(k)
            return None

        if log_type == "firewall":
            std.update({
                "src_ip": G("Source IP"),
                "dst_ip": G("Destination IP"),
                "src_port": _int_or_none(G("Source Port")),
                "dst_port": _int_or_none(G("Destination Port")),
                "proto": G("Protocol"),
                "msg": f"{G('Action') or ''} {G('Protocol') or ''} {G('Source IP') or ''}:{G('Source Port') or ''} -> {G('Destination IP') or ''}:{G('Destination Port') or ''}".strip(),
            })

        elif log_type == "web":
            # Case A: 단일 Request 컬럼(예: "GET /... HTTP/1.1")
            req = G("Request")
            if req is not None:
                std.update({
                    "src_ip": G("Source IP"),
                    "proto": "HTTP",
                    "msg": f"{req} UA={G('User-Agent') or ''} Status={G('Status') or ''}".strip(),
                })
            else:
                # Case B: Client IP / Method / URL / Status Code / User-Agent
                std.update({
                    "src_ip": G("Client IP"),
                    "proto": "HTTP",
                    "msg": f"{G('Method') or ''} {G('URL') or ''} UA={G('User-Agent') or ''} Status={G('Status Code') or ''}".strip(),
                })

        elif log_type == "waf":
            std.update({
                "src_ip": G("Client IP") or G("Source IP"),
                "proto": "HTTP",
                "msg": f"WAF {G('Action') or ''} {G('Target') or ''} Reason={G('Reason') or ''}".strip(),
            })

        elif log_type == "proxy":
            std.update({
                "src_ip": G("Source IP") or G("PC"),
                "dst_ip": G("Destination IP"),
                "msg": f"{G('Action') or ''} to {G('Destination IP') or ''} size={(G('Size(MB)') or G('Size') or '')}MB".strip(),
            })

        elif log_type == "db":
            std.update({
                "src_ip": G("Source IP") or None,   # 내부 확산형에는 없을 수 있음
                "dst_ip": G("DB Host"),
                "proto": "SQL",
                "msg": (G("Query") or "").strip(),
            })

        elif log_type == "auth":
            # 호스트/PC 표기 혼용 케이스. 만약 Host가 IP면 dst_ip로 매핑
            host_or_pc = G("Host") or G("PC")
            std.update({
                "src_ip": G("Source IP"),
                "dst_ip": host_or_pc if (host_or_pc and re_ip(host_or_pc)) else None,
                "src_port": _int_or_none(G("Port")),
                "msg": (G("Result") or "").strip(),
            })

        elif log_type == "dns":
            std.update({
                "src_ip": None,
                "proto": "DNS",
                "msg": (G("Query") or "").strip(),
            })

        elif log_type == "edr":
            std.update({
                "src_ip": None,
                "proto": "EDR",
                "msg": (G("Event") or "").strip(),
            })

        else:
            # 일반 CSV(필드명이 비교적 표준에 가까운 경우)
            std.update({
                "src_ip": G("src_ip") or G("Source IP"),
                "dst_ip": G("dst_ip") or G("dest_ip") or G("Destination IP"),
                "src_port": _int_or_none(G("src_port") or G("Source Port")),
                "dst_port": _int_or_none(G("dst_port") or G("Destination Port")),
                "proto": G("proto") or G("Protocol"),
                "msg": G("msg") or "",
            })

        rows.append(std)
    return rows

def re_ip(s: str) -> bool:
    """문자열이 유효한 IP 형식인지 검사."""
    try:
        import ipaddress
        ipaddress.ip_address(s); return True
    except Exception:
        return False

def parse_zip(raw_bytes: bytes, zip_filename: str) -> List[Dict[str, Any]]:
    """
    ZIP 내 모든 CSV를 파싱하여 합치고, meta에 시나리오/파일명을 추가.
    - 반환: 표준화된 dict 행 리스트
    """
    out: List[Dict[str, Any]] = []
    scenario = zip_filename.rsplit(".", 1)[0]
    with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
        for name in z.namelist():
            if not name.lower().endswith(".csv"):
                continue
            text = z.read(name).decode("utf-8-sig", errors="ignore")
            rows = parse_csv(text)
            # 시나리오/파일 정보 추가
            for r in rows:
                meta = r.get("meta", {}) or {}
                meta["scenario"] = scenario
                meta["file"] = name
                r["meta"] = meta
            out.extend(rows)
    return out
