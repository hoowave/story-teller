# backend/service/preprocessor/parsers.py

import io, csv, json, zipfile
from typing import List, Dict, Any, Optional
from .extractors import iso

def _int_or_none(x: Optional[str]) -> Optional[int]:
    try:
        return int(x) if x not in (None, "") else None
    except Exception:
        return None

def _lower_map(fieldnames: List[str]) -> Dict[str, str]:
    return {k.lower(): k for k in fieldnames}

def _has(fmap: Dict[str, str], *keys) -> bool:
    return all(k.lower() in fmap for k in keys)

def _detect_log_type(fieldnames: List[str]) -> str:
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

    return "csv"  # fallback

def parse_text(lines: List[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in lines:
        s = (line or "").strip()
        if not s:
            continue
        parts = s.split()
        ts = iso(" ".join(parts[:2])) or iso(parts[0])
        rows.append({"ts": ts, "msg": s, "raw": s, "log_type": "text"})
    return rows

def parse_csv(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(text))
    fieldnames = reader.fieldnames or []
    log_type = _detect_log_type(fieldnames)

    for r in reader:
        meta = dict(r)
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

        # 공통 alias helper
        def G(key: str) -> Optional[str]:
            # 대소문자/공백/대괄호 혼재 방지용
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
            # Case A: Request/Status/User-Agent
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
                "src_ip": G("Source IP") or None,   # 내부 확산형에는 없음
                "dst_ip": G("DB Host"),
                "proto": "SQL",
                "msg": (G("Query") or "").strip(),
            })

        elif log_type == "auth":
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
    try:
        import ipaddress
        ipaddress.ip_address(s); return True
    except Exception:
        return False

def parse_zip(raw_bytes: bytes, zip_filename: str) -> List[Dict[str, Any]]:
    """ZIP 내부 모든 CSV를 파싱하여 합칩니다. meta.scenario/file 부가."""
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
