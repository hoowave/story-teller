# parse_text(), parse_csv()

import io, csv, json
from typing import List, Dict, Any, Optional, Tuple
from .extractors import iso

def _int_or_none(x: Optional[str]) -> Optional[int]:
    try:
        return int(x) if x not in (None, "") else None
    except Exception:
        return None

def _detect_log_type(fieldnames: List[str]) -> str:
    f = {k.lower(): k for k in fieldnames}  # 소문자 -> 원래명
    has = lambda *keys: all(k.lower() in f for k in keys)

    if has("protocol", "source ip", "destination ip", "source port", "destination port"):
        return "firewall"
    if has("request") and (has("status") or has("user-agent")):
        return "web"
    if has("target", "action", "reason"):
        return "waf"
    if has("destination ip", "action") and any(k in f for k in ["size(mb)", "size"]):
        return "proxy"
    if has("db host", "query"):
        return "db"
    if has("host", "result") and has("source ip"):
        return "auth"
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
        meta = dict(r)  # 원본 전체 보존
        # 공통 시각
        ts = iso(r.get("ts") or r.get("timestamp") or r.get("time") or r.get("Timestamp") or "")

        # 표준화 초기값
        std: Dict[str, Any] = {
            "ts": ts,
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "proto": None, "msg": None,
            "raw": json.dumps(r, ensure_ascii=False),
            "log_type": log_type,
            "meta": meta,
        }

        # 타입별 매핑
        if log_type == "firewall":
            std.update({
                "src_ip": r.get("Source IP"),
                "dst_ip": r.get("Destination IP"),
                "src_port": _int_or_none(r.get("Source Port")),
                "dst_port": _int_or_none(r.get("Destination Port")),
                "proto": r.get("Protocol"),
                "msg": f"{r.get('Action','')} {r.get('Protocol','')} {r.get('Source IP','')}:{r.get('Source Port','')} -> {r.get('Destination IP','')}:{r.get('Destination Port','')}".strip(),
            })

        elif log_type == "web":
            # 예: Request, Status, User-Agent
            req = r.get("Request") or ""
            ua  = r.get("User-Agent") or ""
            st  = r.get("Status") or ""
            std.update({
                "src_ip": r.get("Source IP"),
                "proto": "HTTP",
                "msg": f"{req} UA={ua} Status={st}".strip(),
            })

        elif log_type == "waf":
            # 예: Target, Action, Reason
            std.update({
                "src_ip": r.get("Source IP"),
                "proto": "HTTP",
                "msg": f"WAF {r.get('Action','')} {r.get('Target','')} Reason={r.get('Reason','')}".strip(),
            })

        elif log_type == "proxy":
            # 예: Destination IP, Action, Size(MB)
            std.update({
                "src_ip": r.get("Source IP"),
                "dst_ip": r.get("Destination IP"),
                "msg": f"{r.get('Action','')} to {r.get('Destination IP','')} size={r.get('Size(MB)') or r.get('Size','')}MB".strip(),
            })

        elif log_type == "db":
            # 예: DB Host, User, Query, Source IP
            std.update({
                "src_ip": r.get("Source IP"),
                "dst_ip": r.get("DB Host"),
                "proto": "SQL",
                "msg": (r.get("Query") or "").strip(),
            })

        elif log_type == "auth":
            # 예: Host, Result, Source IP, Port
            std.update({
                "src_ip": r.get("Source IP"),
                "dst_ip": r.get("Host"),
                "src_port": _int_or_none(r.get("Port")),
                "msg": (r.get("Result") or "").strip(),
            })

        else:
            # 일반 CSV: 최대한 공통 alias
            std.update({
                "src_ip": r.get("src_ip") or r.get("Source IP"),
                "dst_ip": r.get("dst_ip") or r.get("dest_ip") or r.get("Destination IP"),
                "src_port": _int_or_none(r.get("src_port") or r.get("Source Port")),
                "dst_port": _int_or_none(r.get("dst_port") or r.get("Destination Port")),
                "proto": r.get("proto") or r.get("Protocol"),
                "msg": r.get("msg") or "",
            })

        rows.append(std)
    return rows
