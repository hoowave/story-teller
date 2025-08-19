# parse_text(), parse_csv()

import io, csv, json
from typing import List, Dict, Any, Optional
from .extractors import iso

def _int_or_none(x: Optional[str]) -> Optional[int]:
    try:
        return int(x) if x not in (None, "",) else None
    except Exception:
        return None

def parse_text(lines: List[str]) -> List[Dict[str, Any]]:
    """
    일반 텍스트 로그(줄 단위). 앞 1~2 토큰을 날짜로 시도 -> 실패 시 ts 없음.
    """
    rows: List[Dict[str, Any]] = []
    for line in lines:
        s = (line or "").strip()
        if not s:
            continue
        parts = s.split()
        ts = iso(" ".join(parts[:2])) or iso(parts[0])  # "Jan 12 10:10:10" / "2025-01-01"
        rows.append({"ts": ts, "msg": s, "raw": s})
    return rows

def parse_csv(text: str) -> List[Dict[str, Any]]:
    """
    CSV -> dict. 컬럼명(ts/timestamp/time, src_ip/dst_ip/port/proto/msg)을 기대(유연 매핑).
    """
    rows: List[Dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(text))
    for r in reader:
        ts = iso(r.get("ts") or r.get("timestamp") or r.get("time") or "")
        rows.append({
            "ts": ts,
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip") or r.get("dest_ip"),
            "src_port": _int_or_none(r.get("src_port")),
            "dst_port": _int_or_none(r.get("dst_port")),
            "proto": r.get("proto"),
            "msg": r.get("msg"),
            "raw": json.dumps(r, ensure_ascii=False),
        })
    return rows
