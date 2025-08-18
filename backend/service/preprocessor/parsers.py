# parse_text(), parse_csv()

import io, csv, json
from .extractors import iso

def parse_text(lines: list[str]) -> list[dict]:
    """
    일반 텍스트 로그(줄 단위)를 간단히 파싱.
    규칙: 앞 1~2 토큰을 날짜로 시도 -> 실패 시 ts 없음
    """
    rows = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        parts = s.split()
        ts = iso(" ".join(parts[:2])) or iso(parts[0])
        rows.append({"ts": ts, "msg": s, "raw": s})
    return rows

def parse_csv(text: str) -> list[dict]:
    """
    CSV -> dict 로 변환. 컬럼명(ts/timestamp/time, src_ip/dst_ip/port/proto/msg)을 기대.
    """
    rows = []
    reader = csv.DictReader(io.StringIO(text))
    for r in reader:
        ts = iso(r.get("ts") or r.get("timestamp") or r.get("time") or "")
        rows.append({
            "ts": ts,
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "src_port": int(r["src_port"]) if r.get("src_port") else None,
            "dst_port": int(r["dst_port"]) if r.get("dst_port") else None,
            "proto": r.get("proto"),
            "msg": r.get("msg"),
            "raw": json.dumps(r, ensure_ascii=False),
        })
    return rows
