# FastAPI router (/ingest)

from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
import uuid

from .schema import Event
from .extractors import extract_entities, infer_hints
from .parsers import parse_text, parse_csv

router = APIRouter(tags=["preprocessor"])

@router.post("/ingest")
async def ingest(file: UploadFile = File(...)):
    """
    파일 업로드 받아 포맷 감지(csv/text) -> 파싱 -> 엔티티/힌트 -> Event 스키마로 정규화.
    응답: 요약 정보 + 샘플 3개
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    try:
        raw = (await file.read()).decode(errors="ignore")
    except Exception:
        raise HTTPException(status_code=400, detail="File read/decode failed")

    lines = raw.splitlines()
    # 확장자로 아주 단순 감지 (필요시 content sniffing 로 개선 가능)
    if (file.filename or "").lower().endswith(".csv"):
        rows = parse_csv(raw)
        fmt = "csv"
    else:
        rows = parse_text(lines)
        fmt = "text"

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []

    for r in rows:
        if not r.get("ts"):        # 타임스탬프 없는 행은 스킵 (정책적으로 변경 가능)
            continue
        msg = r.get("msg") or r.get("raw", "")
        ents = extract_entities(msg)
        etype, sev = infer_hints(msg)

        ev = Event(
            ingest_id=ingest_id,
            ts=r["ts"],
            src_ip=r.get("src_ip"),
            dst_ip=r.get("dst_ip"),
            src_port=r.get("src_port"),
            dst_port=r.get("dst_port"),
            proto=r.get("proto"),
            msg=msg,
            event_type_hint=etype,
            severity_hint=sev,
            entities=ents,
            raw=r.get("raw", ""),
            parsing_confidence=0.9 if etype or ents.ips or ents.users else 0.7,
        )
        events.append(ev)

    return {
        "ingest_id": ingest_id,
        "format": fmt,
        "count": len(events),
        "sample": [e.model_dump() for e in events[:3]],
    }
