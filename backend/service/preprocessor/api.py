# FastAPI router (/ingest)

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import List, Dict, Any
import uuid

from .schema import Event
from .extractors import extract_entities, infer_hints
from .parsers import parse_text, parse_csv

router = APIRouter(tags=["preprocessor"])

def _read_bytes_safely(b: bytes) -> str:
    try:
        return b.decode("utf-8-sig")
    except Exception:
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return b.decode("latin-1", errors="ignore")

@router.post("/ingest")
async def ingest(file: UploadFile = File(...), full: int = Query(0)) -> Dict[str, Any]:
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    try:
        raw = _read_bytes_safely(await file.read())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File read/decode failed: {e}")

    if not raw.strip():
        raise HTTPException(status_code=400, detail="File is empty")

    if (file.filename or "").lower().endswith(".csv"):
        rows = parse_csv(raw); fmt = "csv"
    else:
        rows = parse_text(raw.splitlines()); fmt = "text"

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []

    for r in rows:
        if not r.get("ts"):
            continue
        msg = r.get("msg") or r.get("raw", "")
        ents = extract_entities(msg)

        log_type = r.get("log_type")
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        etype, sev = infer_hints(msg, log_type=log_type, meta=meta)

        ev = Event(
            ingest_id=ingest_id,
            ts=r["ts"],
            source_type=log_type,
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
            meta=meta,
            parsing_confidence=0.92 if (etype or ents.ips or ents.users) else 0.75,
        )
        events.append(ev)

    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": fmt,
        "count": len(events),
        "sample": [e.dict() for e in events[:3]],  # Pydantic v1
    }
    if full:
        payload["events"] = [e.dict() for e in events]
    return payload
