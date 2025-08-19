# FastAPI router (/ingest)

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import List, Dict, Any
import uuid

from .schema import Event
from .extractors import extract_entities, infer_hints
from .parsers import parse_text, parse_csv

router = APIRouter(tags=["preprocessor"])

def _read_bytes_safely(b: bytes) -> str:
    # BOM 처리 및 기본 UTF-8, 실패 시 latin-1 폴백
    try:
        s = b.decode("utf-8-sig")
        return s
    except Exception:
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return b.decode("latin-1", errors="ignore")

@router.post("/ingest")
async def ingest(file: UploadFile = File(...), full: int = Query(0)) -> Dict[str, Any]:
    """
    파일 업로드 받아 포맷 감지(csv/text) -> 파싱 -> 엔티티/힌트 -> Event 정규화.
    full=1 이면 전체 events 반환; 기본은 요약 + 샘플 3개.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    try:
        raw = _read_bytes_safely(await file.read())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File read/decode failed: {e}")

    if not raw.strip():
        raise HTTPException(status_code=400, detail="File is empty")

    lines = raw.splitlines()
    if (file.filename or "").lower().endswith(".csv"):
        rows = parse_csv(raw); fmt = "csv"
    else:
        rows = parse_text(lines); fmt = "text"

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []

    for r in rows:
        if not r.get("ts"):
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
            parsing_confidence=0.9 if (etype or ents.ips or ents.users) else 0.7,
        )
        events.append(ev)

    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": fmt,
        "count": len(events),
        "sample": [e.dict() for e in events[:3]],   # Pydantic v1
    }
    if full:
        payload["events"] = [e.dict() for e in events]
    return payload

@router.post("/ingest/lines")
async def ingest_lines(body: Dict[str, Any], full: int = Query(1)) -> Dict[str, Any]:
    """
    파일 없이 JSON 바디로 라인 배열을 받는 변형:
    body = {"source":"text","lines":["...","..."]}
    """
    lines: List[str] = body.get("lines") or []
    if not isinstance(lines, list) or not lines:
        raise HTTPException(status_code=400, detail="lines must be a non-empty array of strings")
    fake = UploadFile(filename="lines.txt", file=None)  # filename 유도용
    # Fast path: 텍스트로 취급
    rows = parse_text(lines)
    ingest_id = str(uuid.uuid4())
    events: List[Event] = []
    for r in rows:
        if not r.get("ts"):
            continue
        msg = r.get("msg") or r.get("raw", "")
        ents = extract_entities(msg)
        etype, sev = infer_hints(msg)
        events.append(Event(
            ingest_id=ingest_id, ts=r["ts"], src_ip=r.get("src_ip"),
            dst_ip=r.get("dst_ip"), src_port=r.get("src_port"),
            dst_port=r.get("dst_port"), proto=r.get("proto"),
            msg=msg, event_type_hint=etype, severity_hint=sev,
            entities=ents, raw=r.get("raw",""),
            parsing_confidence=0.9 if (etype or ents.ips or ents.users) else 0.7
        ))
    return {
        "ingest_id": ingest_id,
        "format": "text",
        "count": len(events),
        "events": [e.dict() for e in events] if full else [e.dict() for e in events[:3]],
    }
