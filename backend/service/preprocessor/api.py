# FastAPI router (/ingest): csv/log/txt만 허용, zip 불허
import os
import csv
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import List, Dict, Any
import uuid

from .schema import Event
from .extractors import extract_entities, infer_hints
from .parsers import parse_text, parse_csv

router = APIRouter(tags=["preprocessor"])

ALLOWED_EXTS = {".csv", ".log", ".txt"}

def _read_bytes_safely(b: bytes) -> str:
    try:
        return b.decode("utf-8-sig")
    except Exception:
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return b.decode("latin-1", errors="ignore")

def _ext(name: str) -> str:
    return os.path.splitext(name or "")[1].lower()

def _looks_like_csv(text: str) -> bool:
    """헤더가 있는 CSV로 추정되면 True (로그성 텍스트의 오탐 줄이기)."""
    try:
        lines = text.splitlines()
        sample = "\n".join(lines[: min(len(lines), 10)])
        dialect = csv.Sniffer().sniff(sample)
        has_header = csv.Sniffer().has_header(sample)
        # 구분자가 실제 샘플에 존재하고 헤더가 있다고 판단되면 CSV로 간주
        return (dialect.delimiter in sample) and bool(has_header)
    except Exception:
        return False

def _rows_from_file(name: str, raw_bytes: bytes) -> (List[Dict[str, Any]], str):
    """확장자/내용에 따라 CSV 또는 텍스트 파서 선택."""
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="File is empty")

    text = _read_bytes_safely(raw_bytes)
    ext = _ext(name)

    if ext == ".csv":
        return parse_csv(text), "csv"

    # .log / .txt 이지만 실은 CSV인 경우 자동 판별(헤더가 있는 경우에 한해)
    if ext in {".log", ".txt"} and _looks_like_csv(text):
        return parse_csv(text), "csv"

    # 그 외는 일반 텍스트 라인 파싱
    return parse_text(text.splitlines()), "text"


@router.post("/ingest")
async def ingest(file: UploadFile = File(...), full: int = Query(0)) -> Dict[str, Any]:
    """단일 파일 업로드 전처리 (.csv/.log/.txt만 허용)."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = _ext(file.filename)
    if ext not in ALLOWED_EXTS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type: {ext}. Allowed: .csv, .log, .txt",
        )

    raw_bytes = await file.read()
    try:
        rows, fmt = _rows_from_file(file.filename, raw_bytes)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse failed: {e}")

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []

    for r in rows:
        if not r.get("ts"):
            # 타임스탬프가 전혀 파싱되지 않은 행은 스킵
            continue

        msg = r.get("msg") or r.get("raw", "")
        ents = extract_entities(msg)

        # 구조화된 src/dst_ip도 엔티티에 병합
        for ipk in ("src_ip", "dst_ip"):
            v = r.get(ipk)
            if v and v not in ents.ips:
                ents.ips.append(v)

        log_type = r.get("log_type")
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        # 업로드 파일명 보존
        meta.setdefault("file", file.filename)

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
            parsing_confidence=0.95 if (etype or ents.ips or ents.users or ents.processes) else 0.78,
        )
        events.append(ev)

    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": fmt,
        "count": len(events),
        "sample": [e.dict() for e in events[:3]],
    }
    if full:
        payload["events"] = [e.dict() for e in events]
    return payload


@router.post("/ingest/batch")
async def ingest_batch(files: List[UploadFile] = File(...), full: int = Query(0)) -> Dict[str, Any]:
    """
    (옵션) 여러 파일을 한 번에 처리. 모두 .csv/.log/.txt만 허용.
    ZIP 없이도 시나리오 묶음을 업로드하고 싶을 때 사용.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []
    formats = set()

    for file in files:
        if not file.filename:
            continue
        ext = _ext(file.filename)
        if ext not in ALLOWED_EXTS:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported file type: {ext}. Allowed: .csv, .log, .txt",
            )

        raw_bytes = await file.read()
        rows, fmt = _rows_from_file(file.filename, raw_bytes)
        formats.add(fmt)

        for r in rows:
            if not r.get("ts"):
                continue
            msg = r.get("msg") or r.get("raw", "")
            ents = extract_entities(msg)
            for ipk in ("src_ip", "dst_ip"):
                v = r.get(ipk)
                if v and v not in ents.ips:
                    ents.ips.append(v)

            log_type = r.get("log_type")
            meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
            meta.setdefault("file", file.filename)

            etype, sev = infer_hints(msg, log_type=log_type, meta=meta)

            events.append(
                Event(
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
                    parsing_confidence=0.95 if (etype or ents.ips or ents.users or ents.processes) else 0.78,
                )
            )

    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": "+".join(sorted(formats)) if formats else "unknown",
        "count": len(events),
        "sample": [e.dict() for e in events[:3]],
    }
    if full:
        payload["events"] = [e.dict() for e in events]
    return payload
