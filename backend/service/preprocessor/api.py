# FastAPI router (/ingest): csv/log/txt만 허용
import os
import csv
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import List, Dict, Any
import uuid

from .schema import Event
from .extractors import extract_entities, infer_hints
from .parsers import parse_text, parse_csv

"""
[모듈 개요]
- 업로드된 로그 파일을 읽어 적절한 파서(csv/text)로 구조화한 뒤,
  엔티티(IP/사용자/파일/프로세스/도메인) 추출과 이벤트 힌트(event_type/severity)까지 수행.
- 최종적으로 Pydantic Event 스키마로 정규화하여 샘플/전체 결과를 반환.

엔드포인트
- POST /ingest        : 단일 파일 업로드(.csv/.log/.txt)
- POST /ingest/batch  : 여러 파일 일괄 업로드
"""

router = APIRouter(tags=["preprocessor"])

# 허용 파일 확장자 집합
ALLOWED_EXTS = {".csv", ".log", ".txt"}

def _read_bytes_safely(b: bytes) -> str:
    """바이트를 안전하게 문자열로 디코딩 (BOM·깨짐 최소화)."""
    try:
        return b.decode("utf-8-sig")
    except Exception:
        try:
            return b.decode("utf-8", errors="ignore")
        except Exception:
            return b.decode("latin-1", errors="ignore")

def _ext(name: str) -> str:
    """파일명에서 소문자 확장자만 추출."""
    return os.path.splitext(name or "")[1].lower()

def _looks_like_csv(text: str) -> bool:
    """
    헤더가 있는 CSV로 추정되면 True.
    - csv.Sniffer로 구분자/헤더 존재 여부를 판단
    - .log/.txt 파일이라도 CSV 형태이면 CSV 파서로 우회 처리
    """
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
    """
    파일 확장자/내용에 따라 CSV 또는 텍스트 파서를 선택해
    '표준화된 dict 행' 리스트를 반환.
    return: (rows, "csv"|"text")
    """
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="File is empty")

    text = _read_bytes_safely(raw_bytes)
    ext = _ext(name)

    if ext == ".csv":
        return parse_csv(text), "csv"

    # .log / .txt 이지만 실제로는 헤더가 있는 CSV인 경우
    if ext in {".log", ".txt"} and _looks_like_csv(text):
        return parse_csv(text), "csv"

    # 그 외: 일반 텍스트 라인 파싱
    return parse_text(text.splitlines()), "text"


@router.post("/ingest")
async def ingest(file: UploadFile = File(...), full: int = Query(0)) -> Dict[str, Any]:
    """
    단일 파일 업로드 전처리 엔드포인트.
    - 입력: 업로드 파일(.csv/.log/.txt), 쿼리 full(0|1)
    - 출력: ingest_id, format, count, sample(최대 3개), (full=1이면 events 전체)
    """
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
        # 이미 의미있는 에러를 만들었으면 그대로 전달
        raise
    except Exception as e:
        # 그 외 파싱 실패: 400 반환
        raise HTTPException(status_code=400, detail=f"Parse failed: {e}")

    ingest_id = str(uuid.uuid4())
    events: List[Event] = []

    for r in rows:
        # 타임스탬프(ISO)가 아예 없으면 스킵 (다운스트림에서 시간축 필요)
        if not r.get("ts"):
            continue

        msg = r.get("msg") or r.get("raw", "")
        # 본문에서 엔티티 추출 (IP/사용자/파일/프로세스/도메인)
        ents = extract_entities(msg)

        # 구조화 필드(src_ip/dst_ip)가 있으면 엔티티 IP에 병합
        for ipk in ("src_ip", "dst_ip"):
            v = r.get(ipk)
            if v and v not in ents.ips:
                ents.ips.append(v)

        log_type = r.get("log_type")
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        # 업로드 원본 파일명 기록 (추적용)
        meta.setdefault("file", file.filename)

        # 메시지/메타 기반 이벤트 타입/심각도 힌트
        etype, sev = infer_hints(msg, log_type=log_type, meta=meta)

        # 정규화 Event로 구성
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
            # 간단한 신뢰도 휴리스틱 (엔티티/힌트 유무 기반)
            parsing_confidence=0.95 if (etype or ents.ips or ents.users or ents.processes) else 0.78,
        )
        events.append(ev)

    payload: Dict[str, Any] = {
        "ingest_id": ingest_id,
        "format": fmt,
        "count": len(events),
        # 가볍게 미리보기: 최대 3개
        "sample": [e.model_dump() for e in events[:3]],
    }
    if full:
        payload["events"] = [e.model_dump() for e in events]
    return payload


@router.post("/ingest/batch")
async def ingest_batch(files: List[UploadFile] = File(...), full: int = Query(0)) -> Dict[str, Any]:
    """
    여러 파일 일괄 처리 엔드포인트.
    - 허용: .csv/.log/.txt
    - ZIP 없이도 관련 시나리오 파일 묶음을 한 번에 올릴 때 사용
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
        "sample": [e.model_dump() for e in events[:3]],
    }
    if full:
        payload["events"] = [e.model_dump() for e in events]
    return payload
