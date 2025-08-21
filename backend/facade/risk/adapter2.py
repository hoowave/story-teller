from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import json
from pathlib import Path

@dataclass
class Event:
    event_id: str
    ts: str
    source_type: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    msg: str
    event_type_hint: Optional[str]
    severity_hint: Optional[str]
    entities: Dict[str, Any]
    parsing_confidence: float
    raw: Optional[str] = None
    meta: Dict[str, Any] = None

    @property
    def users(self) -> List[str]:
        return list(self.entities.get("users", []) or [])

    @property
    def files(self) -> List[str]:
        return list(self.entities.get("files", []) or [])

    @property
    def ips(self) -> List[str]:
        return list(self.entities.get("ips", []) or [])

def load_preprocessed_events(path: str | Path) -> List[Event]:
    """전처리된 JSON(events 배열)을 Event 리스트로 로드."""
    raw_data = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as e:
        print(f"⚠️ JSON 파싱 실패: {e} / 데이터: {raw_data[:100]}...")
        return []

    # events 키가 있으면 가져오고, 없으면 빈 리스트
    items = data.get("events", [])

    if not items:
        print("⚠️ 이벤트 배열이 존재하지 않습니다. detailed_analysis 안에 'events' 키 확인 필요")
        return []

    out: List[Event] = []
    for e in items:
        # 혹시 이벤트 구조가 dict가 아닌 경우 처리
        if not isinstance(e, dict):
            print(f"⚠️ 이벤트 데이터 형식 오류: {e}")
            continue

        out.append(Event(
            event_id=e.get("event_id") or e.get("ingest_id") or "",
            ts=e.get("ts", ""),
            source_type=e.get("source_type", ""),
            src_ip=e.get("src_ip", ""),
            dst_ip=e.get("dst_ip", ""),
            msg=e.get("msg", ""),
            event_type_hint=e.get("event_type_hint", ""),
            severity_hint=e.get("severity_hint", ""),
            entities=e.get("entities", {}),
            parsing_confidence=float(e.get("parsing_confidence", 1.0)),
            raw=e.get("raw", ""),
            meta=e.get("meta", {}),
        ))

    return out