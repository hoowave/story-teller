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
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data["events"] if isinstance(data, dict) and "events" in data else data
    out: List[Event] = []
    for e in items:
        out.append(Event(
            event_id=e.get("event_id") or e.get("ingest_id") or "",
            ts=e["ts"],
            source_type=e.get("source_type", ""),
            src_ip=e.get("src_ip"),
            dst_ip=e.get("dst_ip"),
            msg=e.get("msg", ""),
            event_type_hint=e.get("event_type_hint"),
            severity_hint=e.get("severity_hint"),
            entities=e.get("entities", {}),
            parsing_confidence=float(e.get("parsing_confidence", 1.0)),
            raw=e.get("raw"),
            meta=e.get("meta", {}),
        ))
    return out
