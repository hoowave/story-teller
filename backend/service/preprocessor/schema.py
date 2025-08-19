# Entities, Event (Pydantic 모델)

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid

class Entities(BaseModel):
    ips: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)

class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingest_id: str
    ts: str                              # ISO8601 string
    # 출처(파서가 감지): firewall | web | waf | auth | db | proxy | text | csv
    source_type: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    msg: Optional[str] = None

    event_type_hint: Optional[str] = None
    severity_hint: Optional[str] = None
    entities: Entities = Field(default_factory=Entities)

    raw: str                             # 원문(한 줄 또는 json)
    meta: Dict[str, Any] = Field(default_factory=dict)   # 💡 원본의 추가 컬럼 보존
    parsing_confidence: float = 0.8

