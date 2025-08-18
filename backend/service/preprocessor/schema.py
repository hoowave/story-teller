# Entities, Event (Pydantic 모델)

from pydantic import BaseModel, Field
from typing import List, Optional
import uuid

class Entities(BaseModel):
    """문장/로그에서 추출된 개체들"""
    ips: List[str] = []
    users: List[str] = []
    files: List[str] = []
    processes: List[str] = []

class Event(BaseModel):
    """정규화된 이벤트 레코드"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingest_id: str
    ts: str                              # ISO8601 타임스탬프
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
    parsing_confidence: float = 0.8      # 추출 신뢰도(간이)
