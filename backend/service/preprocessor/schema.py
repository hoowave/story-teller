# backend/service/preprocessor/schema.py
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid

class Entities(BaseModel):
    ips: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    files: List[str] = Field(default_factory=list)
    processes: List[str] = Field(default_factory=list)
    # 선택: DNS 도메인 추출까지 하고 싶다면 활성화
    domains: List[str] = Field(default_factory=list)

class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ingest_id: str
    ts: str
    # firewall | web | waf | auth | db | proxy | dns | edr | text | csv
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

    raw: str
    meta: Dict[str, Any] = Field(default_factory=dict)
    parsing_confidence: float = 0.8
