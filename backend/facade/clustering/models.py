# models.py
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from enum import Enum

class SeverityLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EventType(Enum):
    AUTHENTICATION = "authentication"
    FILE_ACCESS = "file_access"
    NETWORK_ACCESS = "network_access"
    SYSTEM_ACCESS = "system_access"
    DB_ACCESS = "db_access"
    DATA_TRANSFER = "data_transfer"
    WEB_ATTACK = "web_attack"

_EVENTTYPE_MAP = {
    "authentication": EventType.AUTHENTICATION, "auth": EventType.AUTHENTICATION,
    "file_access": EventType.FILE_ACCESS,
    "network_access": EventType.NETWORK_ACCESS,
    "system_access": EventType.SYSTEM_ACCESS,
    "db": EventType.DB_ACCESS, "db_access": EventType.DB_ACCESS, "database": EventType.DB_ACCESS,
    "data_transfer": EventType.DATA_TRANSFER, "egress": EventType.DATA_TRANSFER,
    "proxy": EventType.DATA_TRANSFER, "fw": EventType.DATA_TRANSFER,
    "web": EventType.WEB_ATTACK, "waf": EventType.WEB_ATTACK, "web_attack": EventType.WEB_ATTACK,
}

_SEVERITY_MAP = {
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "notice": SeverityLevel.LOW,
    "warning": SeverityLevel.LOW,  # ← 샘플 데이터 호환
    "warn": SeverityLevel.LOW,
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM, "med": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL, "crit": SeverityLevel.CRITICAL, "fatal": SeverityLevel.CRITICAL,
}

def _parse_iso_aware(val: str) -> datetime:
    s = (val or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(hours=9)))
    return dt.astimezone(timezone.utc)

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source_type: str
    src_ip: str
    dst_ip: str
    message: str
    event_type: EventType
    severity: SeverityLevel
    entities: Dict[str, List[str]]
    parsing_confidence: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        ts = _parse_iso_aware(data['ts'])
        raw_hint = (data.get('event_type_hint') or "").lower()
        src_type = (data.get('source_type') or "").lower()
        evt = _EVENTTYPE_MAP.get(raw_hint) or _EVENTTYPE_MAP.get(src_type) or EventType.SYSTEM_ACCESS

        sev_str = (data.get('severity_hint') or 'info').lower()
        sev = _SEVERITY_MAP.get(sev_str, SeverityLevel.INFO)

        ents = data.get('entities') or {}
        for k in ['ips','users','files','processes','domains']:
            ents.setdefault(k, [])
        for k in ['obj_name','row_count','bytes_out','status','asn','geo','ua','session_id','blocked']:
            ents.setdefault(k, None)

        return cls(
            event_id=data['event_id'],
            timestamp=ts,
            source_type=data.get('source_type', ''),
            src_ip=data.get('src_ip', "0.0.0.0"),
            dst_ip=data.get('dst_ip', "0.0.0.0"),
            message=data.get('msg', ''),
            event_type=evt,
            severity=sev,
            entities=ents,
            parsing_confidence=float(data.get('parsing_confidence', 1.0)),
        )

@dataclass
class ClusterMetrics:
    time_concentration: float
    ip_diversification: float
    user_anomaly: float
    file_sensitivity: float
    network_threat: float = 0.0
    overall_risk_score: float = 0.0
    attack_scenario: str = ""
    priority_level: SeverityLevel = SeverityLevel.LOW
