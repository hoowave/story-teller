# models.py
from dataclasses import dataclass
from datetime import datetime
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
    # === 확장 (시나리오 반영) ===
    DB_ACCESS = "db_access"
    DATA_TRANSFER = "data_transfer"
    WEB_ATTACK = "web_attack"

# 안전 매핑(힌트/원천명을 enum으로 매핑)
_EVENTTYPE_MAP = {
    # 기존
    "authentication": EventType.AUTHENTICATION,
    "file_access": EventType.FILE_ACCESS,
    "network_access": EventType.NETWORK_ACCESS,
    "system_access": EventType.SYSTEM_ACCESS,
    # 확장
    "db": EventType.DB_ACCESS,
    "db_access": EventType.DB_ACCESS,
    "database": EventType.DB_ACCESS,
    "data_transfer": EventType.DATA_TRANSFER,
    "egress": EventType.DATA_TRANSFER,
    "proxy": EventType.DATA_TRANSFER,
    "fw": EventType.DATA_TRANSFER,
    "web": EventType.WEB_ATTACK,
    "waf": EventType.WEB_ATTACK,
    "web_attack": EventType.WEB_ATTACK,
}

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
        ts = datetime.fromisoformat(data['ts'].replace('+09:00', ''))
        raw_hint = (data.get('event_type_hint') or "").lower()
        src_type = (data.get('source_type') or "").lower()
        evt = _EVENTTYPE_MAP.get(raw_hint) or _EVENTTYPE_MAP.get(src_type) or EventType.SYSTEM_ACCESS
        sev = SeverityLevel((data.get('severity_hint') or 'info').lower())

        ents = data.get('entities') or {}
        # 필수 키 기본값
        for k in ['ips','users','files','processes','domains']:
            ents.setdefault(k, [])
        # 확장 컨텍스트 기본값
        ents.setdefault('obj_name', None)
        ents.setdefault('row_count', None)
        ents.setdefault('bytes_out', None)
        ents.setdefault('status', None)
        ents.setdefault('asn', None)
        ents.setdefault('geo', None)
        ents.setdefault('ua', None)

        return cls(
            event_id=data['event_id'],
            timestamp=ts,
            source_type=data.get('source_type', ''),
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
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
    overall_risk_score: float
    attack_scenario: str
    priority_level: SeverityLevel
