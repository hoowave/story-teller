# models.py
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum

class SeverityLevel(Enum):
    INFO = "info" # 추가 수정
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EventType(Enum):
    AUTHENTICATION = "authentication"
    FILE_ACCESS = "file_access"
    NETWORK_ACCESS = "network_access"
    SYSTEM_ACCESS = "system_access"

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
        """딕셔너리에서 SecurityEvent 객체 생성"""
        return cls(
            event_id=data['event_id'],
            timestamp=datetime.fromisoformat(data['ts'].replace('+09:00', '')),
            source_type=data['source_type'],
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            message=data['msg'],
            event_type=EventType(data['event_type_hint']),
            severity=SeverityLevel(data['severity_hint']),
            entities=data['entities'],
            parsing_confidence=data['parsing_confidence']
        )

@dataclass
class ClusterMetrics:
    """클러스터링 지표 결과"""
    time_concentration: float
    ip_diversification: float
    user_anomaly: float
    file_sensitivity: float
    overall_risk_score: float
    attack_scenario: str
    priority_level: SeverityLevel
