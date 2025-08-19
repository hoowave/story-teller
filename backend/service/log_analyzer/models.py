# security_log_analyzer/models.py
"""데이터 모델 정의"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel

class AttackType(Enum):
    """공격 유형 열거형"""
    BRUTE_FORCE = "brute_force"
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    FILE_ACCESS = "file_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PROCESS_EXECUTION = "process_execution"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"

class SeverityLevel(Enum):
    """심각도 레벨"""
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"

class EntityModel(BaseModel):
    """엔티티 모델"""
    ips: List[str] = []
    users: List[str] = []
    files: List[str] = []
    processes: List[str] = []

class LogEntry(BaseModel):
    """전처리된 로그 엔트리"""
    event_id: str
    ingest_id: str
    ts: str  # ISO 8601 format timestamp
    msg: str
    entities: EntityModel
    event_type_hint: str
    severity_hint: str
    parsing_confidence: float
    raw: str
    
    @property
    def timestamp(self) -> datetime:
        """타임스탬프를 datetime 객체로 변환"""
        return datetime.fromisoformat(self.ts.replace('+09:00', '+09:00'))
    
    @property
    def ip(self) -> Optional[str]:
        """첫 번째 IP 반환"""
        return self.entities.ips[0] if self.entities.ips else None
    
    @property
    def user(self) -> Optional[str]:
        """첫 번째 사용자 반환"""
        return self.entities.users[0] if self.entities.users else None

class LogIngestion(BaseModel):
    """로그 수집 요청 모델"""
    ingest_id: str
    format: str
    count: int
    sample: List[LogEntry]

@dataclass
class Classification:
    """공격 분류 결과"""
    event_id: str
    rule_based: Dict[str, Any]
    ai_based: Dict[str, Any]
    hybrid_result: Dict[str, Any]
    
@dataclass
class AttackCluster:
    """공격 클러스터"""
    cluster_id: str
    cluster_type: str
    time_window: Dict[str, Any]
    related_events: List[str]  # event_id 리스트
    pattern_analysis: Dict[str, Any]
    cluster_confidence: float = 0.0

