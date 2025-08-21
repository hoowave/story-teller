# user_analyzer.py





# ================================
from typing import List, Dict, Any
from collections import defaultdict
from facade.log_clustering.models import SecurityEvent, EventType
from facade.log_clustering.config import DEFAULT_CONFIG



class UserAnalyzer:
    """사용자 행동 패턴 분석기"""
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.admin_users = set(self.config.admin_users)
        self.sensitive_files = set(self.config.sensitive_files.keys())
    
    def calculate_user_anomaly(self, events: List[SecurityEvent]) -> float:
        """사용자 이상 행동 지수 계산"""
        if not events:
            return 0.0
        
        anomaly_score = 0.0
        total_checks = 0
        
        # 사용자별 활동 분석
        user_activities = defaultdict(list)
        for event in events:
            for user in event.entities.get('users', []):
                user_activities[user].append(event)
        
        for user, user_events in user_activities.items():
            total_checks += 1
            
            # 관리자 계정의 이상 활동 확인
            if user in self.admin_users:
                anomaly_score += self._analyze_admin_behavior(user_events)
            else:
                anomaly_score += self._analyze_regular_user_behavior(user_events)
        
        return min(1.0, anomaly_score / max(1, total_checks))
    
    def detect_privilege_escalation(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """권한 확장 시도 감지"""
        escalation_indicators = []
        
        # 관리자 계정 활동 후 파일 접근 패턴 확인
        admin_events = [e for e in events if any(u in self.admin_users for u in e.entities.get('users', []))]
        file_access_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        
        if admin_events and file_access_events:
            escalation_indicators.append("관리자 계정 후 파일 접근")
        
        # 시스템 파일 접근 확인
        for event in file_access_events:
            for file_path in event.entities.get('files', []):
                if any(sensitive in file_path for sensitive in self.sensitive_files):
                    escalation_indicators.append(f"민감 파일 접근: {file_path}")
        
        return {
            "escalation_detected": len(escalation_indicators) > 0,
            "escalation_indicators": escalation_indicators,
            "risk_level": "HIGH" if len(escalation_indicators) > 1 else "MEDIUM" if escalation_indicators else "LOW"
        }
    
    def _analyze_admin_behavior(self, events: List[SecurityEvent]) -> float:
        """관리자 계정 행동 분석"""
        anomaly = 0.0
        
        # 파일 접근 이벤트가 있으면 이상 행동으로 간주
        file_access_count = sum(1 for e in events if e.event_type == EventType.FILE_ACCESS)
        if file_access_count > 0:
            anomaly += 0.7  # 높은 이상 점수
        
        return anomaly
    
    def _analyze_regular_user_behavior(self, events: List[SecurityEvent]) -> float:
        """일반 사용자 행동 분석"""
        anomaly = 0.0
        
        # 시스템 파일 접근 시도
        for event in events:
            if event.event_type == EventType.FILE_ACCESS:
                for file_path in event.entities.get('files', []):
                    if any(sensitive in file_path for sensitive in self.sensitive_files):
                        anomaly += 0.5
        
        return anomaly