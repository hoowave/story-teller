# user_analyzer.py (drop-in 교체)

from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime
from facade.clustering.models import SecurityEvent, EventType
from facade.clustering.config import DEFAULT_CONFIG

class UserAnalyzer:
    """사용자 행동 패턴 분석기(맥락 반영)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.admin_users = set(self.config.admin_users)
        self.service_accounts = set(self.config.service_accounts)
        self.sensitive_patterns = list(self.config.sensitive_files.keys())

    def calculate_user_anomaly(self, events: List[SecurityEvent]) -> float:
        if not events:
            return 0.0

        # 사용자별 세션화
        user_events = defaultdict(list)
        for e in events:
            for u in e.entities.get('users', []):
                user_events[u].append(e)

        total = 0.0
        n = 0
        for user, evs in user_events.items():
            n += 1
            total += self._score_user_session(user, sorted(evs, key=lambda x: x.timestamp))

        return min(1.0, total / max(1, n))

    def detect_privilege_escalation(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        indicators = []
        users = set(u for e in events for u in e.entities.get('users', []))
        admin_present = any(u in self.admin_users for u in users)

        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        if admin_present and file_events:
            # 관리자 활동 직후 민감 연속 접근 여부 확인
            if self._has_sensitive_sequence(file_events):
                indicators.append("관리자 컨텍스트에서 민감 파일 연속 접근")

        # 일반 사용자라도 민감 연속 접근이면 지표에 포함
        if self._has_sensitive_sequence(file_events):
            indicators.append("민감 파일 연속 접근")

        risk = "LOW"
        if len(indicators) >= 2:
            risk = "HIGH"
        elif indicators:
            risk = "MEDIUM"

        return {"escalation_detected": bool(indicators),
                "escalation_indicators": indicators,
                "risk_level": risk}

    # --- 내부 유틸 ---

    def _score_user_session(self, user: str, evs: List[SecurityEvent]) -> float:
        # 기본: 0
        score = 0.0

        # 서비스 계정이면 기본 감점(정상 반복 작업 가능성)
        if user in self.service_accounts:
            score -= 0.1

        # 업무시간/정비창 감점
        for e in evs:
            hour = e.timestamp.hour
            if self._in_maintenance(hour):
                score -= 0.1
            if self._in_business_hours(hour):
                score -= 0.05

        # 민감 파일 접근(연속성/밀도) 가산
        file_evs = [e for e in evs if e.event_type == EventType.FILE_ACCESS]
        if file_evs:
            if self._has_sensitive_sequence(file_evs):
                score += 0.4  # 연속성 가중
            # 업무외 시간대 + 민감파일이면 추가 가산
            if any((not self._in_business_hours(e.timestamp.hour)) and self._is_sensitive_any(e) for e in file_evs):
                score += 0.2

        # 관리자라면? 단일 신호 가산 제거. 복합 조건일 때만 소폭 가산
        if user in self.admin_users and self._has_sensitive_sequence(file_evs):
            score += 0.15

        return max(0.0, min(1.0, score))

    def _has_sensitive_sequence(self, file_events: List[SecurityEvent], k: int = 2, window_sec: int = 180) -> bool:
        # 최근 k개 이상 민감 파일을 짧은 시간 창에서 연속 접근했는지
        if len(file_events) < k:
            return False
        seq = 0
        last_ts = None
        for e in sorted(file_events, key=lambda x: x.timestamp):
            if self._is_sensitive_any(e):
                if last_ts and (e.timestamp - last_ts).total_seconds() <= window_sec:
                    seq += 1
                else:
                    seq = 1
                last_ts = e.timestamp
                if seq >= k:
                    return True
            else:
                seq = 0
                last_ts = None
        return False

    def _is_sensitive_any(self, e: SecurityEvent) -> bool:
        files = e.entities.get('files', []) or []
        for fp in files:
            low = fp.lower()
            if any(p in low for p in self.sensitive_patterns):
                return True
        return False

    def _in_business_hours(self, hour: int) -> bool:
        s, t = self.config.business_hours
        return s <= hour < t

    def _in_maintenance(self, hour: int) -> bool:
        return any(s <= hour < t for (s, t) in self.config.maintenance_windows)
