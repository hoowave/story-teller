# user_analyzer.py
from typing import List, Dict, Any
from collections import defaultdict
from datetime import timedelta
from models import SecurityEvent, EventType
from config import DEFAULT_CONFIG

class UserAnalyzer:
    """사용자 행동 패턴 분석기(인증 특화 신호 포함)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.admin_users = set(self.config.admin_users)
        self.service_accounts = set(self.config.service_accounts)
        self.sensitive_files = set(self.config.sensitive_files.keys())

    def calculate_user_anomaly(self, events: List[SecurityEvent]) -> float:
        if not events: return 0.0

        base = 0.0
        total_checks = 0
        # 기존 민감파일 연속 접근 등 베이스(간단)
        user_activities = defaultdict(list)
        for e in events:
            for u in e.entities.get('users', []):
                user_activities[u].append(e)

        for user, evs in user_activities.items():
            total_checks += 1
            score = 0.0
            # 서비스 계정 기본 감산
            if user in self.service_accounts:
                score -= 0.1
            # 관리자 + 민감연속 소폭 가산
            if user in self.admin_users:
                if self._has_sensitive_sequence([e for e in evs if e.event_type == EventType.FILE_ACCESS]):
                    score += 0.15
            base += max(0.0, score)

        base = min(1.0, base / max(1, total_checks))

        # === 인증 특화 보너스 결합 ===
        auth_bonus = self._auth_abuse_signals(events)
        return min(1.0, base + auth_bonus)

    def detect_privilege_escalation(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        indicators = []
        admin_present = any(u in self.admin_users for e in events for u in e.entities.get('users', []))
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        if admin_present and self._has_sensitive_sequence(file_events):
            indicators.append("관리자 컨텍스트에서 민감 파일 연속 접근")
        # 인증 특화 신호가 있으면 같이 표기
        auth_signal = self._auth_abuse_signals(events)
        if auth_signal >= 0.35:
            indicators.append("실패폭주 후 단기 관리자 성공")
        risk = "LOW"
        if len(indicators) >= 2: risk = "HIGH"
        elif indicators: risk = "MEDIUM"
        return {"escalation_detected": bool(indicators), "escalation_indicators": indicators, "risk_level": risk}

    # --- 내부 유틸 ---

    def _auth_abuse_signals(self, events: List[SecurityEvent]) -> float:
        """실패폭주→단기성공, 스프레이, 업무외 관리자 성공, first-seen IP/ASN"""
        auth = [e for e in events if e.event_type == EventType.AUTHENTICATION]
        if not auth: return 0.0

        auth_sorted = sorted(auth, key=lambda x: x.timestamp)
        fail_burst_by_key = defaultdict(list)  # (src_ip, user) -> [times]
        spray_users = set()
        success_after_burst = False

        for e in auth_sorted:
            status = (e.entities.get("status") or "").lower()
            user = (e.entities.get("users") or ["unknown"])[0]
            key = (e.src_ip, user)
            if status == "fail":
                t = e.timestamp
                fail_burst_by_key[key].append(t)
                # 창 내 실패 개수
                recent = [x for x in fail_burst_by_key[key] if (t - x) <= timedelta(seconds=self.config.auth_burst_window_sec)]
                if len(recent) >= 1:
                    spray_users.add(user)
            elif status == "success":
                t = e.timestamp
                recent_fails = [x for x in fail_burst_by_key.get(key, []) if (t - x) <= timedelta(seconds=self.config.auth_burst_window_sec)]
                if len(recent_fails) >= self.config.auth_fail_burst_threshold:
                    success_after_burst = True

        bonus = 0.0
        if success_after_burst: bonus += 0.35
        if len(spray_users) >= self.config.auth_spray_user_threshold: bonus += 0.25

        # 관리자 성공(업무외/first-seen ASN/Geo)
        for e in auth_sorted:
            user = (e.entities.get("users") or ["unknown"])[0]
            if user in self.admin_users and (e.entities.get("status") or "").lower() == "success":
                h = e.timestamp.hour
                if not (self.config.business_hours[0] <= h < self.config.business_hours[1]):
                    bonus += 0.2
                if (e.entities.get("asn") == "first_seen") or (e.entities.get("geo") == "first_seen"):
                    bonus += 0.2

        # 상한
        return min(0.6, bonus)

    def _has_sensitive_sequence(self, file_events: List[SecurityEvent], k: int = 2, window_sec: int = 180) -> bool:
        if len(file_events) < k: return False
        seq, last_ts = 0, None
        for e in sorted(file_events, key=lambda x: x.timestamp):
            if self._event_has_sensitive(e):
                if last_ts and (e.timestamp - last_ts).total_seconds() <= window_sec:
                    seq += 1
                else:
                    seq = 1
                last_ts = e.timestamp
                if seq >= k: return True
            else:
                seq, last_ts = 0, None
        return False

    def _event_has_sensitive(self, e: SecurityEvent) -> bool:
        for fp in e.entities.get('files', []) or []:
            low = fp.lower()
            if any(p in low for p in self.sensitive_files):
                return True
        return False
