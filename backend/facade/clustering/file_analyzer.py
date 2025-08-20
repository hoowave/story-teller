# file_analyzer.py (drop-in 교체)

from typing import List, Dict, Any, Set, Tuple
from facade.clustering.models import SecurityEvent, EventType
from facade.clustering.config import DEFAULT_CONFIG
from collections import defaultdict

class FileAnalyzer:
    """파일 접근 패턴 분석기(행동 맥락 반영)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.sensitive_files = self.config.sensitive_files
        self.service_accounts = set(self.config.service_accounts)

    def calculate_file_sensitivity(self, events: List[SecurityEvent]) -> float:
        if not events:
            return 0.0
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        if not file_events:
            return 0.0
        tot, cnt = 0.0, 0
        for e in file_events:
            for fp in e.entities.get('files', []) or []:
                cnt += 1
                tot += self._get_file_sensitivity(fp)
        base = (tot / cnt) if cnt else 0.0

        # 연속 민감 접근이 있으면 소폭 상향
        if self._has_sensitive_sequence(file_events):
            base = min(1.0, base + 0.15)
        return base

    def analyze_data_exfiltration_risk(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        high_risk_files = []
        access_patterns = []

        if not file_events:
            return {"exfiltration_risk_score": 0.0, "high_risk_files": [], "access_patterns": [], "total_file_accesses": 0}

        # 고민감 파일 수집
        for e in file_events:
            user = (e.entities.get('users') or ['unknown'])[0]
            for fp in e.entities.get('files', []) or []:
                sens = self._get_file_sensitivity(fp)
                if sens >= self.config.sensitivity_thresholds['high']:
                    high_risk_files.append({"file": fp, "sensitivity": sens, "timestamp": e.timestamp, "user": user})

        if len(file_events) > 3:
            access_patterns.append("다중 파일 접근")
        if self._has_sensitive_sequence(file_events):
            access_patterns.append("연속 민감 파일 접근")

        # 사용자–파일 신규 조합(세션 내 첫 등장)
        seen: Set[Tuple[str, str]] = set()
        new_pairs = 0
        for e in file_events:
            user = (e.entities.get('users') or ['unknown'])[0]
            for fp in e.entities.get('files', []) or []:
                key = (user, fp)
                if key not in seen:
                    seen.add(key)
                    new_pairs += 1
        if new_pairs >= 3:
            access_patterns.append("신규 사용자–파일 조합 다수")

        risk = 0.0
        risk += min(1.0, len(high_risk_files) * 0.15)
        risk += 0.15 if "연속 민감 파일 접근" in access_patterns else 0.0
        risk += 0.10 if "다중 파일 접근" in access_patterns else 0.0
        risk += 0.10 if "신규 사용자–파일 조합 다수" in access_patterns else 0.0

        # 서비스계정/정비창 감산
        if any((e.entities.get('users') or [''])[0] in self.service_accounts for e in file_events):
            risk = max(0.0, risk - 0.15)
        if any(self._in_maintenance(e.timestamp.hour) for e in file_events):
            risk = max(0.0, risk - 0.15)

        return {
            "exfiltration_risk_score": min(1.0, risk),
            "high_risk_files": high_risk_files,
            "access_patterns": access_patterns,
            "total_file_accesses": len(file_events)
        }

    # --- 내부 유틸 ---

    def _get_file_sensitivity(self, file_path: str) -> float:
        fp = (file_path or "").lower()
        for pattern, s in self.sensitive_files.items():
            if pattern in fp:
                return s
        return 0.3

    def _has_sensitive_sequence(self, file_events: List[SecurityEvent], k: int = 2, window_sec: int = 180) -> bool:
        seq, last_ts = 0, None
        for e in sorted(file_events, key=lambda x: x.timestamp):
            if self._event_has_sensitive(e):
                if last_ts and (e.timestamp - last_ts).total_seconds() <= window_sec:
                    seq += 1
                else:
                    seq = 1
                last_ts = e.timestamp
                if seq >= k:
                    return True
            else:
                seq, last_ts = 0, None
        return False

    def _event_has_sensitive(self, e: SecurityEvent) -> bool:
        for fp in e.entities.get('files', []) or []:
            low = fp.lower()
            if any(p in low for p in self.sensitive_files.keys()):
                return True
        return False

    def _in_maintenance(self, hour: int) -> bool:
        return any(s <= hour < t for (s, t) in self.config.maintenance_windows)
