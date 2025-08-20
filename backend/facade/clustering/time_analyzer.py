# time_analyzer.py (drop-in 교체)

from typing import List, Dict, Any
from facade.log_clustering.models import SecurityEvent
from facade.log_clustering.config import DEFAULT_CONFIG
import statistics

class TimeAnalyzer:
    """시간 기반 공격 패턴(시간대 보정)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG

    def calculate_time_concentration(self, events: List[SecurityEvent]) -> float:
        if len(events) < 2:
            return 0.0
        evs = sorted(events, key=lambda x: x.timestamp)
        gaps = [(evs[i].timestamp - evs[i-1].timestamp).total_seconds() for i in range(1, len(evs))]
        if not gaps:
            return 0.0
        avg_gap = statistics.mean(gaps)
        base = max(0.0, min(1.0, (self.config.time_window_threshold - avg_gap) / self.config.time_window_threshold))
        # 업무시간/정비창 완화
        hours = [e.timestamp.hour for e in evs]
        if any(self._in_business(h) for h in hours):
            base *= 0.9
        if any(self._in_maint(h) for h in hours):
            base *= 0.85
        return base

    def detect_burst_pattern(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        if len(events) < 2:
            return {"burst_detected": False, "burst_intensity": 0.0}
        evs = sorted(events, key=lambda x: x.timestamp)
        duration = (evs[-1].timestamp - evs[0].timestamp).total_seconds() or 1.0
        density = len(events) / duration
        thr = self.config.burst_threshold
        detected = density > thr
        intensity = min(1.0, density / thr)
        # 시간대 보정
        if any(self._in_business(e.timestamp.hour) for e in evs):
            intensity *= 0.9
        if any(self._in_maint(e.timestamp.hour) for e in evs):
            intensity *= 0.85
        return {"burst_detected": intensity > 1.0, "burst_intensity": intensity, "total_duration": duration, "event_density": density}

    def _in_business(self, hour: int) -> bool:
        s, t = self.config.business_hours
        return s <= hour < t

    def _in_maint(self, hour: int) -> bool:
        return any(s <= hour < t for (s, t) in self.config.maintenance_windows)
