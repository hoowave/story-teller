# time_analyzer.py






# ================================


from typing import List, Dict, Any
from datetime import timedelta
import statistics
from models import SecurityEvent
from config import DEFAULT_CONFIG


class TimeAnalyzer:
    """시간 기반 공격 패턴 분석기"""
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.time_window_threshold = self.config.time_window_threshold

    def calculate_time_concentration(self, events: List[SecurityEvent]) -> float:
        """시간 집중도 계산 (0.0 ~ 1.0)"""
        if len(events) < 2:
            return 0.0
        
        # 이벤트들을 시간순으로 정렬
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # 연속 이벤트 간 시간 간격 계산
        time_gaps = []
        for i in range(1, len(sorted_events)):
            gap = (sorted_events[i].timestamp - sorted_events[i-1].timestamp).total_seconds()
            time_gaps.append(gap)
        
        # 시간 집중도 계산: 짧은 간격이 많을수록 높은 점수
        if not time_gaps:
            return 0.0
        
        avg_gap = statistics.mean(time_gaps)
        concentration = max(0.0, min(1.0, (self.time_window_threshold - avg_gap) / self.time_window_threshold))
        
        return concentration
    
    def detect_burst_pattern(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """버스트 패턴 감지"""
        if len(events) < 2:
            return {"burst_detected": False, "burst_intensity": 0.0}
        
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        total_duration = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
        
        if total_duration == 0:
            return {"burst_detected": True, "burst_intensity": 1.0}
        
        # 이벤트 밀도 계산 (이벤트/초)
        event_density = len(events) / total_duration
        
        # 버스트 임계값
        burst_threshold = self.config.burst_threshold
        burst_detected = event_density > burst_threshold
        burst_intensity = min(1.0, event_density / burst_threshold)
        
        return {
            "burst_detected": burst_detected,
            "burst_intensity": burst_intensity,
            "total_duration": total_duration,
            "event_density": event_density
        }