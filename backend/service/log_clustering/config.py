# ================================

# config.py
from dataclasses import dataclass
from typing import Dict

@dataclass
class AnalysisConfig:
    """분석 설정"""
    time_window_threshold: int = 300  # 5분
    burst_threshold: float = 2/60  # 분당 2개 이벤트
    
    # 가중치 설정
    metric_weights: Dict[str, float] = None
    
    # 민감도 임계값
    sensitivity_thresholds: Dict[str, float] = None
    
    def __post_init__(self):
        if self.metric_weights is None:
            self.metric_weights = {
                'time': 0.25,
                'ip': 0.20,
                'user': 0.30,
                'file': 0.25
            }
        
        if self.sensitivity_thresholds is None:
            self.sensitivity_thresholds = {
                'low': 0.4,
                'medium': 0.6,
                'high': 0.8,
                'critical': 0.9
            }

# 전역 설정 인스턴스
DEFAULT_CONFIG = AnalysisConfig()