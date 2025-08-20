# config.py


# ================================

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class AnalysisConfig:
    """분석 설정"""
    # 시간 분석 설정
    time_window_threshold: int = 300  # 5분
    burst_threshold: float = 2/60  # 분당 2개 이벤트
    
    # 네트워크 설정
    internal_networks: List[str] = None
    
    # 사용자 설정
    admin_users: List[str] = None
    
    # 파일 민감도 설정
    sensitive_files: Dict[str, float] = None
    
    # 가중치 설정
    metric_weights: Dict[str, float] = None
    
    # 민감도 임계값
    sensitivity_thresholds: Dict[str, float] = None
    

    def __post_init__(self):

        # 내부 네트워크 설정
        if self.internal_networks is None:
            self.internal_networks = [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16'
            ]
        
        # 관리자 계정 설정
        if self.admin_users is None:
            self.admin_users = ['admin', 'root', 'administrator']
        

        # 민감한 파일 설정
        if self.sensitive_files is None:
            self.sensitive_files = {
                '/var/log/': 0.8,
                '/etc/': 0.9,
                '/root/': 1.0,
                '/home/': 0.6,
                'passwd': 1.0,
                'shadow': 1.0,
                '.config': 0.7
            }
        
        # 가중치 설정
        if self.metric_weights is None:
            self.metric_weights = {
                'time': 0.25,
                'ip': 0.20,
                'user': 0.30,
                'file': 0.25
            }
        
        # 민감도 임계값 설정
        if self.sensitivity_thresholds is None:
            self.sensitivity_thresholds = {
                'low': 0.4,
                'medium': 0.6,
                'high': 0.8,
                'critical': 0.9
            }

# 전역 설정 인스턴스
DEFAULT_CONFIG = AnalysisConfig()