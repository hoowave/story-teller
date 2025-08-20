# ================================

# ip_analyzer.py
from typing import List, Dict, Any
from collections import Counter
import ipaddress
from facade.log_clustering.models import SecurityEvent
from facade.log_clustering.config import DEFAULT_CONFIG

class IPAnalyzer:
    """IP 기반 공격 패턴 분석기"""
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        # 하드코딩된 부분을 config에서 가져오기
        self.internal_networks = [
            ipaddress.IPv4Network(network) 
            for network in self.config.internal_networks
        ]
    
    def calculate_ip_diversification(self, events: List[SecurityEvent]) -> float:
        """IP 다각화 지수 계산"""
        if not events:
            return 0.0
        
        # 고유 소스/대상 IP 개수
        src_ips = set(event.src_ip for event in events)
        dst_ips = set(event.dst_ip for event in events)
        
        total_unique_ips = len(src_ips | dst_ips)
        total_events = len(events)
        
        # 다각화 지수: 고유 IP 수 / 총 이벤트 수
        diversification = min(1.0, total_unique_ips / total_events)
        
        return diversification
    
    def analyze_network_movement(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """네트워크 이동 패턴 분석"""
        external_to_internal = 0
        internal_to_internal = 0
        lateral_movement_detected = False
        
        for event in events:
            src_internal = self._is_internal_ip(event.src_ip)
            dst_internal = self._is_internal_ip(event.dst_ip)
            
            if not src_internal and dst_internal:
                external_to_internal += 1
            elif src_internal and dst_internal:
                internal_to_internal += 1
        
        # 측면 이동 감지: 내부에서 내부로의 이동이 있는 경우
        if internal_to_internal > 0:
            lateral_movement_detected = True
        
        return {
            "external_to_internal": external_to_internal,
            "internal_to_internal": internal_to_internal,
            "lateral_movement_detected": lateral_movement_detected,
            "network_penetration_depth": external_to_internal + internal_to_internal
        }
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """내부 IP인지 확인"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.internal_networks)
        except:
            return False