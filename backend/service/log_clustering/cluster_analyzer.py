# ================================

# cluster_analyzer.py
from typing import List, Dict, Any
from models import SecurityEvent, ClusterMetrics, SeverityLevel
from time_analyzer import TimeAnalyzer
from ip_analyzer import IPAnalyzer
from user_analyzer import UserAnalyzer
from file_analyzer import FileAnalyzer
from config import DEFAULT_CONFIG

class ClusterAnalyzer:
    """종합 클러스터링 분석기"""
    
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        
        # 모든 분석기에 동일한 config 전달
        self.time_analyzer = TimeAnalyzer(self.config)
        self.ip_analyzer = IPAnalyzer(self.config)
        self.user_analyzer = UserAnalyzer(self.config)
        self.file_analyzer = FileAnalyzer(self.config)
        
        # 가중치를 config에서 가져오기
        self.weights = self.config.metric_weights
    
    def analyze_cluster(self, events: List[SecurityEvent]) -> ClusterMetrics:
        """전체 클러스터 분석 수행"""
        if not events:
            return self._empty_metrics()
        
        # 각 분석기별 지표 계산
        time_concentration = self.time_analyzer.calculate_time_concentration(events)
        ip_diversification = self.ip_analyzer.calculate_ip_diversification(events)
        user_anomaly = self.user_analyzer.calculate_user_anomaly(events)
        file_sensitivity = self.file_analyzer.calculate_file_sensitivity(events)
        
        # 종합 위험도 계산
        overall_risk = (
            time_concentration * self.weights['time'] +
            ip_diversification * self.weights['ip'] +
            user_anomaly * self.weights['user'] +
            file_sensitivity * self.weights['file']
        )
        
        # 공격 시나리오 생성
        attack_scenario = self._generate_attack_scenario(events, {
            'time_concentration': time_concentration,
            'ip_diversification': ip_diversification,
            'user_anomaly': user_anomaly,
            'file_sensitivity': file_sensitivity
        })
        
        # 우선순위 레벨 결정
        priority_level = self._determine_priority_level(overall_risk)
        
        return ClusterMetrics(
            time_concentration=time_concentration,
            ip_diversification=ip_diversification,
            user_anomaly=user_anomaly,
            file_sensitivity=file_sensitivity,
            overall_risk_score=overall_risk,
            attack_scenario=attack_scenario,
            priority_level=priority_level
        )
    
    def get_detailed_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """상세 분석 결과 반환"""
        time_analysis = self.time_analyzer.detect_burst_pattern(events)
        ip_analysis = self.ip_analyzer.analyze_network_movement(events)
        user_analysis = self.user_analyzer.detect_privilege_escalation(events)
        file_analysis = self.file_analyzer.analyze_data_exfiltration_risk(events)
        
        return {
            "time_analysis": time_analysis,
            "ip_analysis": ip_analysis,
            "user_analysis": user_analysis,
            "file_analysis": file_analysis,
            "event_count": len(events),
            "unique_users": len(set(user for event in events for user in event.entities.get('users', []))),
            "unique_ips": len(set(event.src_ip for event in events) | set(event.dst_ip for event in events))
        }
    
    def _generate_attack_scenario(self, events: List[SecurityEvent], metrics: Dict[str, float]) -> str:
        """공격 시나리오 텍스트 생성"""
        scenarios = []
        
        if metrics['user_anomaly'] > 0.7:
            scenarios.append("관리자 권한을 이용한 시스템 침투")
        
        if metrics['time_concentration'] > 0.6:
            scenarios.append("단시간 내 집중적인 공격")
        
        if metrics['file_sensitivity'] > 0.6:
            scenarios.append("민감한 시스템 파일에 대한 접근 시도")
        
        if metrics['ip_diversification'] > 0.5:
            scenarios.append("다중 IP를 활용한 분산 공격")
        
        if not scenarios:
            scenarios.append("일반적인 보안 이벤트")
        
        return " + ".join(scenarios)
    
    def _determine_priority_level(self, risk_score: float) -> SeverityLevel:
        """위험도 점수에 따른 우선순위 결정"""
        if risk_score >= 0.8:
            return SeverityLevel.CRITICAL
        elif risk_score >= 0.6:
            return SeverityLevel.HIGH
        elif risk_score >= 0.4:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _empty_metrics(self) -> ClusterMetrics:
        """빈 메트릭 반환"""
        return ClusterMetrics(
            time_concentration=0.0,
            ip_diversification=0.0,
            user_anomaly=0.0,
            file_sensitivity=0.0,
            overall_risk_score=0.0,
            attack_scenario="이벤트 없음",
            priority_level=SeverityLevel.LOW
        )