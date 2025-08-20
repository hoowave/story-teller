# cluster_analyzer.py (drop-in 교체)

from typing import List, Dict, Any
from models import SecurityEvent, ClusterMetrics, SeverityLevel
from time_analyzer import TimeAnalyzer
from ip_analyzer import IPAnalyzer
from user_analyzer import UserAnalyzer
from file_analyzer import FileAnalyzer
from config import DEFAULT_CONFIG
import statistics

class ClusterAnalyzer:
    """종합 클러스터링 분석기(다축 게이팅/보정)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.time_analyzer = TimeAnalyzer(self.config)
        self.ip_analyzer = IPAnalyzer(self.config)
        self.user_analyzer = UserAnalyzer(self.config)
        self.file_analyzer = FileAnalyzer(self.config)
        self.weights = self.config.metric_weights

    def analyze_cluster(self, events: List[SecurityEvent]) -> ClusterMetrics:
        if not events:
            return self._empty_metrics()

        # 축별 스코어
        time_conc = self.time_analyzer.calculate_time_concentration(events)
        ip_div = self.ip_analyzer.calculate_ip_diversification(events)
        user_anom = self.user_analyzer.calculate_user_anomaly(events)
        file_sens = self.file_analyzer.calculate_file_sensitivity(events)

        # 기본 가중합
        risk = (time_conc * self.weights['time'] +
                ip_div * self.weights['ip'] +
                user_anom * self.weights['user'] +
                file_sens * self.weights['file'])

        # 다축 게이팅
        # 축 임계(경험치): 각각 0.6 근처를 '의미 있는 상승'으로 취급
        axes = sum([
            1 if time_conc > 0.6 else 0,
            1 if ip_div > 0.6 else 0,
            1 if user_anom > 0.6 else 0,
            1 if file_sens > 0.6 else 0
        ])

        if axes < self.config.min_axes_for_alert:
            risk = max(0.0, risk - self.config.single_signal_penalty)

        if axes >= 3:
            risk = min(1.0, risk + self.config.orthogonality_bonus)

        # 파싱 신뢰도 보정
        try:
            avg_conf = statistics.mean([e.parsing_confidence for e in events if isinstance(e.parsing_confidence, (int, float))])
        except statistics.StatisticsError:
            avg_conf = 1.0
        if avg_conf < self.config.parsing_confidence_floor:
            risk *= 0.85  # 불확실성 감산

        attack_scenario = self._generate_attack_scenario(events, {
            'time_concentration': time_conc,
            'ip_diversification': ip_div,
            'user_anomaly': user_anom,
            'file_sensitivity': file_sens
        })
        priority = self._determine_priority_level(risk)

        return ClusterMetrics(
            time_concentration=time_conc,
            ip_diversification=ip_div,
            user_anomaly=user_anom,
            file_sensitivity=file_sens,
            overall_risk_score=risk,
            attack_scenario=attack_scenario,
            priority_level=priority
        )

    def get_detailed_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
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
            "unique_users": len(set(u for e in events for u in e.entities.get('users', []))),
            "unique_ips": len(set(e.src_ip for e in events) | set(e.dst_ip for e in events))
        }

    def _generate_attack_scenario(self, events: List[SecurityEvent], m: Dict[str, float]) -> str:
        scenarios = []
        if m['user_anomaly'] > 0.7: scenarios.append("권한 악용/상승 의심")
        if m['time_concentration'] > 0.6: scenarios.append("단시간 집중 활동")
        if m['file_sensitivity'] > 0.6: scenarios.append("민감 파일 연속 접근")
        if m['ip_diversification'] > 0.6: scenarios.append("내부 연쇄/다중 IP 활용")
        if not scenarios: scenarios.append("일반적 이벤트")
        return " + ".join(scenarios)

    def _determine_priority_level(self, risk: float) -> SeverityLevel:
        if risk >= 0.8: return SeverityLevel.CRITICAL
        if risk >= 0.6: return SeverityLevel.HIGH
        if risk >= 0.4: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _empty_metrics(self) -> ClusterMetrics:
        return ClusterMetrics(0.0,0.0,0.0,0.0,0.0,"이벤트 없음",SeverityLevel.LOW)
