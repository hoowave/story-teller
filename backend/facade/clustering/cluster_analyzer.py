# cluster_analyzer.py
from typing import List, Dict, Any
from dataclasses import dataclass
from facade.clustering.models import SecurityEvent, ClusterMetrics, SeverityLevel, EventType
from facade.clustering.time_analyzer import TimeAnalyzer
from facade.clustering.ip_analyzer import IPAnalyzer
from facade.clustering.user_analyzer import UserAnalyzer
from facade.clustering.file_analyzer import FileAnalyzer
from facade.clustering.config import DEFAULT_CONFIG

class ClusterAnalyzer:
    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.time_analyzer  = TimeAnalyzer(self.config)
        self.ip_analyzer    = IPAnalyzer(self.config)
        self.user_analyzer  = UserAnalyzer(self.config)
        self.file_analyzer  = FileAnalyzer(self.config)

    def analyze_cluster(self, events: List[SecurityEvent]) -> ClusterMetrics:
        t = self.time_analyzer.calculate_time_concentration(events)
        i = self.ip_analyzer.calculate_ip_diversification(events)
        u = self.user_analyzer.calculate_user_anomaly(events)
        f = self.file_analyzer.calculate_file_sensitivity(events)

        # 네트워크 위협 축(차단 유출/대용량/C2)
        net_score, _ = self.ip_analyzer.calculate_network_threat(events)

        # 가중 합산 (+ 네트워크 축은 파일/사용자 축 성격이라 약간 낮은 가중으로 결합)
        w = self.config.metric_weights  # {'time':0.25,'ip':0.20,'user':0.30,'file':0.25}
        base = (w['time']*t + w['ip']*i + w['user']*u + w['file']*f)
        overall = min(1.0, base + 0.2 * net_score)

        # 단일 축만 높을 때 패널티
        axes_hit = sum(1 for x in [t,i,u,f,net_score] if x >= self.config.sensitivity_thresholds['low'])
        if axes_hit < self.config.min_axes_for_alert:
            overall = max(0.0, overall - self.config.single_signal_penalty)
        # 서로 다른 축 3개↑ 동시 히트 시 보너스
        if axes_hit >= 3:
            overall = min(1.0, overall + self.config.orthogonality_bonus)

        # 시나리오 라벨링
        detailed = self.get_detailed_analysis(events)
        attack_scenario = self._label_scenario(detailed, t,i,u,f,net_score)

        # 우선순위 산정
        level = SeverityLevel.LOW
        if   overall >= self.config.sensitivity_thresholds['critical']: level = SeverityLevel.CRITICAL
        elif overall >= self.config.sensitivity_thresholds['high']:     level = SeverityLevel.HIGH
        elif overall >= self.config.sensitivity_thresholds['medium']:   level = SeverityLevel.MEDIUM
        elif overall >= self.config.sensitivity_thresholds['low']:      level = SeverityLevel.LOW

        return ClusterMetrics(
            time_concentration=t,
            ip_diversification=i,
            user_anomaly=u,
            file_sensitivity=f,
            network_threat=net_score,
            overall_risk_score=overall,
            attack_scenario=attack_scenario,
            priority_level=level
        )

    def _label_scenario(self, detailed: Dict[str,Any], t,i,u,f,net_score) -> str:
        ip_ = detailed["ip_analysis"]
        ua_ = detailed["user_analysis"]
        fa_ = detailed["file_analysis"]
        na_ = detailed["network_analysis"]

        # 시나리오 1: 외부 침입 → 관리자/DB → 외부 유출(또는 차단된 유출)
        cond_exfil = (fa_.get("exfiltration_risk_score",0) >= 0.35) or (na_.get("blocked_egress",0) > 0) or (na_.get("egress_bytes",0) >= self.config.exfil_bytes_threshold)
        cond_intr  = (ip_.get("external_to_internal",0) >= 1)
        if cond_intr and cond_exfil:
            return "외부 침입 후 데이터 유출(차단 포함)"

        # 시나리오 2: 내부 확산(측면 이동) + 유출 시도/차단
        if ip_.get("lateral_movement_detected", False) and cond_exfil:
            return "내부 측면 이동 후 외부 유출 시도"

        # 인증 남용 신호
        if ua_.get("escalation_detected") or u >= 0.3:
            return "인증 남용/권한 가로채기 의심"

        # 기본
        if t >= 0.6 and i < 0.3:
            return "단시간 집중 활동"
        return "정상에 가까움"

    def get_detailed_analysis(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        time_analysis = self.time_analyzer.detect_burst_pattern(events)
        ip_analysis   = self.ip_analyzer.analyze_network_movement(events)
        user_analysis = self.user_analyzer.detect_privilege_escalation(events)
        file_analysis = self.file_analyzer.analyze_data_exfiltration_risk(events)
        net_score, net_detail = self.ip_analyzer.calculate_network_threat(events)

        unique_users = len({u for e in events for u in (e.entities.get("users") or [])})
        unique_ips   = len({ip for e in events for ip in (e.entities.get("ips") or [])})

        return {
            "time_analysis": time_analysis,
            "ip_analysis": ip_analysis,
            "user_analysis": user_analysis,
            "file_analysis": file_analysis,
            "event_count": len(events),
            "unique_users": unique_users,
            "unique_ips": unique_ips,
            "network_analysis": {
                "network_threat": net_score,
                **net_detail
            }
        }
