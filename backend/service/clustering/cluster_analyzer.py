# cluster_analyzer.py
from typing import List, Dict, Any
import statistics
from models import SecurityEvent, ClusterMetrics, SeverityLevel
from time_analyzer import TimeAnalyzer
from ip_analyzer import IPAnalyzer
from user_analyzer import UserAnalyzer
from file_analyzer import FileAnalyzer
from config import DEFAULT_CONFIG

class ClusterAnalyzer:
    """종합 클러스터링 분석기(다축 게이팅/보정 + 조합 규칙 Uplift)"""

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

        # 1) 축별 점수
        time_conc = self.time_analyzer.calculate_time_concentration(events)
        ip_div    = self.ip_analyzer.calculate_ip_diversification(events)
        user_anom = self.user_analyzer.calculate_user_anomaly(events)
        file_sens = self.file_analyzer.calculate_file_sensitivity(events)

        # (있을 수도 있는) 네트워크 위협 축
        net_threat = None
        net_details = {}
        try:
            net_threat, net_details = self.ip_analyzer.calculate_network_threat(events)  # 5축 버전일 때만 존재
        except Exception:
            pass

        # 2) 가중합
        risk = (
            time_conc * self.weights.get('time', 0.25) +
            ip_div    * self.weights.get('ip', 0.20) +
            user_anom * self.weights.get('user', 0.30) +
            file_sens * self.weights.get('file', 0.25)
        )
        if net_threat is not None:
            risk += net_threat * self.weights.get('network', 0.0)

        # 3) 다축 게이팅
        axes_vals = [time_conc, ip_div, user_anom, file_sens]
        if net_threat is not None:
            axes_vals.append(net_threat)
        axes = sum(1 for v in axes_vals if v > 0.6)

        if axes < self.config.min_axes_for_alert:
            risk = max(0.0, risk - self.config.single_signal_penalty)
        if axes >= 3:
            risk = min(1.0, risk + self.config.orthogonality_bonus)

        # 4) 파싱 신뢰도 감산
        try:
            avg_conf = statistics.mean(
                [e.parsing_confidence for e in events if isinstance(e.parsing_confidence, (int, float))]
            )
        except statistics.StatisticsError:
            avg_conf = 1.0
        if avg_conf < self.config.parsing_confidence_floor:
            risk *= 0.85

        # 5) 상세 분석(조합 규칙에 필요)
        time_analysis = self.time_analyzer.detect_burst_pattern(events)
        ip_analysis   = self.ip_analyzer.analyze_network_movement(events)
        user_analysis = self.user_analyzer.detect_privilege_escalation(events)
        file_analysis = self.file_analyzer.analyze_data_exfiltration_risk(events)

        # 6) 조합 규칙 Uplift (게이팅 우회 승격)
        uplift_reasons = []

        # 6-1) DB 대량 민감 접근 + 대용량 외부 전송(또는 차단된 외부 전송)
        exfil_score = float(file_analysis.get("exfiltration_risk_score", 0.0))
        db_heavy    = file_analysis.get("db_heavy_objects") or []
        bytes_out   = int(file_analysis.get("total_bytes_out", 0))
        exfil_thr   = getattr(self.config, "exfil_bytes_threshold", 50 * 1024 * 1024)

        blocked_egress = 0
        if net_details:
            blocked_egress = int(net_details.get("blocked_egress", 0))

        if (db_heavy and (bytes_out >= exfil_thr or blocked_egress >= 1)) or exfil_score >= 0.7:
            risk = max(risk, 0.6)  # 최소 HIGH로 끌어올림
            uplift_reasons.append("DB 대량 민감 접근 + 유출(또는 차단된 유출)")

        # 6-2) 내부 측면 이동 + 유출 신호(대량 전송 또는 차단된 외부 전송)
        if ip_analysis.get("lateral_movement_detected") and (bytes_out >= exfil_thr or blocked_egress >= 1):
            risk = max(risk, 0.6)
            uplift_reasons.append("내부 측면 이동 + 유출 신호")

        # 6-3) 관리자 탈취 징후(실패폭주 후 성공 등) + DB 민감 접근
        if user_analysis.get("escalation_detected") and db_heavy:
            risk = max(risk, 0.6)
            uplift_reasons.append("관리자 탈취 의심 + DB 민감 접근")

        # 6-4) C2 beacon + 차단된 외부 전송(시나리오2)
        if net_details:
            beacon_hits = net_details.get("beacon_hits") or []
            if beacon_hits and blocked_egress >= 1:
                risk = max(risk, 0.6)
                uplift_reasons.append("C2 beacon + 차단된 외부 전송")

        # 7) 시나리오 문자열 생성
        factors = {
            'time_concentration': time_conc,
            'ip_diversification': ip_div,
            'user_anomaly': user_anom,
            'file_sensitivity': file_sens
        }
        if net_threat is not None:
            factors['network_threat'] = net_threat

        attack_scenario = self._generate_attack_scenario(events, factors, uplift_reasons)
        priority = self._determine_priority_level(risk)

        # 8) 리턴
        # (metrics 구조가 4축/5축 둘 다 호환되게 생성)
        try:
            return ClusterMetrics(
                time_concentration=time_conc,
                ip_diversification=ip_div,
                user_anomaly=user_anom,
                file_sensitivity=file_sens,
                network_threat=net_threat if net_threat is not None else 0.0,  # 5축 버전이면 사용
                overall_risk_score=risk,
                attack_scenario=attack_scenario,
                priority_level=priority
            )
        except TypeError:
            # 4축 버전의 ClusterMetrics 시그니처와도 호환
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
        ip_analysis   = self.ip_analyzer.analyze_network_movement(events)
        user_analysis = self.user_analyzer.detect_privilege_escalation(events)
        file_analysis = self.file_analyzer.analyze_data_exfiltration_risk(events)
        payload = {
            "time_analysis": time_analysis,
            "ip_analysis": ip_analysis,
            "user_analysis": user_analysis,
            "file_analysis": file_analysis,
            "event_count": len(events),
            "unique_users": len(set(u for e in events for u in e.entities.get('users', []))),
            "unique_ips": len(set(e.src_ip for e in events) | set(e.dst_ip for e in events))
        }
        # 네트워크 위협 축이 구현되어 있다면 상세도 포함
        try:
            net_score, net_details = self.ip_analyzer.calculate_network_threat(events)
            payload["network_analysis"] = {"network_threat": net_score, **net_details}
        except Exception:
            pass
        return payload

    def _generate_attack_scenario(self, events: List[SecurityEvent], m: Dict[str, float], reasons=None) -> str:
        s = []
        if m.get('user_anomaly', 0.0) > 0.7: s.append("자격 남용/권한 악용 의심")
        if m.get('time_concentration', 0.0) > 0.6: s.append("단시간 집중 활동")
        if m.get('file_sensitivity', 0.0) > 0.6: s.append("민감/DB 대량 접근")
        if m.get('ip_diversification', 0.0) > 0.6: s.append("내부 연쇄/다중 IP 활용")
        if m.get('network_threat', 0.0) > 0.6: s.append("C2/차단 유출/의심 DNS")
        if reasons:
            s.extend(reasons)
        return " + ".join(dict.fromkeys(s)) if s else "일반적 이벤트"  # 중복 제거

    def _determine_priority_level(self, risk: float) -> SeverityLevel:
        if risk >= 0.8: return SeverityLevel.CRITICAL
        if risk >= 0.6: return SeverityLevel.HIGH
        if risk >= 0.4: return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _empty_metrics(self) -> ClusterMetrics:
        try:
            return ClusterMetrics(0.0,0.0,0.0,0.0,0.0,0.0,"이벤트 없음",SeverityLevel.LOW)
        except TypeError:
            return ClusterMetrics(0.0,0.0,0.0,0.0,0.0,"이벤트 없음",SeverityLevel.LOW)
