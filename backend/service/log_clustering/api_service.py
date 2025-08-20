# api_service.py



# ================================


"""API 서비스 모듈 - FastAPI와 연동을 위한 서비스 레이어"""
from typing import List, Dict, Any, Optional
from models import SecurityEvent, ClusterMetrics
from cluster_analyzer import ClusterAnalyzer
from data_loader import DataLoader
from utils import ReportGenerator
import json

class SecurityAnalysisService:
    """보안 분석 서비스 클래스"""
    
    def __init__(self):
        self.cluster_analyzer = ClusterAnalyzer()
        self.data_loader = DataLoader()
        self.report_generator = ReportGenerator()
    
    def analyze_events(self, events_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """이벤트 데이터 분석"""
        try:
            # 딕셔너리 데이터를 SecurityEvent 객체로 변환
            events = []
            for event_data in events_data:
                try:
                    event = SecurityEvent.from_dict(event_data)
                    events.append(event)
                except Exception as e:
                    print(f"이벤트 변환 실패: {e}")
                    continue
            
            if not events:
                return self._empty_analysis_result()
            
            # 클러스터 분석 수행
            metrics = self.cluster_analyzer.analyze_cluster(events)
            detailed_analysis = self.cluster_analyzer.get_detailed_analysis(events)
            
            # 권장사항 생성
            recommendations = self._generate_recommendations(metrics)
            
            # 요약 보고서 생성
            summary_report = self.report_generator.generate_summary_report(metrics, detailed_analysis)
            incident_timeline = self.report_generator.generate_incident_timeline(events)
            
            return {
                "success": True,
                "analysis_result": {
                    "metrics": {
                        "time_concentration": metrics.time_concentration,
                        "ip_diversification": metrics.ip_diversification,
                        "user_anomaly": metrics.user_anomaly,
                        "file_sensitivity": metrics.file_sensitivity,
                        "overall_risk_score": metrics.overall_risk_score
                    },
                    "attack_scenario": metrics.attack_scenario,
                    "priority_level": metrics.priority_level.value,
                    "detailed_analysis": detailed_analysis,
                    "recommendations": recommendations,
                    "summary_report": summary_report,
                    "incident_timeline": incident_timeline
                },
                "metadata": {
                    "total_events": len(events),
                    "analysis_timestamp": "2023-01-01T12:02:00Z",
                    "analysis_version": "1.0.0"
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis_result": None
            }
    
    def analyze_json_string(self, json_string: str) -> Dict[str, Any]:
        """JSON 문자열 형태의 로그 분석"""
        try:
            data = json.loads(json_string)
            events_data = data.get('events', [])
            return self.analyze_events(events_data)
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"JSON 파싱 오류: {str(e)}",
                "analysis_result": None
            }
    
    def analyze_sample_data(self) -> Dict[str, Any]:
        """샘플 데이터 분석"""
        events = self.data_loader.load_sample_data()
        events_data = []
        
        # SecurityEvent를 딕셔너리로 변환
        for event in events:
            event_dict = {
                "event_id": event.event_id,
                "ts": event.timestamp.isoformat() + "+09:00",
                "source_type": event.source_type,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "msg": event.message,
                "event_type_hint": event.event_type.value,
                "severity_hint": event.severity.value,
                "entities": event.entities,
                "parsing_confidence": event.parsing_confidence
            }
            events_data.append(event_dict)
        
        return self.analyze_events(events_data)
    
    def _generate_recommendations(self, metrics: ClusterMetrics) -> List[str]:
        """위험도에 따른 권장사항 생성"""
        recommendations = []
        
        if metrics.overall_risk_score >= 0.8:
            recommendations.extend([
                "즉시 해당 계정 및 IP 차단 조치 필요",
                "보안팀 긴급 대응 절차 가동",
                "영향받은 시스템 격리 검토"
            ])
        elif metrics.overall_risk_score >= 0.6:
            recommendations.extend([
                "추가 모니터링 강화 필요",
                "해당 사용자 계정 보안 검토",
                "접근 로그 상세 분석"
            ])
        elif metrics.overall_risk_score >= 0.4:
            recommendations.extend([
                "정기 보안 점검 수행",
                "사용자 보안 교육 고려"
            ])
        else:
            recommendations.append("정상 범위 내 활동으로 판단됨")
        
        # 특정 지표별 권장사항
        if metrics.user_anomaly > 0.7:
            recommendations.append("사용자 권한 재검토 및 최소 권한 원칙 적용")
        
        if metrics.file_sensitivity > 0.7:
            recommendations.append("민감 파일 접근 권한 강화 및 DLP 솔루션 적용")
        
        if metrics.time_concentration > 0.7:
            recommendations.append("공격 패턴 기반 실시간 차단 룰 적용")
        
        return recommendations
    
    def _empty_analysis_result(self) -> Dict[str, Any]:
        """빈 분석 결과 반환"""
        return {
            "success": True,
            "analysis_result": {
                "metrics": {
                    "time_concentration": 0.0,
                    "ip_diversification": 0.0,
                    "user_anomaly": 0.0,
                    "file_sensitivity": 0.0,
                    "overall_risk_score": 0.0
                },
                "attack_scenario": "이벤트 없음",
                "priority_level": "low",
                "detailed_analysis": {},
                "recommendations": ["분석할 이벤트가 없습니다"],
                "summary_report": "분석할 데이터가 없습니다",
                "incident_timeline": ""
            },
            "metadata": {
                "total_events": 0,
                "analysis_timestamp": "2023-01-01T12:02:00Z",
                "analysis_version": "1.0.0"
            }
        }
