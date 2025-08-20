# ================================

# utils.py
import json
from typing import List, Dict, Any
from datetime import datetime
from models import SecurityEvent, ClusterMetrics

class LogProcessor:
    """로그 처리 유틸리티"""
    
    @staticmethod
    def load_json_logs(file_path: str) -> List[Dict[str, Any]]:
        """JSON 파일에서 로그 데이터 로드"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('events', [])
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {file_path}")
            return []
        except json.JSONDecodeError:
            print(f"JSON 형식이 올바르지 않습니다: {file_path}")
            return []
    
    @staticmethod
    def save_analysis_result(result: Dict[str, Any], output_path: str):
        """분석 결과를 JSON 파일로 저장"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False, default=str)
            print(f"분석 결과가 저장되었습니다: {output_path}")
        except Exception as e:
            print(f"파일 저장 중 오류 발생: {e}")
    
    @staticmethod
    def validate_event_data(event_data: Dict[str, Any]) -> bool:
        """이벤트 데이터 유효성 검증"""
        required_fields = ['event_id', 'ts', 'src_ip', 'dst_ip', 'msg', 'event_type_hint', 'severity_hint', 'entities']
        
        for field in required_fields:
            if field not in event_data:
                print(f"필수 필드 누락: {field}")
                return False
        
        # 시간 형식 검증
        try:
            datetime.fromisoformat(event_data['ts'].replace('+09:00', ''))
        except ValueError:
            print(f"잘못된 시간 형식: {event_data['ts']}")
            return False
        
        return True

class ReportGenerator:
    """보고서 생성 유틸리티"""
    
    @staticmethod
    def generate_summary_report(metrics: ClusterMetrics, detailed_analysis: Dict[str, Any]) -> str:
        """요약 보고서 생성"""
        report = f"""
=== 보안 로그 분석 요약 보고서 ===
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

위험도 평가
- 종합 위험도: {metrics.overall_risk_score:.1%} ({metrics.priority_level.value.upper()})
- 공격 시나리오: {metrics.attack_scenario}

주요 지표
- 시간 집중도: {metrics.time_concentration:.1%}
- IP 다각화: {metrics.ip_diversification:.1%}
- 사용자 이상행동: {metrics.user_anomaly:.1%}
- 파일 민감도: {metrics.file_sensitivity:.1%}

상세 분석
- 총 이벤트: {detailed_analysis['event_count']}건
- 고유 사용자: {detailed_analysis['unique_users']}명
- 고유 IP: {detailed_analysis['unique_ips']}개

주요 발견사항
"""
        
        # 주요 발견사항 추가
        if detailed_analysis['user_analysis']['escalation_detected']:
            report += "- 권한 확장 시도 감지\n"
        
        if detailed_analysis['time_analysis']['burst_detected']:
            report += "- 버스트 패턴 공격 감지\n"
        
        if detailed_analysis['ip_analysis']['lateral_movement_detected']:
            report += "- 네트워크 측면 이동 감지\n"
        
        if detailed_analysis['file_analysis']['high_risk_files']:
            report += f"- 고위험 파일 {len(detailed_analysis['file_analysis']['high_risk_files'])}개 접근\n"
        
        return report
    
    @staticmethod
    def generate_incident_timeline(events: List[SecurityEvent]) -> str:
        """사건 타임라인 생성"""
        timeline = "\n=== 사건 타임라인 ===\n"
        
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        for i, event in enumerate(sorted_events, 1):
            timeline += f"{i}. {event.timestamp.strftime('%H:%M:%S')} - "
            timeline += f"{event.event_type.value.upper()}: {event.message}\n"
            timeline += f"   IP: {event.src_ip} → {event.dst_ip}\n"
            if event.entities.get('users'):
                timeline += f"   사용자: {', '.join(event.entities['users'])}\n"
            if event.entities.get('files'):
                timeline += f"   파일: {', '.join(event.entities['files'])}\n"
            timeline += "\n"
        
        return timeline