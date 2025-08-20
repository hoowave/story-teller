# main.py




# ================================


import json
from typing import List, Dict, Any
from models import SecurityEvent
from cluster_analyzer import ClusterAnalyzer
from data_loader import DataLoader


def main():
    """메인 실행 함수"""
    print("=== 보안 로그 클러스터링 분석 시스템 ===")
    print()
    
    # 샘플 데이터 로드
    loader = DataLoader()
    events = loader.load_sample_data()
    

    # 클러스터 분석기 초기화
    cluster_analyzer = ClusterAnalyzer()
    
    # 기본 클러스터 분석
    print("클러스터 분석 결과:")
    print("-" * 50)
    metrics = cluster_analyzer.analyze_cluster(events)
    
    print(f"시간 집중도: {metrics.time_concentration:.3f}")
    print(f"IP 다각화: {metrics.ip_diversification:.3f}")
    print(f"사용자 이상행동: {metrics.user_anomaly:.3f}")
    print(f"파일 민감도: {metrics.file_sensitivity:.3f}")
    print(f"종합 위험도: {metrics.overall_risk_score:.3f}")
    print(f"공격 시나리오: {metrics.attack_scenario}")
    print(f"우선순위: {metrics.priority_level.value.upper()}")
    
    print()
    print("=" * 60)
    print()
    
    # 상세 분석
    print("상세 분석 결과:")
    print("-" * 50)
    detailed_analysis = cluster_analyzer.get_detailed_analysis(events)
    
    # 시간 분석
    time_analysis = detailed_analysis["time_analysis"]
    print(f"버스트 패턴 감지: {time_analysis['burst_detected']}")
    print(f"버스트 강도: {time_analysis['burst_intensity']:.3f}")
    print(f"총 지속시간: {time_analysis['total_duration']:.1f}초")
    
    # IP 분석
    ip_analysis = detailed_analysis["ip_analysis"]
    print(f"외부→내부 이동: {ip_analysis['external_to_internal']}건")
    print(f"내부→내부 이동: {ip_analysis['internal_to_internal']}건")
    print(f"측면 이동 감지: {ip_analysis['lateral_movement_detected']}")
    
    # 사용자 분석
    user_analysis = detailed_analysis["user_analysis"]
    print(f"권한 확장 감지: {user_analysis['escalation_detected']}")
    print(f"위험 레벨: {user_analysis['risk_level']}")
    if user_analysis['escalation_indicators']:
        print(f"확장 지표: {', '.join(user_analysis['escalation_indicators'])}")
    
    # 파일 분석
    file_analysis = detailed_analysis["file_analysis"]
    print(f"데이터 유출 위험: {file_analysis['exfiltration_risk_score']:.3f}")
    print(f"총 파일 접근: {file_analysis['total_file_accesses']}건")
    if file_analysis['high_risk_files']:
        print("고위험 파일:")
        for file_info in file_analysis['high_risk_files']:
            print(f"   - {file_info['file']} (민감도: {file_info['sensitivity']:.2f}, 사용자: {file_info['user']})")
    
    # 전체 통계
    print()
    print("전체 통계:")
    print(f"   - 총 이벤트: {detailed_analysis['event_count']}건")
    print(f"   - 고유 사용자: {detailed_analysis['unique_users']}명")
    print(f"   - 고유 IP: {detailed_analysis['unique_ips']}개")
    
    print()
    print("=" * 60)
    print()
    
    print("분석 완료!")
    
    # JSON 형태로 결과 출력 (API 응답 시뮬레이션)
    print()
    print("JSON 응답 형태:")
    print("-" * 50)
    
    result_json = {
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
            "recommendations": generate_recommendations(metrics)
        },
        "timestamp": "2023-01-01T12:02:00Z",
        "analysis_version": "1.0.0"
    }
    
    print(json.dumps(result_json, indent=2, ensure_ascii=False, default=str))



def generate_recommendations(metrics):
    """위험도에 따른 권장사항 생성"""
    from models import ClusterMetrics
    
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

if __name__ == "__main__":
    main()