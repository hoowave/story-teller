# main.py
import json
import sys
from typing import List, Dict, Any
from facade.clustering.models import SecurityEvent
from facade.clustering.cluster_analyzer import ClusterAnalyzer
from facade.clustering.data_loader import DataLoader

def main():
    print("=== 보안 로그 클러스터링 분석 시스템 ===\n")

    loader = DataLoader()

    # 사용법: python main.py /path/to/log.json
    events: List[SecurityEvent]
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
        print(f"[입력] {log_path} 에서 로그 로드")
        events = loader.load_from_json_file(log_path)
    else:
        print("[경고] 입력 파일이 지정되지 않아 샘플 데이터로 실행합니다.")
        events = loader.load_sample_data()

    cluster_analyzer = ClusterAnalyzer()
    metrics = cluster_analyzer.analyze_cluster(events)

    print("클러스터 분석 결과:")
    print("-" * 50)
    print(f"시간 집중도: {metrics.time_concentration:.3f}")
    print(f"IP 다각화: {metrics.ip_diversification:.3f}")
    print(f"사용자 이상행동: {metrics.user_anomaly:.3f}")
    print(f"파일 민감도: {metrics.file_sensitivity:.3f}")
    print(f"종합 위험도: {metrics.overall_risk_score:.3f}")
    print(f"공격 시나리오: {metrics.attack_scenario}")
    print(f"우선순위: {metrics.priority_level.value.upper()}\n")
    print("=" * 60 + "\n")

    detailed = cluster_analyzer.get_detailed_analysis(events)
    print("상세 분석 결과:")
    print("-" * 50)
    time_analysis = detailed["time_analysis"]
    ip_analysis = detailed["ip_analysis"]
    user_analysis = detailed["user_analysis"]
    file_analysis = detailed["file_analysis"]
    print(f"버스트 패턴 감지: {time_analysis.get('burst_detected', False)}")
    print(f"버스트 강도: {time_analysis.get('burst_intensity', 0.0):.3f}")
    print(f"외부→내부 이동: {ip_analysis.get('external_to_internal', 0)}건")
    print(f"내부→내부 이동: {ip_analysis.get('internal_to_internal', 0)}건")
    print(f"측면 이동 감지: {ip_analysis.get('lateral_movement_detected', False)}")
    print(f"권한 확장 감지: {user_analysis.get('escalation_detected', False)} (레벨: {user_analysis.get('risk_level', 'LOW')})")
    print(f"데이터 유출 위험: {file_analysis.get('exfiltration_risk_score', 0.0):.3f}")
    print(f"총 파일 접근: {file_analysis.get('total_file_accesses', 0)}건\n")

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
            "detailed_analysis": detailed,
        }
    }
    print("JSON 응답 형태:")
    print("-" * 50)
    print(json.dumps(result_json, indent=2, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()
