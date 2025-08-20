# ================================

# test_runner.py
"""테스트 실행 모듈"""
from api_service import SecurityAnalysisService

def run_tests():
    """전체 테스트 실행"""
    print("=== 보안 로그 분석 시스템 테스트 ===")
    print()
    
    # 서비스 초기화
    service = SecurityAnalysisService()
    
    # 샘플 데이터 분석 테스트
    print("샘플 데이터 분석 테스트...")
    result = service.analyze_sample_data()
    
    if result["success"]:
        analysis = result["analysis_result"]
        print("분석 성공!")
        print(f"종합 위험도: {analysis['metrics']['overall_risk_score']:.3f}")
        print(f"공격 시나리오: {analysis['attack_scenario']}")
        print(f"우선순위: {analysis['priority_level'].upper()}")
        print()
        
        print("상세 분석 결과:")
        detailed = analysis["detailed_analysis"]
        print(f"- 버스트 패턴: {detailed.get('time_analysis', {}).get('burst_detected', False)}")
        print(f"- 권한 확장: {detailed.get('user_analysis', {}).get('escalation_detected', False)}")
        print(f"- 측면 이동: {detailed.get('ip_analysis', {}).get('lateral_movement_detected', False)}")
        print()
        
        print("권장사항:")
        for i, rec in enumerate(analysis["recommendations"], 1):
            print(f"{i}. {rec}")
        
    else:
        print(f"분석 실패: {result['error']}")
    
    print()
    print("테스트 완료!")

if __name__ == "__main__":
    run_tests()