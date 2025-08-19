# security_log_analyzer/main.py
"""메인 실행 모듈"""
from datetime import datetime
from typing import List, Dict, Any
import json
from models import LogEntry, LogIngestion, AttackCluster, Classification, EntityModel
from attack_classifier import HybridClassifier
from event_clustering import EventClusterer

class SecurityLogAnalyzer:
    """보안 로그 분석 시스템 메인 클래스"""
    
    def __init__(self):
        self.classifier = HybridClassifier()
        self.clusterer = EventClusterer(time_window_seconds=60)
        
    def analyze_ingestion(self, ingestion_data: Dict[str, Any]) -> Dict[str, Any]:
        """LogIngestion 형식의 데이터 분석"""
        # Pydantic 모델로 변환
        ingestion = LogIngestion(**ingestion_data)
        
        print("=" * 60)
        print(f"보안 로그 분석 시작 - Ingestion ID: {ingestion.ingest_id}")
        print(f"총 {ingestion.count}개 로그 분석")
        print("=" * 60)
        
        # 로그 분석
        classifications, clusters = self.analyze(ingestion.sample)
        
        # 결과를 JSON 형식으로 반환
        return {
            "ingest_id": ingestion.ingest_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_events": ingestion.count,
            "classifications": [self._classification_to_dict(c) for c in classifications],
            "clusters": [self._cluster_to_dict(c) for c in clusters],
            "summary": self._generate_summary(classifications, clusters)
        }
        
    def analyze(self, logs: List[LogEntry]) -> tuple[List[Classification], List[AttackCluster]]:
        """로그 분석 수행"""
        # 1. 공격 분류
        print("\n[1단계] 공격 분류 진행중...")
        classifications = []
        for log in logs:
            classification = self.classifier.classify(log)
            classifications.append(classification)
            print(f"  - {log.event_id[:8]}...: {classification.hybrid_result['primary_category']}")
        
        # 2. 이벤트 클러스터링
        print("\n[2단계] 이벤트 클러스터링 진행중...")
        clusters = self.clusterer.cluster_events(logs, classifications)
        for cluster in clusters:
            print(f"  - {cluster.cluster_id}: {cluster.cluster_type} ({len(cluster.related_events)} events)")
        
        return classifications, clusters
    
    def _classification_to_dict(self, classification: Classification) -> Dict[str, Any]:
        """Classification 객체를 딕셔너리로 변환"""
        return {
            "event_id": classification.event_id,
            "rule_based": classification.rule_based,
            "ai_based": classification.ai_based,
            "hybrid_result": classification.hybrid_result
        }
    
    def _cluster_to_dict(self, cluster: AttackCluster) -> Dict[str, Any]:
        """AttackCluster 객체를 딕셔너리로 변환"""
        return {
            "cluster_id": cluster.cluster_id,
            "cluster_type": cluster.cluster_type,
            "time_window": cluster.time_window,
            "related_events": cluster.related_events,
            "pattern_analysis": cluster.pattern_analysis,
            "cluster_confidence": cluster.cluster_confidence
        }
    
    def _generate_summary(self, classifications: List[Classification], clusters: List[AttackCluster]) -> Dict[str, Any]:
        """분석 결과 요약 생성"""
        # 공격 유형별 통계
        attack_type_counts = {}
        for cls in classifications:
            for attack_type in cls.hybrid_result.get('final_attack_types', []):
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        
        # 클러스터 유형별 통계
        cluster_type_counts = {}
        for cluster in clusters:
            cluster_type_counts[cluster.cluster_type] = cluster_type_counts.get(cluster.cluster_type, 0) + 1
        
        # 위험도 계산
        high_risk_clusters = [c for c in clusters if c.cluster_confidence > 0.8]
        
        return {
            "attack_types_detected": list(attack_type_counts.keys()),
            "attack_type_distribution": attack_type_counts,
            "cluster_types": list(cluster_type_counts.keys()),
            "cluster_distribution": cluster_type_counts,
            "high_risk_clusters": len(high_risk_clusters),
            "total_clusters": len(clusters),
            "risk_level": self._determine_risk_level(clusters)
        }
    
    def _determine_risk_level(self, clusters: List[AttackCluster]) -> str:
        """전체 위험도 레벨 결정"""
        if not clusters:
            return "LOW"
        
        max_confidence = max(c.cluster_confidence for c in clusters)
        critical_types = ['brute_force_sequence', 'post_compromise_activity', 'privilege_escalation_attempt']
        has_critical = any(c.cluster_type in critical_types for c in clusters)
        
        if max_confidence > 0.9 and has_critical:
            return "CRITICAL"
        elif max_confidence > 0.7 or has_critical:
            return "HIGH"
        elif max_confidence > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def print_results(self, classifications: List[Classification], clusters: List[AttackCluster]):
        """결과 출력"""
        print("\n" + "=" * 60)
        print("분석 결과")
        print("=" * 60)
        
        # 분류 결과 출력
        print("\n### 공격 분류 결과 ###")
        for cls in classifications:
            print(f"\n이벤트 ID: {cls.event_id[:8]}...")
            print(f"  규칙 기반: {cls.rule_based['attack_types']}")
            print(f"  AI 기반: {cls.ai_based['attack_types']}")
            print(f"  최종 분류: {cls.hybrid_result['final_attack_types']}")
            print(f"  카테고리: {cls.hybrid_result['primary_category']}")
            print(f"  신뢰도: {cls.hybrid_result['combined_confidence']}")
        
        # 클러스터 결과 출력
        print("\n### 클러스터링 결과 ###")
        for cluster in clusters:
            print(f"\n클러스터 ID: {cluster.cluster_id}")
            print(f"  타입: {cluster.cluster_type}")
            print(f"  시간 윈도우: {cluster.time_window['duration_seconds']}초")
            print(f"  관련 이벤트: {len(cluster.related_events)}개")
            print(f"  공격 진행: {cluster.pattern_analysis['attack_progression']}")
            print(f"  공통 엔티티: {cluster.pattern_analysis['common_entities']}")
            print(f"  권한 상승 감지: {cluster.pattern_analysis['escalation_detected']}")
            print(f"  심각도 분포: {cluster.pattern_analysis.get('severity_distribution', {})}")
            print(f"  클러스터 신뢰도: {cluster.cluster_confidence}")

# 샘플 데이터 생성 함수
def create_sample_ingestion() -> Dict[str, Any]:
    """제공된 형식의 샘플 데이터 생성"""
    return {
        "ingest_id": "sample-ingest-001",
        "format": "text",
        "count": 7,
        "sample": [
            {
                "event_id": "evt-001",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:30:45+09:00",
                "msg": "2023-08-18 10:30:45 Failed login for user: admin from 192.168.1.100",
                "entities": {
                    "ips": ["192.168.1.100"],
                    "users": ["admin"],
                    "files": [],
                    "processes": []
                },
                "event_type_hint": "authentication",
                "severity_hint": "warning",
                "parsing_confidence": 0.9,
                "raw": "2023-08-18 10:30:45 Failed login for user: admin from 192.168.1.100"
            },
            {
                "event_id": "evt-002",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:30:47+09:00",
                "msg": "2023-08-18 10:30:47 Failed login for user: admin from 192.168.1.100",
                "entities": {
                    "ips": ["192.168.1.100"],
                    "users": ["admin"],
                    "files": [],
                    "processes": []
                },
                "event_type_hint": "authentication",
                "severity_hint": "warning",
                "parsing_confidence": 0.9,
                "raw": "2023-08-18 10:30:47 Failed login for user: admin from 192.168.1.100"
            },
            {
                "event_id": "evt-003",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:31:22+09:00",
                "msg": "2023-08-18 10:31:22 Successful login for user: admin from 192.168.1.100",
                "entities": {
                    "ips": ["192.168.1.100"],
                    "users": ["admin"],
                    "files": [],
                    "processes": []
                },
                "event_type_hint": "authentication",
                "severity_hint": "info",
                "parsing_confidence": 0.95,
                "raw": "2023-08-18 10:31:22 Successful login for user: admin from 192.168.1.100"
            },
            {
                "event_id": "evt-004",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:31:35+09:00",
                "msg": "2023-08-18 10:31:35 User admin accessed sensitive file: /etc/passwd",
                "entities": {
                    "ips": [],
                    "users": ["admin"],
                    "files": ["/etc/passwd"],
                    "processes": []
                },
                "event_type_hint": "file_access",
                "severity_hint": "warning",
                "parsing_confidence": 0.9,
                "raw": "2023-08-18 10:31:35 User admin accessed sensitive file: /etc/passwd"
            },
            {
                "event_id": "evt-005",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:31:50+09:00",
                "msg": "2023-08-18 10:31:50 User admin accessed sensitive file: /etc/shadow",
                "entities": {
                    "ips": [],
                    "users": ["admin"],
                    "files": ["/etc/shadow"],
                    "processes": []
                },
                "event_type_hint": "file_access",
                "severity_hint": "critical",
                "parsing_confidence": 0.92,
                "raw": "2023-08-18 10:31:50 User admin accessed sensitive file: /etc/shadow"
            },
            {
                "event_id": "evt-006",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:32:10+09:00",
                "msg": "2023-08-18 10:32:10 Process executed: nc.exe by user admin",
                "entities": {
                    "ips": [],
                    "users": ["admin"],
                    "files": [],
                    "processes": ["nc.exe"]
                },
                "event_type_hint": "process_execution",
                "severity_hint": "critical",
                "parsing_confidence": 0.88,
                "raw": "2023-08-18 10:32:10 Process executed: nc.exe by user admin"
            },
            {
                "event_id": "evt-007",
                "ingest_id": "sample-ingest-001",
                "ts": "2023-08-18T10:32:25+09:00",
                "msg": "2023-08-18 10:32:25 Large data transfer detected to 10.0.0.100",
                "entities": {
                    "ips": ["10.0.0.100"],
                    "users": [],
                    "files": [],
                    "processes": []
                },
                "event_type_hint": "network",
                "severity_hint": "high",
                "parsing_confidence": 0.85,
                "raw": "2023-08-18 10:32:25 Large data transfer detected to 10.0.0.100"
            }
        ]
    }

# FastAPI 연동을 위한 API 엔드포인트 예제
def create_api_response(ingestion_data: Dict[str, Any]) -> Dict[str, Any]:
    """API 응답 형식으로 분석 결과 반환"""
    analyzer = SecurityLogAnalyzer()
    result = analyzer.analyze_ingestion(ingestion_data)
    
    # API 응답 형식
    return {
        "status": "success",
        "data": result,
        "metadata": {
            "analyzer_version": "1.0.0",
            "timestamp": datetime.now().isoformat()
        }
    }

# 실행 예제
if __name__ == "__main__":
    # 샘플 데이터 생성
    sample_data = create_sample_ingestion()
    
    # 분석기 실행
    analyzer = SecurityLogAnalyzer()
    
    # JSON 형식으로 분석
    result = analyzer.analyze_ingestion(sample_data)
    
    # 결과를 보기 좋게 출력
    print("\n" + "=" * 60)
    print("JSON 형식 분석 결과")
    print("=" * 60)
    print(json.dumps(result, indent=2, default=str))
    
    # 추가로 상세 결과도 출력
    ingestion = LogIngestion(**sample_data)
    classifications, clusters = analyzer.analyze(ingestion.sample)
    analyzer.print_results(classifications, clusters)