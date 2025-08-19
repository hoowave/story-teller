# security_log_analyzer/main.py
"""메인 실행 모듈"""
from datetime import datetime
from typing import List, Dict, Any, Tuple
import json
from models import LogEntry, LogIngestion, AttackCluster, Classification, EntityModel
from attack_classifier import HybridClassifier
from event_clustering import EventClusterer
from _anomaly_fix import StatisticalAnomalyDetector

class SecurityLogAnalyzer:
    """보안 로그 분석 시스템 메인 클래스"""
    
    def __init__(self):
        self.classifier = HybridClassifier()
        self.clusterer = EventClusterer(time_window_seconds=60)
        self.anomaly_detector = StatisticalAnomalyDetector()
        
    def analyze_ingestion(self, ingestion_data: Dict[str, Any]) -> Dict[str, Any]:
        """LogIngestion 형식의 데이터 분석"""
        try:
            ingestion = LogIngestion(**ingestion_data)
        except Exception as e:
            return {"status": "error", "message": f"Invalid input format: {e}"}

        print("=" * 60)
        print(f"보안 로그 분석 시작 - Ingestion ID: {ingestion.ingest_id}")
        print(f"총 {ingestion.count}개 로그 분석")
        print("=" * 60)
        
        analysis_results = self.analyze(ingestion.sample)
        
        return {
            "ingest_id": ingestion.ingest_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_events": ingestion.count,
            "classifications": [self._classification_to_dict(c) for c in analysis_results['classifications']],
            "clusters": [self._cluster_to_dict(c) for c in analysis_results['clusters']],
            "anomaly_results": analysis_results['anomaly_results']
        }
    
    def analyze(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """로그 리스트 분석 (내부 함수)"""
        classifications: List[Classification] = []
        anomaly_results: List[Dict[str, Any]] = []

        for log_entry in logs:
            anomaly_result = self.anomaly_detector.detect_anomalies(log_entry.model_dump())
            anomaly_results.append(anomaly_result)
            
            classification = self.classifier.predict(log_entry)
            classifications.append(classification)
        
        clusters = self.clusterer.cluster_events(logs, classifications)
        
        return {
            "classifications": classifications,
            "clusters": clusters,
            "anomaly_results": anomaly_results
        }
        
    def _classification_to_dict(self, c: Classification) -> Dict[str, Any]:
        return c.model_dump(by_alias=True)
    
    def _cluster_to_dict(self, c: AttackCluster) -> Dict[str, Any]:
        return c.model_dump(by_alias=True)

if __name__ == "__main__":
    sample_data = {
        "ingest_id": "ingest-001",
        "count": 5,
        "format": "json",
        "sample": [
            {
                "event_id": "e1",
                "ingest_id": "ingest-001",
                "ts": "2023-10-27T10:00:00Z",
                "bytes_in": 120,
                "bytes_out": 340,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 443,
                "event_type_hint": "network",
                "severity_hint": "info",
                "parsing_confidence": 0.9,
                "msg": "SSH login attempt from 192.168.1.10",
                "raw": "SSH login attempt from 192.168.1.10",
                "entities": {
                    "ips": ["192.168.1.10", "192.168.1.1"],
                    "users": ["admin"],
                    "files": []
                }
            },
            {
                "event_id": "e2",
                "ingest_id": "ingest-001",
                "ts": "2023-10-27T10:00:01Z",
                "bytes_in": 1500,
                "bytes_out": 25000,
                "src_ip": "192.168.1.11",
                "dst_ip": "192.168.1.2",
                "src_port": 54322,
                "dst_port": 80,
                "event_type_hint": "network",
                "severity_hint": "info",
                "parsing_confidence": 0.9,
                "msg": "HTTP request to retrieve a large file",
                "raw": "HTTP request to retrieve a large file",
                "entities": {
                    "ips": ["192.168.1.11", "192.168.1.2"],
                    "users": ["guest"],
                    "files": ["/data/big_file.zip"]
                }
            },
            {
                "event_id": "e3",
                "ingest_id": "ingest-001",
                "ts": "2023-10-27T10:00:02Z",
                "bytes_in": 100,
                "bytes_out": 200,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "src_port": 54323,
                "dst_port": 443,
                "event_type_hint": "network",
                "severity_hint": "warning",
                "parsing_confidence": 0.9,
                "msg": "Failed SSH login attempt from 192.168.1.10",
                "raw": "Failed SSH login attempt from 192.168.1.10",
                "entities": {
                    "ips": ["192.168.1.10", "192.168.1.1"],
                    "users": ["admin"],
                    "files": []
                }
            },
            {
                "event_id": "e4",
                "ingest_id": "ingest-001",
                "ts": "2023-10-27T10:00:03Z",
                "bytes_in": 1000,
                "bytes_out": 2000,
                "src_ip": "192.168.1.12",
                "dst_ip": "192.168.1.3",
                "src_port": 54324,
                "dst_port": 22,
                "event_type_hint": "network",
                "severity_hint": "info",
                "parsing_confidence": 0.9,
                "msg": "SSH successful login",
                "raw": "SSH successful login",
                "entities": {
                    "ips": ["192.168.1.12", "192.168.1.3"],
                    "users": ["devops"],
                    "files": []
                }
            },
            {
                "event_id": "e5",
                "ingest_id": "ingest-001",
                "ts": "2023-10-27T10:00:04Z",
                "bytes_in": 10000,
                "bytes_out": 500000,
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.4",
                "src_port": 54325,
                "dst_port": 80,
                "event_type_hint": "network",
                "severity_hint": "critical",
                "parsing_confidence": 0.9,
                "msg": "Large file download from web server",
                "raw": "Large file download from web server",
                "entities": {
                    "ips": ["192.168.1.10", "192.168.1.4"],
                    "users": ["admin"],
                    "files": ["/public/report.pdf", "/public/presentation.pptx"]
                }
            }
        ]
    }
    
    analyzer = SecurityLogAnalyzer()
    
    result = analyzer.analyze_ingestion(sample_data)
    
    with open('analysis_result.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
        
    print("\n" + "=" * 60)
    print("분석 완료. 'analysis_result.json' 파일에 결과가 저장되었습니다.")
    print("=" * 60)