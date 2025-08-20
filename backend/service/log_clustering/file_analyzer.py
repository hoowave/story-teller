# ================================

# file_analyzer.py
from typing import List, Dict, Any
from models import SecurityEvent, EventType

class FileAnalyzer:
    """파일 접근 패턴 분석기"""
    
    def __init__(self):
        self.sensitive_files = {
            '/var/log/': 0.8,
            '/etc/': 0.9,
            '/root/': 1.0,
            '/home/': 0.6,
            'passwd': 1.0,
            'shadow': 1.0,
            '.config': 0.7
        }
    
    def calculate_file_sensitivity(self, events: List[SecurityEvent]) -> float:
        """파일 민감도 지수 계산"""
        if not events:
            return 0.0
        
        total_sensitivity = 0.0
        file_access_count = 0
        
        for event in events:
            if event.event_type == EventType.FILE_ACCESS:
                for file_path in event.entities.get('files', []):
                    file_access_count += 1
                    sensitivity = self._get_file_sensitivity(file_path)
                    total_sensitivity += sensitivity
        
        if file_access_count == 0:
            return 0.0
        
        return total_sensitivity / file_access_count
    
    def analyze_data_exfiltration_risk(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """데이터 유출 위험 분석"""
        high_risk_files = []
        access_patterns = []
        
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        
        for event in file_events:
            for file_path in event.entities.get('files', []):
                sensitivity = self._get_file_sensitivity(file_path)
                if sensitivity >= 0.7:
                    high_risk_files.append({
                        "file": file_path,
                        "sensitivity": sensitivity,
                        "timestamp": event.timestamp,
                        "user": event.entities.get('users', ['unknown'])[0] if event.entities.get('users') else 'unknown'
                    })
        
        # 접근 패턴 분석
        if len(file_events) > 1:
            access_patterns.append("다중 파일 접근")
        
        if high_risk_files:
            access_patterns.append("높은 민감도 파일 접근")
        
        exfiltration_risk = len(high_risk_files) * 0.3 + len(access_patterns) * 0.2
        
        return {
            "exfiltration_risk_score": min(1.0, exfiltration_risk),
            "high_risk_files": high_risk_files,
            "access_patterns": access_patterns,
            "total_file_accesses": len(file_events)
        }
    
    def _get_file_sensitivity(self, file_path: str) -> float:
        """파일 경로에 따른 민감도 반환"""
        for pattern, sensitivity in self.sensitive_files.items():
            if pattern in file_path.lower():
                return sensitivity
        return 0.3  # 기본 민감도