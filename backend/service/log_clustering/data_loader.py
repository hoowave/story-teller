# ================================

# data_loader.py
"""데이터 로더 모듈 - 외부 데이터 소스 처리"""
import json
from typing import List, Dict, Any, Optional
from models import SecurityEvent
from utils import LogProcessor

class DataLoader:
    """다양한 소스에서 보안 로그 데이터를 로드하는 클래스"""
    
    def __init__(self):
        self.log_processor = LogProcessor()
    
    def load_from_json_file(self, file_path: str) -> List[SecurityEvent]:
        """JSON 파일에서 보안 이벤트 로드"""
        raw_events = self.log_processor.load_json_logs(file_path)
        events = []
        
        for event_data in raw_events:
            if self.log_processor.validate_event_data(event_data):
                try:
                    event = SecurityEvent.from_dict(event_data)
                    events.append(event)
                except Exception as e:
                    print(f"이벤트 변환 실패: {e}")
                    continue
        
        return events
    
    def load_from_json_string(self, json_string: str) -> List[SecurityEvent]:
        """JSON 문자열에서 보안 이벤트 로드"""
        try:
            data = json.loads(json_string)
            raw_events = data.get('events', [])
            events = []
            
            for event_data in raw_events:
                if self.log_processor.validate_event_data(event_data):
                    try:
                        event = SecurityEvent.from_dict(event_data)
                        events.append(event)
                    except Exception as e:
                        print(f"이벤트 변환 실패: {e}")
                        continue
            
            return events
        except json.JSONDecodeError as e:
            print(f"JSON 파싱 오류: {e}")
            return []
    
    def load_sample_data(self) -> List[SecurityEvent]:
        """샘플 데이터 로드"""
        sample_data = {
            "events": [
                {
                    "event_id": "550e8400-e29b-41d4-a716-446655440000",
                    "ingest_id": "550e8400-e29b-41d4-a716-446655440000",
                    "ts": "2023-01-01T12:00:00+09:00",
                    "source_type": "auth",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "msg": "User admin logged in from 192.168.1.1",
                    "event_type_hint": "authentication",
                    "severity_hint": "info",
                    "entities": {
                        "ips": ["192.168.1.1", "10.0.0.1"],
                        "users": ["admin"],
                        "files": [],
                        "processes": [],
                        "domains": []
                    },
                    "raw": "2023-01-01T12:00:00,192.168.1.1,10.0.0.1,User admin logged in from 192.168.1.1",
                    "meta": {},
                    "parsing_confidence": 0.8
                },
                {
                    "event_id": "550e8400-e29b-41d4-a716-446655440001",
                    "ingest_id": "550e8400-e29b-41d4-a716-446655440000",
                    "ts": "2023-01-01T12:01:00+09:00",
                    "source_type": "text",
                    "src_ip": "192.168.1.2",
                    "dst_ip": "10.0.0.2",
                    "msg": "File access: /var/log/access.log by user:johndoe",
                    "event_type_hint": "file_access",
                    "severity_hint": "info",
                    "entities": {
                        "ips": ["192.168.1.2", "10.0.0.2"],
                        "users": ["johndoe"],
                        "files": ["/var/log/access.log"],
                        "processes": [],
                        "domains": []
                    },
                    "raw": "2023-01-01T12:01:00,192.168.1.2,10.0.0.2,File access: /var/log/access.log by user:johndoe",
                    "meta": {},
                    "parsing_confidence": 0.8
                }
            ]
        }
        
        events = []
        for event_data in sample_data["events"]:
            try:
                event = SecurityEvent.from_dict(event_data)
                events.append(event)
            except Exception as e:
                print(f"샘플 데이터 변환 실패: {e}")
        
        return events
