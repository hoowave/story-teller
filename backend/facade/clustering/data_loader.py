# ================================

# data_loader.py
"""데이터 로더 모듈 - 외부 데이터 소스 처리"""
import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from facade.clustering.models import SecurityEvent
from facade.clustering.utils import LogProcessor

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
        project_root = Path(__file__).parent.parent
        json_path = project_root / "data" / "processor_output.json"
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"JSON 파일을 찾을 수 없습니다: {json_path}")
        
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        events_data = data.get("events", [])
        
        events = []
        for event_data in events_data:
            try:
                event = SecurityEvent.from_dict(event_data)
                events.append(event)
            except Exception as e:
                print(f"이벤트 변환 실패: {e}\n데이터: {event_data}")

        return events