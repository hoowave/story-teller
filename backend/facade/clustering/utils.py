# utils.py (validate 강화 부분만 교체하면 됨)

import json
from typing import List, Dict, Any
from datetime import datetime
import ipaddress
from facade.log_clustering.models import SecurityEvent, ClusterMetrics

class LogProcessor:
    @staticmethod
    def load_json_logs(file_path: str) -> List[Dict[str, Any]]:
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
    def validate_event_data(event_data: Dict[str, Any]) -> bool:
        required = ['event_id','ts','src_ip','dst_ip','msg','event_type_hint','severity_hint','entities']
        for k in required:
            if k not in event_data:
                print(f"필수 필드 누락: {k}")
                return False
        # 시간
        try:
            ts = datetime.fromisoformat(event_data['ts'].replace('+09:00',''))
            if ts > datetime.now():
                print(f"미래 시각 이벤트 제외: {event_data['ts']}")
                return False
        except ValueError:
            print(f"잘못된 시간 형식: {event_data['ts']}")
            return False
        # IP
        for ipk in ['src_ip','dst_ip']:
            try:
                ipaddress.IPv4Address(event_data[ipk])
            except:
                print(f"잘못된 IP 형식 {ipk}: {event_data[ipk]}")
                return False
        # 엔티티 최소 구조
        ents = event_data.get('entities') or {}
        if not isinstance(ents, dict):
            print("entities 형식 오류")
            return False
        for key in ['ips','users','files','processes','domains']:
            if key not in ents:
                ents[key] = []
        return True
