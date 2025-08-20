# utils.py
import json
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
import ipaddress

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
    def _parse_iso_aware(val: str) -> datetime:
        s = (val or "").strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone(timedelta(hours=9)))
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _coerce_ipv4(event_data: Dict[str, Any], key: str) -> None:
        val = event_data.get(key)
        try:
            ipaddress.IPv4Address(val)
        except Exception:
            # 누락/비정상 → 보정
            event_data[key] = "0.0.0.0"
            try:
                event_data["parsing_confidence"] = float(event_data.get("parsing_confidence", 1.0)) * 0.7
            except Exception:
                event_data["parsing_confidence"] = 0.7

    @staticmethod
    def validate_event_data(event_data: Dict[str, Any]) -> bool:
        required = ['event_id','ts','src_ip','dst_ip','msg','event_type_hint','severity_hint','entities']
        for k in required:
            if k not in event_data:
                print(f"필수 필드 누락: {k}")
                return False

        # 시간: TZ-aware로 표준화, 미래 이벤트 제외
        try:
            ts_utc = LogProcessor._parse_iso_aware(event_data['ts'])
            if ts_utc > datetime.now(timezone.utc):
                print(f"미래 시각 이벤트 제외: {event_data['ts']}")
                return False
            event_data['ts'] = ts_utc.isoformat()
        except Exception:
            print(f"잘못된 시간 형식: {event_data['ts']}")
            return False

        # IP: 드롭하지 말고 보정
        LogProcessor._coerce_ipv4(event_data, 'src_ip')
        LogProcessor._coerce_ipv4(event_data, 'dst_ip')

        # entities 최소 구조 보정
        ents = event_data.get('entities') or {}
        if not isinstance(ents, dict):
            print("entities 형식 오류")
            return False
        for key in ['ips','users','files','processes','domains']:
            ents.setdefault(key, [])
        event_data['entities'] = ents

        return True
