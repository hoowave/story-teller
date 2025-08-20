# data_loader.py
import json
import hashlib
from pathlib import Path
import os
from datetime import datetime, timezone
from typing import List, Dict, Any
from facade.log_clustering.models import SecurityEvent
from facade.log_clustering.utils import LogProcessor

class DataLoader:
    """다양한 소스에서 보안 로그 데이터를 로드하는 클래스"""

    def __init__(self, config=None):
        self.log_processor = LogProcessor()
        self.config = config  # 필요시 사용

    # (선택) 세션키: src_ip + user + 30분 버킷
    def _mk_session_id(self, src_ip: str, user: str, ts: datetime, window_min: int = 30) -> str:
        bucket = int(ts.timestamp() // (window_min * 60))
        raw = f"{src_ip}|{user}|{bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _normalize_event_dict(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        ed = dict(event_data)

        # 1) event_type_hint 보정 (없거나 unknown이면 source_type 기반으로 표준화)
        hint = (ed.get("event_type_hint") or "").lower()
        src = (ed.get("source_type") or "").lower()
        if not hint or hint == "unknown":
            if src in ("waf","web"):
                ed["event_type_hint"] = "web_attack"
            elif src in ("db","database"):
                ed["event_type_hint"] = "db_access"
            elif src in ("proxy","fw","egress"):
                ed["event_type_hint"] = "data_transfer"
            elif src in ("auth","authentication"):
                ed["event_type_hint"] = "authentication"
            else:
                ed["event_type_hint"] = "system_access"

        # 2) entities 키 보정 + 확장 필드 기본값
        ents = ed.get("entities") or {}
        for k in ['ips','users','files','processes','domains']:
            ents.setdefault(k, [])
        ents.setdefault("obj_name", None)
        ents.setdefault("row_count", None)
        ents.setdefault("bytes_out", None)
        ents.setdefault("status", None)
        ents.setdefault("asn", None)
        ents.setdefault("geo", None)
        ents.setdefault("ua", None)
        ed["entities"] = ents

        # 3) (선택) session_id 생성해서 entities에 넣어두면 이후 세션화에 도움
        try:
            ts = datetime.fromisoformat(ed['ts'].replace("Z","+00:00")).astimezone(timezone.utc)
        except Exception:
            ts = datetime.fromisoformat(ed['ts'].replace('+09:00',''))
        user = (ents.get("users") or ["unknown"])[0]
        session_id = self._mk_session_id(ed.get("src_ip","0.0.0.0"), user, ts, 30)
        ed.setdefault("session_id", session_id)
        ed["entities"]["session_id"] = session_id

        return ed

    def load_from_json_file(self, file_path: str) -> List[SecurityEvent]:
        raw_events = self.log_processor.load_json_logs(file_path)
        events: List[SecurityEvent] = []
        for event_data in raw_events:
            if self.log_processor.validate_event_data(event_data):
                try:
                    norm = self._normalize_event_dict(event_data)
                    events.append(SecurityEvent.from_dict(norm))
                except Exception as e:
                    print(f"이벤트 변환 실패: {e}")
                    continue
        return events

    def load_from_json_string(self, json_string: str) -> List[SecurityEvent]:
        try:
            data = json.loads(json_string)
            raw_events = data.get('events', [])
        except json.JSONDecodeError as e:
            print(f"JSON 파싱 오류: {e}")
            return []

        events: List[SecurityEvent] = []
        for event_data in raw_events:
            if self.log_processor.validate_event_data(event_data):
                try:
                    norm = self._normalize_event_dict(event_data)
                    events.append(SecurityEvent.from_dict(norm))
                except Exception as e:
                    print(f"이벤트 변환 실패: {e}")
                    continue
        return events

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