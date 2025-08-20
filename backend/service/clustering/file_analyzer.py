# file_analyzer.py
from typing import List, Dict, Any, Set, Tuple
from models import SecurityEvent, EventType
from config import DEFAULT_CONFIG

class FileAnalyzer:
    """파일/DB/유출 리스크 분석"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.sensitive_files = self.config.sensitive_files
        self.service_accounts = set(self.config.service_accounts)

    def calculate_file_sensitivity(self, events: List[SecurityEvent]) -> float:
        """민감 파일 평균 민감도 + 연속성 보정"""
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        if not file_events:
            return 0.0
        tot, cnt = 0.0, 0
        for e in file_events:
            for fp in e.entities.get('files', []) or []:
                cnt += 1
                tot += self._get_file_sensitivity(fp)
        base = (tot / cnt) if cnt else 0.0
        if self._has_sensitive_sequence(file_events):
            base = min(1.0, base + 0.15)
        return base

    def analyze_data_exfiltration_risk(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        file_events = [e for e in events if e.event_type == EventType.FILE_ACCESS]
        db_events   = [e for e in events if e.event_type == EventType.DB_ACCESS]
        egress      = [e for e in events if e.event_type == EventType.DATA_TRANSFER]

        patterns = []
        heavy_db = []

        # DB 대량 민감 오브젝트 접근
        for e in db_events:
            obj = (e.entities.get("obj_name") or "").lower()
            rows = int(e.entities.get("row_count") or 0)
            if rows >= self.config.db_row_threshold and any(tag in obj for tag in self.config.db_sensitive_names):
                heavy_db.append({"obj": obj, "rows": rows, "ts": e.timestamp})
        risk = 0.4 if heavy_db else 0.0
        if heavy_db: patterns.append("DB 대량 민감 오브젝트 접근")

        # 외부 유출 바이트 급증
        total_bytes_out = sum(int(e.entities.get("bytes_out") or 0) for e in egress)
        if total_bytes_out >= self.config.exfil_bytes_threshold:
            risk += 0.35
            patterns.append("외부로 대량 전송")

        # 민감 파일 연속 접근
        if self._has_sensitive_sequence(file_events):
            risk += 0.15
            patterns.append("민감 파일 연속 접근")

        # 정비창/서비스계정 감산
        if any(self._in_maintenance(e.timestamp.hour) for e in events):
            risk = max(0.0, risk - 0.15)
        if any(((e.entities.get('users') or [""])[0]) in self.service_accounts for e in events):
            risk = max(0.0, risk - 0.1)

        # 민감 파일 정보 수집
        high_risk_files = []
        for e in file_events:
            for fp in e.entities.get("files", []) or []:
                sens = self._get_file_sensitivity(fp)
                if sens >= 0.7:  # 민감도 높은 파일만 추림
                    high_risk_files.append({
                        "file": fp,
                        "sensitivity": sens,
                        "user": (e.entities.get("users") or ["?"])[0]
                    })

        return {
            "exfiltration_risk_score": min(1.0, risk),
            "access_patterns": patterns,
            "total_file_accesses": len(file_events),
            "db_heavy_objects": heavy_db,
            "total_bytes_out": total_bytes_out,
            "high_risk_files": high_risk_files
        }
        

    # --- 내부 유틸 ---

    def _get_file_sensitivity(self, file_path: str) -> float:
        low = (file_path or "").lower()
        for pattern, s in self.sensitive_files.items():
            if pattern in low:
                return s
        return 0.3

    def _has_sensitive_sequence(self, file_events: List[SecurityEvent], k: int = 2, window_sec: int = 180) -> bool:
        if len(file_events) < k: return False
        seq, last_ts = 0, None
        for e in sorted(file_events, key=lambda x: x.timestamp):
            if self._event_has_sensitive(e):
                if last_ts and (e.timestamp - last_ts).total_seconds() <= window_sec:
                    seq += 1
                else:
                    seq = 1
                last_ts = e.timestamp
                if seq >= k: return True
            else:
                seq, last_ts = 0, None
        return False

    def _event_has_sensitive(self, e: SecurityEvent) -> bool:
        for fp in e.entities.get('files', []) or []:
            if any(p in fp.lower() for p in self.sensitive_files.keys()):
                return True
        return False

    def _in_maintenance(self, hour: int) -> bool:
        return any(s <= hour < t for (s, t) in self.config.maintenance_windows)
