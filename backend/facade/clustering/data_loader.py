# data_loader.py
import json
import hashlib
import re
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any
from facade.clustering.models import SecurityEvent
from facade.clustering.utils import LogProcessor

UNIT_FACTORS = {
    "b": 1,
    "kb": 1024,
    "mb": 1024**2,
    "gb": 1024**3,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    # 종종 대문자/혼합 표기
}

def _parse_size_to_bytes(text: str) -> int:
    """'155,785', '150MB', '1.2 GiB', '73400320' 등 → Bytes 정규화"""
    if not text:
        return 0
    s = str(text).strip()
    # 숫자만 있을 땐 bytes로 간주
    m = re.fullmatch(r"\s*([0-9][0-9,\.]*)\s*\Z", s)
    if m:
        try:
            return int(m.group(1).replace(",", ""))
        except:
            pass
    # 숫자 + 단위
    m = re.search(r"([0-9][0-9,\.]*)\s*([A-Za-z]{1,3})", s)
    if not m:
        return 0
    num = m.group(1).replace(",", "")
    unit = m.group(2).lower()
    try:
        val = float(num)
    except:
        return 0
    # 통일
    unit = {"k":"kb","m":"mb","g":"gb"}.get(unit, unit)
    factor = UNIT_FACTORS.get(unit, 1)
    return int(val * factor)

def _choose_dst_ip(ed: dict) -> str:
    """dst_ip가 없을 때 entities/meta에서 백필. 못 찾으면 0.0.0.0."""
    dst = (ed.get("dst_ip") or "").strip()
    if dst:
        return dst
    src = ed.get("src_ip")
    ents = ed.get("entities") or {}
    for cand in (ents.get("ips") or []):
        try:
            ipaddress.IPv4Address(cand)
            if cand and cand != src:
                return cand
        except:
            pass
    meta = ed.get("meta") or {}
    for k in ["Dst","Destination","dst","dst_ip","server","host_ip","PC"]:
        cand = (meta.get(k) or "").strip()
        try:
            ipaddress.IPv4Address(cand)
            if cand and cand != src:
                return cand
        except:
            pass
    return "0.0.0.0"

class DataLoader:
    """다양한 소스에서 보안 로그 데이터를 로드하는 클래스"""

    def __init__(self, config=None):
        self.log_processor = LogProcessor()
        self.config = config  # 필요시 사용

    def _mk_session_id(self, src_ip: str, user: str, ts: datetime, window_min: int = 30) -> str:
        bucket = int(ts.timestamp() // (window_min * 60))
        raw = f"{src_ip}|{user}|{bucket}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _normalize_event_dict(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        ed = dict(event_data)

        # 1) event_type_hint 보정
        hint = (ed.get("event_type_hint") or "").lower()
        src  = (ed.get("source_type") or "").lower()
        if not hint or hint == "unknown":
            if src in ("waf","web"):              ed["event_type_hint"] = "web_attack"
            elif src in ("db","database"):        ed["event_type_hint"] = "db_access"
            elif src in ("proxy","fw","egress"):  ed["event_type_hint"] = "data_transfer"
            elif src in ("auth","authentication"):ed["event_type_hint"] = "authentication"
            else:                                 ed["event_type_hint"] = "system_access"

        # 2) entities 기본 키/확장
        ents = ed.get("entities") or {}
        for k in ['ips','users','files','processes','domains']:
            ents.setdefault(k, [])
        for k in ["obj_name","row_count","bytes_out","status","asn","geo","ua","session_id","blocked"]:
            ents.setdefault(k, None)
        ed["entities"] = ents

        msg  = ed.get("msg")  or ""
        meta = ed.get("meta") or {}
        ehin = ed["event_type_hint"].lower()

        # 3) 목적지 IP 백필
        ed["dst_ip"] = _choose_dst_ip(ed)

        # 4) 유형별 파싱
        if ehin == "authentication":
            low = msg.lower()
            if   "accepted password" in low or "logged in" in low or "success" in low:
                ed["entities"]["status"] = "success"
            elif "failed password" in low or "invalid password" in low or "fail" in low:
                ed["entities"]["status"] = "fail"

        elif ehin == "db_access":
            # rows: "rows=15000" / meta 내 유사 키
            rows = 0
            m = re.search(r"rows\s*[:=]\s*([0-9,]+)", msg, re.I)
            if m: rows = int(m.group(1).replace(",",""))
            if not rows:
                for k in ("rows","RowCount","ROWCOUNT"):
                    v = meta.get(k)
                    try:
                        rows = int(str(v).replace(",",""))
                        break
                    except:
                        pass
            ed["entities"]["row_count"] = rows or ed["entities"]["row_count"]
            # obj_name: "from credentials"
            m = re.search(r"\bfrom\s+([A-Za-z0-9_\.]+)", msg, re.I)
            if m:
                ed["entities"]["obj_name"] = m.group(1)

        elif ehin == "data_transfer":
            # bytes_out: 메시지/메타에 단위가 붙어도 파싱
            by = 0
            for cand in [msg, str(meta.get("Bytes") or ""), str(meta.get("Size") or ""), str(meta.get("Transferred") or "")]:
                by = _parse_size_to_bytes(cand)
                if by: break
            if by:
                ed["entities"]["bytes_out"] = by
            # 차단 여부: waf/firewall/proxy + block/deny 키워드
            if src in ("waf","firewall","proxy"):
                if re.search(r"\b(block|deny|blocked|denied)\b", (msg + " " + str(meta)).lower()):
                    ed["entities"]["blocked"] = True

        elif ehin == "web_attack":
            if re.search(r"\b(block|deny|blocked|denied)\b", (msg + " " + str(meta)).lower()):
                ed["entities"]["blocked"] = True

        # 5) session_id
        try:
            ts = datetime.fromisoformat(ed['ts'].replace("Z","+00:00")).astimezone(timezone.utc)
        except Exception:
            ts = datetime.fromisoformat(ed['ts'].replace('+09:00',''))
        user = (ents.get("users") or ["unknown"])[0]
        session_id = self._mk_session_id(ed.get("src_ip","0.0.0.0"), user, ts, 30)
        ed.setdefault("session_id", session_id)
        ed["entities"]["session_id"] = session_id

        return ed

    # -------- Loaders --------
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
        return []
