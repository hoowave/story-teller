# ip_analyzer.py
from typing import List, Dict, Any, Tuple, Set
import ipaddress, math
from collections import defaultdict
from facade.clustering.models import SecurityEvent, EventType
from facade.clustering.config import DEFAULT_CONFIG

def _valid_v4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False

class IPAnalyzer:
    """IP 기반 공격 패턴 분석기 + 네트워크 위협 축"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.internal_networks = [ipaddress.IPv4Network(n) for n in self.config.internal_networks]

    def _is_internal(self, ip_str: str) -> bool:
        if not _valid_v4(ip_str) or ip_str == "0.0.0.0":
            return False
        ip = ipaddress.IPv4Address(ip_str)
        return any(ip in net for net in self.internal_networks)

    def calculate_ip_diversification(self, events: List[SecurityEvent]) -> float:
        if not events: return 0.0
        all_ips, ext_ips = set(), set()
        for e in events:
            for ip in (e.src_ip, e.dst_ip):
                if not _valid_v4(ip) or ip == "0.0.0.0": continue
                all_ips.add(ip)
                if not self._is_internal(ip): ext_ips.add(ip)
        total_events = len(events)
        unique_all, unique_ext = len(all_ips), len(ext_ips)
        global_score = (math.log1p(unique_all) / math.log1p(total_events + 1)) if total_events else 0.0

        window_min = getattr(self.config, "ip_div_window_min", 15)
        buckets = defaultdict(list)
        for e in events:
            buckets[int(e.timestamp.timestamp() // (window_min * 60))].append(e)

        window_scores = []
        for _, evs in buckets.items():
            ext_set = set()
            for ev in evs:
                for ip in (ev.src_ip, ev.dst_ip):
                    if not _valid_v4(ip) or ip == "0.0.0.0": continue
                    if not self._is_internal(ip): ext_set.add(ip)
            cnt = len(evs)
            if cnt == 0: continue
            window_scores.append(math.log1p(len(ext_set)) / math.log1p(cnt + 1))
        window_score = sorted(window_scores)[int(0.75*(len(window_scores)-1))] if window_scores else 0.0
        external_ratio = (unique_ext/unique_all) if unique_all else 0.0
        return max(0.0, min(1.0, 0.5*global_score + 0.4*window_score + 0.1*external_ratio))

    def analyze_network_movement(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """같은 (src,dst) 반복 이벤트는 세션 버킷 단위로 1회만 카운트"""
        if not events:
            return {"external_to_internal":0,"internal_to_internal":0,"lateral_movement_detected":False,"network_penetration_depth":0}

        window_min = getattr(self.config, "sequence_window_min", 30)
        seen_extint: Set[Tuple[int,str,str]] = set()
        seen_intint: Set[Tuple[int,str,str]] = set()

        # 체인 탐지용
        by_time = sorted(events, key=lambda x: x.timestamp)
        last_dst = None
        chain = 0
        ext_int_seen_before_chain = False

        for e in by_time:
            if (not _valid_v4(e.src_ip)) or (not _valid_v4(e.dst_ip)) or e.src_ip == "0.0.0.0" or e.dst_ip == "0.0.0.0":
                continue
            bucket = int(e.timestamp.timestamp() // (window_min * 60))
            src_int = self._is_internal(e.src_ip)
            dst_int = self._is_internal(e.dst_ip)

            if (not src_int) and dst_int:
                key = (bucket, e.src_ip, e.dst_ip)
                if key not in seen_extint:
                    seen_extint.add(key)
                # 체인 리셋
                chain = 0
                last_dst = e.dst_ip

            elif src_int and dst_int:
                key = (bucket, e.src_ip, e.dst_ip)
                if key not in seen_intint:
                    seen_intint.add(key)
                if last_dst and e.src_ip == last_dst:
                    chain += 1
                    last_dst = e.dst_ip
                else:
                    chain = 1
                    last_dst = e.dst_ip
                if chain >= 2 and len(seen_extint) > 0:
                    ext_int_seen_before_chain = True

        ext_to_int = len(seen_extint)
        int_to_int = len(seen_intint)
        lateral = (chain >= 2) or ext_int_seen_before_chain
        depth = ext_to_int + int_to_int
        return {
            "external_to_internal": ext_to_int,
            "internal_to_internal": int_to_int,
            "lateral_movement_detected": lateral,
            "network_penetration_depth": depth
        }

    def calculate_network_threat(self, events: List[SecurityEvent]):
        """차단된 외부 전송/대용량 egress/C2 beacon 신호 결합"""
        blocked_egress = 0
        egress_bytes   = 0
        beacon_hits    = []
        for e in events:
            if e.event_type == EventType.DATA_TRANSFER:
                try:
                    egress_bytes += int(e.entities.get("bytes_out") or 0)
                except:
                    pass
                if (e.entities.get("blocked") is True) or ("block" in (e.message or "").lower()) or ("deny" in (e.message or "").lower()):
                    blocked_egress += 1
            if e.source_type.lower() in ("dns","edr","ids","nids"):
                low = (e.message or "").lower()
                if any(k in low for k in ("beacon","c2","callback","command-and-control")):
                    beacon_hits.append({"ts": e.timestamp, "src": e.src_ip})

        score = 0.0
        if blocked_egress > 0: score += 0.4
        if egress_bytes >= getattr(self.config, "exfil_bytes_threshold", 50*1024*1024): score += 0.3
        if beacon_hits: score += 0.3
        return min(1.0, score), {"blocked_egress": blocked_egress, "egress_bytes": egress_bytes, "beacon_hits": beacon_hits}
