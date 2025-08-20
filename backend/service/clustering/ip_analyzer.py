# ip_analyzer.py
from typing import List, Dict, Any
import ipaddress
from models import SecurityEvent
from config import DEFAULT_CONFIG
import math
from collections import defaultdict



def _valid_ip(ip: str):
    try:
        return ipaddress.IPv4Address(ip)
    except Exception:
        return None

class IPAnalyzer:
    """IP 기반 공격 패턴 분석기(연쇄 hop 반영)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.internal_networks = [ipaddress.IPv4Network(n) for n in self.config.internal_networks]

    def calculate_ip_diversification(self, events):
        if not events:
            return 0.0

        all_ips, ext_ips, int_ips = set(), set(), set()

        for e in events:
            for ip in (e.src_ip, e.dst_ip):
                if not _valid_ip(ip) or ip == "0.0.0.0":
                    continue  # ← 비정상/보정 IP는 통계에서 제외
                all_ips.add(ip)
                if self._is_internal(ip):
                    int_ips.add(ip)
                else:
                    ext_ips.add(ip)

        total_events = len(events)
        unique_all = len(all_ips)
        unique_ext = len(ext_ips)

        global_score = 0.0
        if total_events > 0 and unique_all > 0:
            global_score = math.log1p(unique_all) / math.log1p(total_events + 1)

        window_min = getattr(self.config, "ip_div_window_min", 15)
        buckets = defaultdict(list)
        for e in events:
            bucket = int(e.timestamp.timestamp() // (window_min * 60))
            buckets[bucket].append(e)

        window_scores = []
        for _, evs in buckets.items():
            ext_set = set()
            for ev in evs:
                for ip in (ev.src_ip, ev.dst_ip):
                    if not _valid_ip(ip) or ip == "0.0.0.0":
                        continue
                    if not self._is_internal(ip):
                        ext_set.add(ip)
            cnt = len(evs)
            if cnt == 0:
                continue
            score = math.log1p(len(ext_set)) / math.log1p(cnt + 1)
            window_scores.append(score)

        if window_scores:
            window_scores.sort()
            idx = max(0, min(len(window_scores) - 1, int(0.75 * (len(window_scores) - 1))))
            window_score = window_scores[idx]
        else:
            window_score = 0.0

        external_ratio = (unique_ext / unique_all) if unique_all > 0 else 0.0
        final = 0.5 * global_score + 0.4 * window_score + 0.1 * external_ratio
        return max(0.0, min(1.0, final))

    def analyze_network_movement(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        if not events:
            return {"external_to_internal":0,"internal_to_internal":0,"lateral_movement_detected":False,"network_penetration_depth":0}

        evs = sorted(events, key=lambda x: x.timestamp)
        ext_to_int = 0
        int_to_int = 0
        chain = 0
        last_dst = None
        ext_int_then_chain = False

        for e in evs:
            # ← 유효하지 않은 IP 포함 이벤트는 이동 집계에서 제외
            if not (_valid_ip(e.src_ip) and _valid_ip(e.dst_ip)):
                continue
            src_int = self._is_internal(e.src_ip)
            dst_int = self._is_internal(e.dst_ip)
            if (not src_int) and dst_int:
                ext_to_int += 1
                chain = 0
                last_dst = e.dst_ip
            elif src_int and dst_int:
                int_to_int += 1
                if last_dst and e.src_ip == last_dst:
                    chain += 1
                    last_dst = e.dst_ip
                else:
                    chain = 1
                    last_dst = e.dst_ip
                if chain >= 2 and ext_to_int > 0:
                    ext_int_then_chain = True

        lateral = (chain >= 2) or ext_int_then_chain
        depth = ext_to_int + int_to_int
        return {
            "external_to_internal": ext_to_int,
            "internal_to_internal": int_to_int,
            "lateral_movement_detected": lateral,
            "network_penetration_depth": depth
        }

    def _is_internal(self, ip_str: str) -> bool:
        ip = _valid_ip(ip_str)
        if not ip:
            # 내부/외부 판단 불가: 보수적으로 외부 취급 대신, 상위 로직에서 제외했으므로 여기선 False로 처리
            return False
        return any(ip in net for net in self.internal_networks)
