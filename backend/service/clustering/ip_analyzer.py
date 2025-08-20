# ip_analyzer.py (drop-in 교체)

from typing import List, Dict, Any
import ipaddress
from collections import defaultdict
from models import SecurityEvent
from config import DEFAULT_CONFIG

class IPAnalyzer:
    """IP 기반 공격 패턴 분석기(연쇄 hop 반영)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.internal_networks = [ipaddress.IPv4Network(n) for n in self.config.internal_networks]

    def calculate_ip_diversification(self, events: List[SecurityEvent]) -> float:
        if not events:
            return 0.0
        src = set(e.src_ip for e in events)
        dst = set(e.dst_ip for e in events)
        return min(1.0, len(src | dst) / len(events))

    def analyze_network_movement(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        if not events:
            return {"external_to_internal": 0, "internal_to_internal": 0, "lateral_movement_detected": False, "network_penetration_depth": 0}

        evs = sorted(events, key=lambda x: x.timestamp)
        ext_to_int = 0
        int_to_int = 0
        chain_len = 0
        last_dst = None
        ext_int_then_chain = False

        for e in evs:
            src_int = self._is_internal(e.src_ip)
            dst_int = self._is_internal(e.dst_ip)

            if not src_int and dst_int:
                ext_to_int += 1
                chain_len = 0
                last_dst = e.dst_ip
            elif src_int and dst_int:
                int_to_int += 1
                if last_dst and e.src_ip == last_dst:
                    chain_len += 1
                    last_dst = e.dst_ip
                else:
                    chain_len = 1
                    last_dst = e.dst_ip

                if chain_len >= 2 and ext_to_int > 0:
                    ext_int_then_chain = True

        lateral = (chain_len >= 2) or ext_int_then_chain
        depth = ext_to_int + int_to_int
        return {
            "external_to_internal": ext_to_int,
            "internal_to_internal": int_to_int,
            "lateral_movement_detected": lateral,
            "network_penetration_depth": depth
        }

    def _is_internal(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in net for net in self.internal_networks)
        except:
            return False
