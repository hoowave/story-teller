# ip_analyzer.py
from typing import List, Dict, Any
import ipaddress
from models import SecurityEvent
from config import DEFAULT_CONFIG
import math
from collections import defaultdict


class IPAnalyzer:
    """IP 기반 공격 패턴 분석기(연쇄 hop 반영)"""

    def __init__(self, config=None):
        self.config = config or DEFAULT_CONFIG
        self.internal_networks = [ipaddress.IPv4Network(n) for n in self.config.internal_networks]

    def calculate_ip_diversification(self, events):
        """
        개선된 IP 다각화 점수:
        - 전역 로그 스케일: log1p(unique_ips) / log1p(total_events)
        - 시간 윈도우 기반: 각 버킷에서 log1p(unique_external_ips) / log1p(events_in_bucket)의 75퍼센타일
        - 외부 IP 비율 가산: unique_external / unique_all
        최종: 0.5*global + 0.4*window + 0.1*external_ratio (0~1)
        """
        if not events:
            return 0.0

        # ---- 전역 통계 ----
        all_ips = set()
        ext_ips = set()
        int_ips = set()

        for e in events:
            for ip in (e.src_ip, e.dst_ip):
                all_ips.add(ip)
                if self._is_internal(ip):
                    int_ips.add(ip)
                else:
                    ext_ips.add(ip)

        total_events = len(events)
        unique_all = len(all_ips)
        unique_ext = len(ext_ips)

        # 전역 점수: 로그 스케일 (이벤트 수 큰 경우 완만하게 증가)
        global_score = 0.0
        if total_events > 0:
            global_score = math.log1p(unique_all) / math.log1p(total_events + 1)

        # ---- 시간 윈도우 점수 ----
        # 윈도우 크기: config.ip_div_window_min (없으면 15분)
        window_min = getattr(self.config, "ip_div_window_min", 15)
        buckets = defaultdict(list)
        # 버킷 키 = (utc_ts // (window_min*60))
        for e in events:
            bucket = int(e.timestamp.timestamp() // (window_min * 60))
            buckets[bucket].append(e)

        window_scores = []
        for _, evs in buckets.items():
            # 각 버킷은 외부 IP 다양성이 봇넷/프록시에 더 유의미
            ext_set = set()
            for ev in evs:
                if not self._is_internal(ev.src_ip):
                    ext_set.add(ev.src_ip)
                if not self._is_internal(ev.dst_ip):
                    ext_set.add(ev.dst_ip)
            uniq_ext_in_bucket = len(ext_set)
            cnt = len(evs)
            if cnt == 0:
                continue
            score = math.log1p(uniq_ext_in_bucket) / math.log1p(cnt + 1)
            window_scores.append(score)

        if window_scores:
            window_scores.sort()
            # 상위 75퍼센타일 사용 (봇넷성 '피크'를 반영)
            idx = max(0, min(len(window_scores) - 1, int(0.75 * (len(window_scores) - 1))))
            window_score = window_scores[idx]
        else:
            window_score = 0.0

        # ---- 외부 IP 비율 가산 ----
        external_ratio = unique_ext / max(1, unique_all)

        # ---- 최종 결합 ----
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
            src_int = self._is_internal(e.src_ip)
            dst_int = self._is_internal(e.dst_ip)
            if not src_int and dst_int:
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
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in net for net in self.internal_networks)
        except:
            return False
