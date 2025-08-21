from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime, timezone
import hashlib, math
from collections import defaultdict

# === 정책 테이블 (v0.3) ===
BASE_TYPE = {
    "authentication": 5,
    "auth_failure": 6,
    "file_accessed": 6,
    "process_start": 7,
    "network_connection": 6,
    "privilege_escalation": 10,
    "malware_detected": 10,
    "data_exfil": 9,
    "scan": 4,
    "bruteforce": 7,
    "config_change": 7,
    "xss": 6,
    "sqli": 8,
    "rce": 10,
    None: 3,
    "other": 3,
}

SEVERITY_HINT = {
    "info": 2,
    "low": 4,
    "medium": 6,
    "high": 8,
    "critical": 10,
    None: 3,
}

def _asset_crit(dst_ip: Optional[str], files: List[str], source_type: str) -> int:
    # 파일 경로 힌트
    for f in files or []:
        if any(p in f for p in ("/etc/", "/var/www/", "/etc/shadow", "/var/lib/", "/home/")):
            return 8
        if any(p in f for p in ("/var/log/", "/opt/app/", "/srv/")):
            return 6
    # 사설망 IP 간단 힌트
    if dst_ip:
        if dst_ip.startswith(("10.", "172.16.", "172.31.", "192.168.")):
            return 6
    # 소스 타입 힌트
    if source_type in ("auth", "ids", "edr", "db", "firewall"):
        return 7
    return 5

def _risk_level(score: float) -> str:
    if score >= 8.5: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.5: return "Medium"
    if score >= 2.5: return "Low"
    return "Info"

@dataclass
class GroupContext:
    key: Tuple
    count: int
    first_seen: str
    last_seen: str
    sample_msgs: List[str]

def _hash_key(key: Tuple) -> str:
    m = hashlib.sha256("|".join([str(x) for x in key]).encode())
    return m.hexdigest()[:12]

def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def score_groups(
    events: List[Any],
    group_by: Optional[List[str]] = None,
    anomaly_weight: float = 0.2,
    anomaly_score_lookup: Optional[Dict[str, float]] = None
) -> Dict[str, Any]:
    """
    전처리 필드만으로 스코어 산출.
    anomaly_score_lookup[cluster_id] ∈ [0,1]이 들어오면 (나중에) 가중치 얹어서 반영.
    """
    if group_by is None:
        group_by = ["user", "src_ip", "dst_ip", "event_type_hint"]

    buckets: Dict[Tuple, List[Any]] = defaultdict(list)
    for ev in events:
        users = ev.entities.get("users") or [None]
        for u in users:
            key = (u, getattr(ev, "src_ip", None), getattr(ev, "dst_ip", None), getattr(ev, "event_type_hint", None))
            buckets[key].append(ev)

    all_ts = [_parse_iso(e.ts) for e in events]
    if not all_ts:
        return {"policy_version": "v0.3", "groups": []}
    min_ts, max_ts = min(all_ts), max(all_ts)
    span_sec = max(1.0, (max_ts - min_ts).total_seconds())

    results = []
    for key, evs in buckets.items():
        # 유형/심각도 힌트(그룹 내 최대값 사용)
        type_score = max([BASE_TYPE.get(getattr(e, "event_type_hint", None), BASE_TYPE[None]) for e in evs] or [3])
        severity = max([SEVERITY_HINT.get(getattr(e, "severity_hint", None), SEVERITY_HINT[None]) for e in evs] or [3])

        # 볼륨: 로그스케일
        volume = min(10.0, 3 + math.log2(len(evs) + 1))

        # 최근성: 데이터셋 범위 내 상대 위치
        last_seen_dt = max(_parse_iso(e.ts) for e in evs)
        recency = 2 + 8 * ((last_seen_dt - min_ts).total_seconds() / span_sec)  # 2..10

        # 자산 중요도
        sample = evs[-1]
        asset = _asset_crit(getattr(sample, "dst_ip", None), sample.entities.get("files") or [], getattr(sample, "source_type", ""))

        # 파싱 신뢰도 보정(-2..+2 근사)
        avg_conf = sum(getattr(e, "parsing_confidence", 1.0) for e in evs) / len(evs)
        confidence_adj = (avg_conf - 0.5) * 4

        base_score = (
            0.30 * type_score +
            0.20 * severity +
            0.20 * volume +
            0.15 * recency +
            0.15 * asset
        ) + confidence_adj
        base_score = max(0.0, min(10.0, base_score))

        # 이상탐지 훅(선택)
        cid = _hash_key(key)
        anomaly_0_1 = 0.0
        if anomaly_score_lookup and cid in anomaly_score_lookup:
            anomaly_0_1 = max(0.0, min(1.0, float(anomaly_score_lookup[cid])))

        final_score = base_score * (1 - anomaly_weight) + (base_score + 2.0) * anomaly_weight * anomaly_0_1
        final_score = max(0.0, min(10.0, final_score))

        ctx = GroupContext(
            key=key,
            count=len(evs),
            first_seen=min(_parse_iso(e.ts) for e in evs).isoformat(),
            last_seen=last_seen_dt.isoformat(),
            sample_msgs=[e.msg for e in evs[:3]],
        )

        results.append({
            "cluster_id": cid,
            "risk_score": round(final_score, 2),
            "risk_level": _risk_level(final_score),
            "factors": {
                "type": round(type_score, 1),
                "severity": round(severity, 1),
                "volume": round(volume, 1),
                "recency": round(recency, 1),
                "asset": round(asset, 1),
                "confidence_adj": round(confidence_adj, 1),
            },
            "group_context": {
                "key": {
                    "user": key[0],
                    "src_ip": key[1],
                    "dst_ip": key[2],
                    "event_type_hint": key[3],
                },
                "count": ctx.count,
                "first_seen": ctx.first_seen,
                "last_seen": ctx.last_seen,
                "sample_msgs": ctx.sample_msgs,
            },
            "explain": f"{key[3]} 관련 이벤트 {len(evs)}건. 최근성{round(recency,1)}/자산{asset}/확신도보정{round(confidence_adj,1)} 반영",
            "policy_version": "v0.3"
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"policy_version": "v0.3", "groups": results}

def main_from_events(events: List[Any]) -> Dict[str, Any]:
    return score_groups(events)
