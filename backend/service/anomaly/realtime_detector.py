# backend/service/anomaly/realtime_detector.py
from __future__ import annotations
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict, deque
import math
import time
from datetime import datetime, timezone

# ---------- 유틸 ----------
def utc_ts(s: str) -> float:
    # "2025-01-15T03:24:15Z" → epoch seconds
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

def now_ts() -> float:
    return time.time()

def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))

# ---------- 슬라이딩 윈도우 카운터 ----------
class SlidingCounter:
    """
    key별 이벤트 타임스탬프를 보관하고, 최근 window_sec 기준의 빈도/초를 계산.
    메모리 보호를 위해 key마다 deque를 유지하고, window 밖을 즉시 청소.
    """
    def __init__(self, window_sec: int = 300):
        self.window_sec = window_sec
        self.events: Dict[str, deque] = defaultdict(deque)

    def add(self, key: str, ts: float):
        dq = self.events[key]
        dq.append(ts)
        cutoff = ts - self.window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def rate_per_sec(self, key: str, ref_ts: Optional[float] = None) -> float:
        dq = self.events.get(key)
        if not dq:
            return 0.0
        if ref_ts is None:
            ref_ts = now_ts()
        cutoff = ref_ts - self.window_sec
        # deque가 이미 청소되어 있다고 가정하지만, 혹시 몰라서 1회 더 필터링
        cnt = sum(1 for t in dq if t >= cutoff)
        return cnt / float(self.window_sec)

    def unique_keys(self) -> List[str]:
        return list(self.events.keys())

# ---------- EWMA(지수이동평균) 기준선 ----------
@dataclass
class EWMAState:
    mean: float = 0.0
    var: float  = 1e-6  # 분산 0 방지
    initialized: bool = False

class EWMABaseline:
    """
    key별로 빈도(rate_per_sec)의 지수 이동 평균과 분산을 업데이트하며
    직전 관측값의 z-score를 산출.
    """
    def __init__(self, alpha_mean: float = 0.2, alpha_var: float = 0.2):
        self.alpha_mean = alpha_mean
        self.alpha_var  = alpha_var
        self.state: Dict[str, EWMAState] = defaultdict(EWMAState)

    def update_and_z(self, key: str, value: float) -> float:
        st = self.state[key]
        if not st.initialized:
            st.mean = value
            st.var  = 1e-6
            st.initialized = True
            return 0.0
        # 업데이트 전 z
        std = math.sqrt(max(st.var, 1e-6))
        z = 0.0 if std == 0 else (value - st.mean) / std
        # 업데이트
        new_mean = (1 - self.alpha_mean) * st.mean + self.alpha_mean * value
        # 분산의 EWMA (Welford 대용, 간단화)
        new_var  = (1 - self.alpha_var) * st.var + self.alpha_var * ((value - st.mean) ** 2)
        st.mean, st.var = new_mean, max(new_var, 1e-9)
        return z

# ---------- 간단 드리프트 감지(평균 차이로 리셋) ----------
class SimpleDrift:
    """
    두 구간의 이동 평균 차이가 큰 경우 '리셋'을 제안하는 초간단 드리프트 감지기.
    실서비스에선 ADWIN 등의 검출기로 교체 권장.
    """
    def __init__(self, long_alpha=0.02, short_alpha=0.2, z_reset=6.0):
        self.long = EWMABaseline(alpha_mean=long_alpha, alpha_var=long_alpha)
        self.short = EWMABaseline(alpha_mean=short_alpha, alpha_var=short_alpha)
        self.z_reset = z_reset  # 너무 크면 리셋 발생 적음

    def update_and_need_reset(self, key: str, value: float) -> bool:
        z_long  = self.long.update_and_z(key, value)
        z_short = self.short.update_and_z(key, value)
        # 단기 평균이 장기 평균 대비 과도하게 벗어나면 리셋권고
        return abs(z_short - z_long) > self.z_reset

# ---------- 개별 감지기 ----------
@dataclass
class AnomalyResult:
    score: float
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, float] = field(default_factory=dict)

class RarityDetector:
    """
    희소성: 최근 window에서 '드문' key일수록 점수↑
    구현:  count(key) → rarity = 1/sqrt(count+1)
    """
    def __init__(self, window_sec: int = 1800):
        self.window = SlidingCounter(window_sec=window_sec)

    def update(self, key: str, ts: float) -> AnomalyResult:
        self.window.add(key, ts)
        # count는 rate*window_sec 와 동일하나, 간단화를 위해 rate_per_sec 사용
        rps = self.window.rate_per_sec(key, ref_ts=ts)  # events/window
        count_est = rps * self.window.window_sec
        rarity = 1.0 / math.sqrt(count_est + 1.0)  # 0~1대
        return AnomalyResult(
            score=rarity,
            reasons=[f"희소 이벤트: {key} (최근 {int(count_est)}건 추정)"],
            details={"rarity": rarity, "recent_count_est": count_est}
        )

class BurstDetector:
    """
    버스트: key의 발생율(rate)이 자기 평균 대비 얼마나 튀었는지 z-score로 평가
    """
    def __init__(self, window_sec: int = 300, alpha_mean=0.2, alpha_var=0.2, z_scale=0.5):
        self.window = SlidingCounter(window_sec=window_sec)
        self.baseline = EWMABaseline(alpha_mean, alpha_var)
        self.drift = SimpleDrift()
        self.z_scale = z_scale

    def update(self, key: str, ts: float) -> AnomalyResult:
        self.window.add(key, ts)
        rps = self.window.rate_per_sec(key, ref_ts=ts)
        if self.drift.update_and_need_reset(key, rps):
            # 기준선 리셋 (간단: 상태 재생성)
            self.baseline.state[key] = EWMAState(initialized=False)
        z = self.baseline.update_and_z(key, rps)
        # z를 0~1로 압축 (z_scale로 공격성 조절)
        score = sigmoid(self.z_scale * z)
        return AnomalyResult(
            score=score,
            reasons=[f"버스트 탐지: {key} (z={z:.2f}, rps={rps:.3f})"],
            details={"z": z, "rps": rps, "score": score}
        )

# ---------- 앙상블 ----------
class EnsembleDetector:
    """
    여러 감지기의 점수를 가중 평균. 각 감지기는 update(event_key, ts) 호출로 상태 갱신.
    """
    def __init__(self):
        self.detectors: List[Tuple[float, object]] = [
            (0.5, RarityDetector(window_sec=1800)),
            (0.5, BurstDetector(window_sec=300)),
        ]

    def update_event(self, keys: List[str], ts: float) -> Tuple[float, List[str], Dict[str, float]]:
        # 여러 key(예: src_ip, (src,dst), user, event_type 등)를 각각 업데이트하고 최대치를 취함
        scores, reasons, details = [], [], {}
        for key in keys:
            key_scores = []
            for w, det in self.detectors:
                res = det.update(key, ts)
                key_scores.append(w * res.score)
                reasons.extend([f"[{key}] {r}" for r in res.reasons])
                # details에 key별 소분류 값도 남겨두기
                for k, v in res.details.items():
                    details[f"{key}.{k}"] = v
            scores.append(sum(key_scores))
        final_score = max(scores) if scores else 0.0
        return final_score, reasons, details

# ---------- 이벤트 → 키 추출 ----------
def build_keys_from_event(event) -> List[str]:
    """
    dict(preprocessor output) 또는 models.SecurityEvent 모두 지원.
    """
    # SecurityEvent 객체
    if hasattr(event, "entities") and isinstance(event.entities, dict):
        ent = event.entities
        src = (ent.get("ips") or ["unknown"])[0]
        user = (ent.get("users") or ["unknown"])[0]
        etype = ent.get("event_type") or "unknown"
        dst = ent.get("destination_ip") or ent.get("dst_ip") or ["unknown"]
        if isinstance(dst, list):
            dst = dst[0]
        pair = f"{src}->{dst}"
        return [f"src:{src}", f"user:{user}", f"type:{etype}", f"flow:{pair}"]

    # dict 객체 (기존)
    ent = event.get("extracted_entities", {}) or {}
    src = (ent.get("ips") or ["unknown"])[0]
    user = (ent.get("users") or ["unknown"])[0]
    etype = ent.get("event_type") or "unknown"
    dst = (ent.get("dst_ip") or ent.get("destination_ip") or ["unknown"])
    if isinstance(dst, list):
        dst = dst[0]
    pair = f"{src}->{dst}"
    return [f"src:{src}", f"user:{user}", f"type:{etype}", f"flow:{pair}"]

# ---------- 퍼사드 ----------
class RealtimeAnomalyEngine:
    def __init__(self, high_th=0.80, med_th=0.55):
        self.ensemble = EnsembleDetector()
        self.high_th = high_th
        self.med_th = med_th

    def infer_one(self, event: dict) -> dict:
        ts = event.get("timestamp") or event.get("extracted_entities", {}).get("timestamp")
        tsf = utc_ts(ts) if isinstance(ts, str) else (ts if ts else now_ts())
        keys = build_keys_from_event(event)
        score, reasons, details = self.ensemble.update_event(keys, tsf)

        label = "low"
        if score >= self.high_th:
            label = "high"
        elif score >= self.med_th:
            label = "medium"

        return {
            "id": event.get("id"),
            "timestamp": ts,
            "anomaly_score": round(score, 4),
            "label": label,
            "top_reasons": reasons[:5],
            "details": details
        }

    def infer_batch(self, events: List[dict]) -> List[dict]:
        return [self.infer_one(e) for e in events]
