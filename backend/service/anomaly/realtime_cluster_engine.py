# backend/service/anomaly/realtime_cluster_engine.py
from __future__ import annotations
from typing import Dict, Deque, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import asdict, is_dataclass
import time

# --- 안전한 import (패키지/상대 경로 모두 지원) ---
try:
    from backend.service.anomaly.realtime_detector import RealtimeAnomalyEngine
except Exception:
    from .realtime_detector import RealtimeAnomalyEngine

try:
    from backend.service.clustering.cluster_analyzer import ClusterAnalyzer
    from backend.service.clustering.models import SecurityEvent, ClusterMetrics, SeverityLevel
except Exception:
    from ..clustering.cluster_analyzer import ClusterAnalyzer
    from ..clustering.models import SecurityEvent, ClusterMetrics, SeverityLevel


def _now_ts() -> float:
    return time.time()

def _to_dict(obj) -> dict:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return {k: getattr(obj, k) for k in dir(obj) if not k.startswith("_") and not callable(getattr(obj, k))}

def _extract_user_key(event: Any) -> str:
    # SecurityEvent
    if hasattr(event, "entities") and isinstance(event.entities, dict):
        users = event.entities.get("users") or []
        return f"user:{users[0]}" if users else "user:unknown"
    # dict
    if isinstance(event, dict):
        ent = (event.get("extracted_entities") or {})
        users = ent.get("users") or []
        return f"user:{users[0]}" if users else "user:unknown"
    return "user:unknown"

def _ensure_security_event(event_like: Any) -> SecurityEvent:
    if isinstance(event_like, SecurityEvent):
        return event_like
    e = event_like or {}
    ent = (e.get("extracted_entities") or {})
    dst = ent.get("destination_ip") or ent.get("dst_ip") or [None]
    if isinstance(dst, list):
        dst = dst[0]
    return SecurityEvent(
        id=e.get("id"),
        timestamp=e.get("timestamp") or ent.get("timestamp"),
        src_ip=(ent.get("ips") or [None])[0],
        dst_ip=dst,
        entities=ent,
        parsing_confidence=e.get("parsing_confidence", 1.0),
        original_text=e.get("original_text") or e.get("normalized_content") or ""
    )


class UserBuffer:
    def __init__(self, max_events: int = 400, window_sec: int = 3600):
        self.max_events = max_events
        self.window_sec = window_sec
        self.events: Deque[SecurityEvent] = deque()
        self.last_flush_ts: float = 0.0

    def add(self, ev: SecurityEvent):
        self.events.append(ev)
        while len(self.events) > self.max_events:
            self.events.popleft()

    def snapshot(self) -> List[SecurityEvent]:
        return list(self.events)

    def should_time_flush(self, now_ts: float, flush_interval_sec: int) -> bool:
        return (now_ts - self.last_flush_ts) >= flush_interval_sec

    def mark_flushed(self, ts: float):
        self.last_flush_ts = ts


class UnifiedRealtimeClusterEngine:
    """
    실시간 이상치(단건) ↔ 사용자 기반 클러스터링(배치) 브리지.
    result = {
      "event_anomaly": {...},
      "cluster_metrics": {...} | None,
      "cluster_triggered": bool,
      "user_key": "user:alice"
    }
    """
    def __init__(
        self,
        trigger_on_labels: Tuple[str, ...] = ("medium", "high"),
        min_events_for_cluster: int = 5,
        periodic_flush_sec: int = 600,
        user_buffer_max_events: int = 400,
        user_buffer_window_sec: int = 3600,
        rt_engine: Optional[RealtimeAnomalyEngine] = None,
        cluster_analyzer: Optional[ClusterAnalyzer] = None,
    ):
        self.rt = rt_engine or RealtimeAnomalyEngine()
        self.ca = cluster_analyzer or ClusterAnalyzer()
        self.trigger_on_labels = set(trigger_on_labels)
        self.min_events_for_cluster = min_events_for_cluster
        self.periodic_flush_sec = periodic_flush_sec
        self.buffers: Dict[str, UserBuffer] = defaultdict(
            lambda: UserBuffer(user_buffer_max_events, user_buffer_window_sec)
        )

    def ingest(self, event: Any) -> Dict[str, Any]:
        # 1) 단건 이상치
        rt_res = self.rt.infer_one(
            event if isinstance(event, dict) else self._security_event_to_dict(event)
        )

        # 2) 사용자 버퍼 적재
        sec_event = _ensure_security_event(event)
        user_key = _extract_user_key(sec_event)
        buf = self.buffers[user_key]
        buf.add(sec_event)

        # 3) 트리거 판단
        triggered = False
        cluster_dict = None
        now_ts = _now_ts()
        label = rt_res.get("label")

        if label in self.trigger_on_labels and len(buf.events) >= self.min_events_for_cluster:
            cluster_dict = self._run_cluster(buf)
            buf.mark_flushed(now_ts)
            triggered = True
        elif buf.should_time_flush(now_ts, self.periodic_flush_sec) and len(buf.events) >= self.min_events_for_cluster:
            cluster_dict = self._run_cluster(buf)
            buf.mark_flushed(now_ts)
            triggered = True

        return {
            "event_anomaly": rt_res,
            "cluster_metrics": cluster_dict,
            "cluster_triggered": triggered,
            "user_key": user_key
        }

    def flush_user(self, user_key: str, reason: str = "manual"):
        buf = self.buffers.get(user_key)
        if not buf or len(buf.events) < self.min_events_for_cluster:
            return None
        result = self._run_cluster(buf)
        buf.mark_flushed(_now_ts())
        return {"user_key": user_key, "reason": reason, "cluster_metrics": result}

    def flush_all(self, reason: str = "shutdown"):
        out = {}
        for user_key, buf in self.buffers.items():
            if len(buf.events) >= self.min_events_for_cluster:
                out[user_key] = self._run_cluster(buf)
                buf.mark_flushed(_now_ts())
        return {"reason": reason, "results": out}

    def _run_cluster(self, buf: UserBuffer) -> Dict[str, Any]:
        events = buf.snapshot()
        metrics: ClusterMetrics = self.ca.analyze_cluster(events)
        details = self.ca.get_detailed_analysis(events)
        return {"metrics": _to_dict(metrics), "details": details, "event_count": len(events)}

    @staticmethod
    def _security_event_to_dict(se: SecurityEvent) -> dict:
        return {
            "id": getattr(se, "id", None),
            "timestamp": getattr(se, "timestamp", None),
            "extracted_entities": getattr(se, "entities", {}) or {},
            "parsing_confidence": getattr(se, "parsing_confidence", 1.0),
            "original_text": getattr(se, "original_text", "")
        }
