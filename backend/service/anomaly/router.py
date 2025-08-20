# backend/service/anomaly/router.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# ---- Engines ----
# 기존 실시간 엔진
from .realtime_detector import RealtimeAnomalyEngine
# 새 통합 엔진(전처리 → 실시간 → 사용자 버퍼 → 클러스터링)
try:
    from .realtime_cluster_engine import UnifiedRealtimeClusterEngine
except Exception:
    # 배치 환경/상대경로용 폴백
    from backend.service.anomaly.realtime_cluster_engine import UnifiedRealtimeClusterEngine

router = APIRouter(tags=["anomaly"])

# 단건 이상치(레거시) 엔진: 그대로 유지
RT_ENGINE = RealtimeAnomalyEngine()

# 통합 엔진: 레거시 엔진을 내부에서 재사용(동일 기준/상태 유지)
UNIFIED_ENGINE = UnifiedRealtimeClusterEngine(
    rt_engine=RT_ENGINE,
    trigger_on_labels=("medium", "high"),  # medium/high 라벨이면 클러스터 트리거
    min_events_for_cluster=5,              # 사용자 버퍼 최소 5건 이상일 때
    periodic_flush_sec=600                 # 10분 주기 플러시
)

# ----- 스키마 -----
class PreprocessedEvent(BaseModel):
    id: Optional[str]
    timestamp: str
    original_text: Optional[str]
    normalized_content: Optional[str]
    extracted_entities: dict = Field(default_factory=dict)
    parsing_confidence: Optional[float] = 1.0

class DetectRequest(BaseModel):
    events: List[PreprocessedEvent]

class DetectResponseItem(BaseModel):
    id: Optional[str]
    timestamp: str
    anomaly_score: float
    label: str
    top_reasons: List[str]
    details: dict

class DetectResponse(BaseModel):
    results: List[DetectResponseItem]

# 통합 응답: 이벤트 단건 결과 + (있으면) 클러스터 결과
class UnifiedDetectResponseItem(BaseModel):
    event_anomaly: DetectResponseItem
    cluster_metrics: Optional[Dict[str, Any]] = None  # {"metrics": {...}, "details": {...}, "event_count": int}
    cluster_triggered: bool
    user_key: str

class UnifiedDetectResponse(BaseModel):
    results: List[UnifiedDetectResponseItem]

# ----- REST: 레거시 (단건 이상치만) -----
@router.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    results = [RT_ENGINE.infer_one(e.model_dump()) for e in req.events]
    # DetectResponseItem 스키마로 맞춰 리맵핑
    mapped = [
        DetectResponseItem(
            id=r.get("id"),
            timestamp=r.get("timestamp"),
            anomaly_score=r.get("anomaly_score"),
            label=r.get("label"),
            top_reasons=r.get("top_reasons", []),
            details=r.get("details", {})
        )
        for r in results
    ]
    return {"results": mapped}

# ----- REST: 통합 (이상치 + 클러스터) -----
@router.post("/detect/unified", response_model=UnifiedDetectResponse)
def detect_unified(req: DetectRequest):
    out: List[UnifiedDetectResponseItem] = []
    for e in req.events:
        res = UNIFIED_ENGINE.ingest(e.model_dump())
        # event_anomaly를 DetectResponseItem 타입으로 매핑
        ea = res.get("event_anomaly", {})
        ea_item = DetectResponseItem(
            id=ea.get("id"),
            timestamp=ea.get("timestamp"),
            anomaly_score=ea.get("anomaly_score"),
            label=ea.get("label"),
            top_reasons=ea.get("top_reasons", []),
            details=ea.get("details", {})
        )
        out.append(UnifiedDetectResponseItem(
            event_anomaly=ea_item,
            cluster_metrics=res.get("cluster_metrics"),
            cluster_triggered=res.get("cluster_triggered", False),
            user_key=res.get("user_key", "user:unknown")
        ))
    return {"results": out}

# ----- WebSocket: 레거시 스트림 (단건 이상치만) -----
active_sockets_legacy: List[WebSocket] = []

@router.websocket("/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    active_sockets_legacy.append(ws)
    try:
        while True:
            event = await ws.receive_json()       # 전처리 이벤트 1건
            result = RT_ENGINE.infer_one(event)   # 단건 이상치
            await ws.send_json(result)
    except WebSocketDisconnect:
        if ws in active_sockets_legacy:
            active_sockets_legacy.remove(ws)

# ----- WebSocket: 통합 스트림 (이상치 + 클러스터) -----
active_sockets_unified: List[WebSocket] = []

@router.websocket("/stream/unified")
async def stream_unified(ws: WebSocket):
    await ws.accept()
    active_sockets_unified.append(ws)
    try:
        while True:
            event = await ws.receive_json()           # 전처리 이벤트 1건
            result = UNIFIED_ENGINE.ingest(event)     # 이상치 + (트리거 시) 클러스터
            await ws.send_json(result)
    except WebSocketDisconnect:
        if ws in active_sockets_unified:
            active_sockets_unified.remove(ws)
