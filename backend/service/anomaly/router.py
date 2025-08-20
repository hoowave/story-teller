# backend/service/anomaly/router.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from typing import List, Optional
from .realtime_detector import RealtimeAnomalyEngine

router = APIRouter(tags=["anomaly"])
ENGINE = RealtimeAnomalyEngine()

# ----- 스키마 -----
class PreprocessedEvent(BaseModel):
    id: Optional[str]
    timestamp: str
    original_text: Optional[str]
    normalized_content: Optional[str]
    extracted_entities: dict = Field(default_factory=dict)
    parsing_confidence: Optional[float]

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

# ----- REST: 단건/배치 공용 -----
@router.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest):
    results = [ENGINE.infer_one(e.dict()) for e in req.events]
    return {"results": results}

# ----- WebSocket: 실시간 스트림 (프론트 대시보드 연동용) -----
active_sockets: List[WebSocket] = []

@router.websocket("/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    active_sockets.append(ws)
    try:
        while True:
            # 클라 → 서버: 전처리 이벤트 1건씩 전송한다고 가정
            event = await ws.receive_json()
            result = ENGINE.infer_one(event)
            # 서버 → 클라: 실시간 결과 push
            await ws.send_json(result)
    except WebSocketDisconnect:
        if ws in active_sockets:
            active_sockets.remove(ws)
