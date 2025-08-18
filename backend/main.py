"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import interfaces.controller as Controller

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(Controller.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
"""

# 수정본
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import interfaces.controller as Controller
from service.preprocessor.api import router as preproc_router   # ★ 추가

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(Controller.router)
app.include_router(preproc_router, prefix="/v1")  # ★ /v1/ingest 로 노출

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)