from fastapi import APIRouter, Depends, File, UploadFile
from typing import List
from service.service import Service

router = APIRouter()

service = Service()

def get_service():
    return service

@router.get("/")
def index():
    return "Welcome to the story-teller API!"

# 파일 업로드 API
@router.post("/upload")
def upload_files(
    files: List[UploadFile] = File(...),
    service: Service = Depends(get_service)
):
    service.upload(files)
    return "Files upload API is working!"

# 테스트용 API
@router.get("/api/risk")
def graph(
    service: Service = Depends(get_service)
):
    service.risk()
    return "test API is working!"