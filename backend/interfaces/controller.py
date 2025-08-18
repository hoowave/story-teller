from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from interfaces.dto.request_dto import RequestDto
from service.service import Service

router = APIRouter()

service = Service()

def get_service():
    return service

@router.get("/")
def index():
    return "Welcome to the story-teller API!"

# 테스트용 API
@router.get("/api/test")
def graph(
    service: Service = Depends(get_service)
):
    print("Test API called")
    return service.test()