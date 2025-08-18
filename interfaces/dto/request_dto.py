from pydantic import BaseModel

class RequestDto(BaseModel):
    message: str        # 자연어처리용
    age: str            # 머신러닝용
    gender: str         # 머신러닝용
    theme: str          # 머신러닝용    
    duration: str       # 자연어처리용