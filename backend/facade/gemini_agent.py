from dotenv import load_dotenv
from google import genai
import os
import json
import re

class GeminiAgent:
    def __init__(self):
        load_dotenv()
        api_key = os.getenv("GEMINI_API_KEY")
        # client 생성 및 API 키 설정
        self.__client = genai.Client(api_key=api_key)   
    
    def request(self, prompt):
        req = f"""여기에 프롬프트가 들어갑니다.
        프롬프트 내용: {prompt}
        """
        
        response = self.__client.models.generate_content(
            model="gemini-2.5-flash",
            contents=req
        )
        return response.text