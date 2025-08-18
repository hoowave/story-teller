from facade.open_ai_agent import OpenAIAgent
from interfaces.dto.request_dto import RequestDto
import time
import os

class Service:
    def __init__(self):
        self.__open_ai_agent = OpenAIAgent()
        self.__df = None

    def test(self):
        return "Test API is working!"