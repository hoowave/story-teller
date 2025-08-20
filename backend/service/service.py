from facade.gemini_agent import GeminiAgent
from facade.log_cluster import LogCluster
from facade.risk_agent import RiskAgent

class Service:
    def __init__(self):
        self.__log_cluster = LogCluster()
        self.__risk_agent = RiskAgent()
        self.__gemini_agent = GeminiAgent()

    ## Step 1 사용자에게 로그 파일 업로드 전달받음
    def upload(self, files):
        for file in files:
            print(f"Uploaded file: {file.filename}")
        return "Files uploaded completed."

    ## Step 2 업로드된 로그 파일 데이터 전처리
    def preprocess(self):
        ## TODO : Implement the preprocessing logic
        return "Preprocessing completed."

    ## Step 3 전처리된 로그 데이터를 기반으로 클러스터링
    def clustering(self):
        self.__log_cluster.analyze()
        return "Clustering analysis completed."
    
    ## Step 4 클러스터링 결과를 기반으로 위험도 평가
    def risk(self):
        self.__risk_agent.run()
        return "Risk assessment completed."
    
    ## Step 5 위험도 평가 결과를 기반으로 스토리 생성
    def generate_story(self):
        ## TODO : Implement the story generation logic
        return "Story generation completed."