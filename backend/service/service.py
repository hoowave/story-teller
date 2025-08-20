import tempfile

from facade.gemini_agent import GeminiAgent
from facade.log_cluster import LogCluster
from facade.log_cluster_test import Clustering
from facade.risk_agent import RiskAgent
from facade.processor_agent import ProcessorAgent

class Service:
    def __init__(self):
        self.__processor_agent = ProcessorAgent()
        self.__log_cluster = LogCluster()
        self.__clustering = Clustering()
        self.__risk_agent = RiskAgent()
        self.__gemini_agent = GeminiAgent()

    ## Step 1 사용자에게 로그 파일 업로드 전달받음
    def upload(self, files):
        ## Step 2 업로드된 로그 파일 데이터 전처리
        self.__processor_agent.run_preprocessor_from_files(files, full=True, save_json="facade/data/processor_output.json")
        
        ## Step 3 전처리된 로그 데이터를 기반으로 클러스터링
        ## 이 부분에서 클러스터링을 두번째 방법으로 진행합니다.
        ## 첫번째 방법으로 하고자 하시면 아래를 주석처리하고 self.__log_cluster.analyze() 를 사용해주세요.
        
        self.__clustering.analyze()
        # self.__log_cluster.analyze()
        

        ## Step 4 클러스터링 결과를 기반으로 위험도 평가
        self.__risk_agent.run()

        ## Step 5 위험도 평가 결과를 기반으로 스토리 생성
        ## TODO : Implement the story generation logic

        return "Action completed."