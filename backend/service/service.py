from facade.gemini_agent import GeminiAgent
from facade.log_cluster import LogCluster

class Service:
    def __init__(self):
        self.__log_cluster = LogCluster()
        self.__gemini_agent = GeminiAgent()


    def upload(self, files):
        for file in files:
            print(f"Uploaded file: {file.filename}")
        return "Files uploaded completed."


    def clustering(self):
        self.__log_cluster.analyze()
        return "Clustering analysis completed."