# security_log_analyzer/anomaly_detector.py
"""통계 기반 이상 탐지 모듈"""
import numpy as np
import math
from datetime import datetime
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional
from models import LogEntry


class StatisticalAnomalyDetector:
    """통계적 이상 탐지 엔진"""

    def __init__(self, baseline_config: Optional[Dict[str, Any]] = None):
        self.baseline = baseline_config or self._initialize_baseline()
        self.sliding_window = defaultdict(lambda: deque(maxlen=100))
        self.thresholds = self._initialize_thresholds()
        self.hourly_counter = defaultdict(int)

    def _initialize_baseline(self) -> Dict[str, Any]:
        return {
            "hourly_events": {
                "mean": 50,
                "std": 15,
                "distribution": [30, 25, 20, 18, 15, 12, 10, 8, 15, 25, 35, 45,
                                 50, 55, 60, 58, 55, 50, 45, 40, 35, 30, 28, 25]
            },
            "user_activity": {
                "avg_files_per_day": 20,
                "avg_logins_per_day": 5,
                "avg_processes_per_session": 10,
                "working_hours": (9, 18),
                "typical_users": ["admin", "user1", "user2", "service_account"]
            },
            "network_patterns": {
                "avg_connections_per_hour": 100,
                "typical_ports": [22, 80, 443, 3306, 5432],
                "internal_subnet": ["192.168.", "10.", "172."],
                "avg_data_transfer_mb": 50
            },
            "file_access_patterns": {
                "avg_file_access_per_user": 30,
                "sensitive_file_access_threshold": 5,
                "bulk_download_threshold": 100,
                "typical_extensions": [".txt", ".log", ".csv", ".json", ".xml"]
            },
            "authentication_patterns": {
                "failed_login_threshold": 5,
                "password_spray_threshold": 3,
                "brute_force_time_window": 300
            }
        }

    def _initialize_thresholds(self) -> Dict[str, float]:
        return {
            "z_score_threshold": 3.0,
            "iqr_multiplier": 1.5,
            "entropy_threshold": 0.8,
            "deviation_threshold": 2.0,
            "correlation_threshold": 0.7
        }

    def detect(self, log: LogEntry, historical: List[LogEntry]) -> Dict[str, Any]:
        """종합적인 이상 탐지"""
        anomalies = {
            "event_id": log.event_id,
            "is_anomalous": False,
            "anomaly_scores": {},
            "anomaly_types": [],
            "details": [],
            "detection_confidence": 0.0,
        }

        # 1. 시간 기반
        temporal = self._detect_temporal_anomaly(log)
        if temporal["is_anomalous"]:
            anomalies["is_anomalous"] = True
            anomalies["anomaly_types"].append("temporal")
            anomalies["anomaly_scores"]["temporal"] = temporal["score"]
            anomalies["details"].extend(temporal["details"])

        # 2. 볼륨 기반
        volume = self._detect_volume_anomaly(log, historical)
        if volume["is_anomalous"]:
            anomalies["is_anomalous"] = True
            anomalies["anomaly_types"].append("volume")
            anomalies["anomaly_scores"]["volume"] = volume["score"]
            anomalies["details"].extend(volume["details"])

        # 3. 행동 기반
        behavioral = self._detect_behavioral_anomaly(log)
        if behavioral["is_anomalous"]:
            anomalies["is_anomalous"] = True
            anomalies["anomaly_types"].append("behavioral")
            anomalies["anomaly_scores"]["behavioral"] = behavioral["score"]
            anomalies["details"].extend(behavioral["details"])

        # 4. 통계 기반
        statistical = self._detect_statistical_outliers(log, historical)
        if statistical["is_outlier"]:
            anomalies["is_anomalous"] = True
            anomalies["anomaly_types"].append("statistical")
            anomalies["anomaly_scores"]["statistical"] = statistical["outlier_score"]
            anomalies["details"].append("통계적 이상치 감지")

        # 5. 컨텍스트 기반
        contextual = self._detect_contextual_anomaly(log, historical)
        if contextual["is_anomalous"]:
            anomalies["is_anomalous"] = True
            anomalies["anomaly_types"].append("contextual")
            anomalies["anomaly_scores"]["contextual"] = contextual["score"]
            anomalies["details"].extend(contextual["details"])

        # 신뢰도 계산
        if anomalies["anomaly_scores"]:
            anomalies["detection_confidence"] = self._calculate_confidence(anomalies["anomaly_scores"])

        return anomalies

    # -------------------------------
    # 개별 탐지 로직들
    # -------------------------------
    def _detect_temporal_anomaly(self, log: LogEntry) -> Dict[str, Any]:
        result = {"is_anomalous": False, "score": 0.0, "details": []}
        ts = log.timestamp
        hour = ts.hour
        dow = ts.weekday()
        working_hours = self.baseline["user_activity"]["working_hours"]

        if not (working_hours[0] <= hour <= working_hours[1]) and dow < 5:
            result["is_anomalous"] = True
            result["score"] = 0.7
            result["details"].append(f"업무 시간 외 활동 ({hour}시)")
        if dow >= 5:
            result["is_anomalous"] = True
            result["score"] = max(result["score"], 0.6)
            result["details"].append("주말 활동")
        if 0 <= hour < 5:
            result["is_anomalous"] = True
            result["score"] = max(result["score"], 0.8)
            result["details"].append("새벽 활동 감지")
        return result

    def _detect_volume_anomaly(self, log: LogEntry, historical: List[LogEntry]) -> Dict[str, Any]:
        result = {"is_anomalous": False, "score": 0.0, "details": []}
        files = log.entities.files
        if len(files) > 10:
            result["is_anomalous"] = True
            result["score"] = min(len(files) / 20, 1.0)
            result["details"].append(f"다량의 파일 접근: {len(files)}개")
        return result

    def _detect_behavioral_anomaly(self, log: LogEntry) -> Dict[str, Any]:
        result = {"is_anomalous": False, "score": 0.0, "details": []}
        if log.event_type_hint == "authentication" and "failed" in log.msg.lower():
            user = log.user or "unknown"
            self.sliding_window[f"failed_{user}"].append(datetime.now())
            if len(self.sliding_window[f"failed_{user}"]) > self.baseline["authentication_patterns"]["failed_login_threshold"]:
                result["is_anomalous"] = True
                result["score"] = 0.8
                result["details"].append(f"{user} 계정에서 다수 로그인 실패")
        return result

    def _detect_statistical_outliers(self, log: LogEntry, historical: List[LogEntry]) -> Dict[str, Any]:
        result = {"is_outlier": False, "outlier_score": 0.0}
        if len(historical) < 5:
            return result
        current = len(log.entities.files)
        hist = [len(h.entities.files) for h in historical]
        mean = np.mean(hist)
        std = np.std(hist)
        if std > 0:
            z = abs((current - mean) / std)
            if z > self.thresholds["z_score_threshold"]:
                result["is_outlier"] = True
                result["outlier_score"] = min(z / 5, 1.0)
        return result

    def _detect_contextual_anomaly(self, log: LogEntry, historical: List[LogEntry]) -> Dict[str, Any]:
        result = {"is_anomalous": False, "score": 0.0, "details": []}
        if log.user and log.user not in self.baseline["user_activity"]["typical_users"]:
            result["is_anomalous"] = True
            result["score"] = 0.6
            result["details"].append(f"비정상 사용자: {log.user}")
        return result

    def _calculate_confidence(self, scores: Dict[str, float]) -> float:
        weights = {"temporal": 0.15, "volume": 0.2, "behavioral": 0.25, "statistical": 0.2, "contextual": 0.2}
        total = sum(weights.get(k, 0.1) for k in scores)
        if total == 0:
            return 0.0
        return round(sum(scores[k] * weights.get(k, 0.1) for k in scores) / total, 3)


class AnomalyCorrelator:
    """이상 탐지 상관관계 분석"""
    def correlate(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = {"correlated": False, "groups": []}
        counts = defaultdict(int)
        for a in anomalies:
            for t in a.get("anomaly_types", []):
                counts[t] += 1
        for t, c in counts.items():
            if c > 2:
                summary["correlated"] = True
                summary["groups"].append({"type": t, "count": c})
        return summary
