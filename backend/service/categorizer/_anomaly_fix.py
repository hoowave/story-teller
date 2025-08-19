import pandas as pd
from sklearn.ensemble import IsolationForest
import numpy as np
from collections import deque
import time
from datetime import datetime
from transformers import pipeline

class StatisticalAnomalyDetector:
    def __init__(self, training_threshold=100, time_window=300):
        self.model = IsolationForest(contamination='auto', random_state=42)
        self.training_threshold = training_threshold
        self.model_trained = False
        self.log_data = []
        self.log_timestamps = deque(maxlen=training_threshold)
        self.hourly_counter = {}
        self.time_window = time_window  # 5분 윈도우

        try:
            self.text_classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
            self.text_classifier_available = True
            print("Hugging Face text classification model loaded successfully.")
        except Exception as e:
            print(f"Failed to load Hugging Face model: {e}. Text-based anomaly detection will be skipped.")
            self.text_classifier_available = False

    def _prepare_data(self):
        """데이터프레임을 생성하고 필요한 특성을 추출합니다."""
        df = pd.DataFrame(self.log_data)
        if df.empty or 'ts' not in df.columns:
            return None
        
        df['ts'] = pd.to_datetime(df['ts'])
        df.set_index('ts', inplace=True)
        
        features = ['bytes_in', 'bytes_out']
        for f in features:
            if f not in df.columns:
                df[f] = 0
        
        return df

    def _train_model(self):
        """데이터가 충분하면 IsolationForest 모델을 훈련합니다."""
        if len(self.log_data) < self.training_threshold:
            return
        
        df = self._prepare_data()
        if df is None or df.empty:
            return

        features = ['bytes_in', 'bytes_out']
        X = df[features].dropna()
        
        if not X.empty:
            self.model.fit(X)
            self.model_trained = True
            print("IsolationForest model trained successfully.")

    def _detect_temporal_anomaly(self, log_entry):
        """시간적 이상을 감지합니다. 최근 로그 볼륨을 비교합니다."""
        ts = pd.to_datetime(log_entry.get('ts'))
        self.log_timestamps.append(ts)
        
        current_time = pd.to_datetime(time.time(), unit='s')
        recent_logs = sum(1 for t in self.log_timestamps if (current_time - t).total_seconds() <= self.time_window)
        
        if len(self.log_timestamps) > self.time_window * 2 and recent_logs > len(self.log_timestamps) / 2:
             return True, 0.8
        
        return False, 0.2

    def _detect_statistical_outliers(self, log_entry):
        """IsolationForest 모델을 사용하여 통계적 이상치를 감지합니다."""
        if not self.model_trained:
            return False, 0.1

        features = ['bytes_in', 'bytes_out']
        feature_values = [log_entry.get(f, 0) for f in features]
        
        try:
            prediction = self.model.predict([feature_values])
            if prediction == -1:
                return True, 0.9
        except Exception as e:
            print(f"Statistical outlier detection failed: {e}")
            return False, 0.1
        
        return False, 0.2

    def _detect_behavioral_anomaly(self, log_entry):
        """IsolationForest 모델을 사용하여 행동 이상을 감지합니다."""
        if not self.model_trained:
            return False, 0.1

        features = ['bytes_in', 'bytes_out']
        feature_values = [log_entry.get(f, 0) for f in features]
        
        try:
            prediction = self.model.predict([feature_values])
            if prediction == -1:
                decision_function = self.model.decision_function([feature_values])[0]
                confidence = 1 - (decision_function + 0.5)
                return True, confidence
        except Exception as e:
            print(f"Behavioral anomaly detection failed: {e}")
            return False, 0.1
        
        return False, 0.2

    def _detect_contextual_anomaly(self, log_entry):
        """로그의 컨텍스트(사용자, IP, 포트)를 기반으로 이상을 감지합니다."""
        entities = log_entry.get('entities', {})
        
        dst_port = log_entry.get('dst_port')
        if dst_port and dst_port not in [80, 443, 22, 25]:
            return True, 0.7

        suspicious_files = ['/etc/passwd', 'C:\\Windows\\System32']
        if 'files' in entities and any(file in suspicious_files for file in entities['files']):
            return True, 0.9
            
        return False, 0.3

    def _detect_text_anomaly(self, log_entry):
        """Hugging Face 모델을 사용하여 로그 메시지 텍스트의 이상을 감지합니다."""
        if not self.text_classifier_available:
            return False, 0.1
        
        msg = log_entry.get('msg', '')
        if not msg:
            return False, 0.1

        try:
            result = self.text_classifier(msg)
            label = result[0]['label']
            score = result[0]['score']

            if label == 'NEGATIVE' and score > 0.8:
                return True, score
        except Exception as e:
            print(f"Hugging Face text detection failed: {e}")
            return False, 0.1

        return False, 0.1

    def _calculate_confidence(self, anomalies):
        """가중치를 부여하여 최종 이상 감지 신뢰도를 계산합니다."""
        weights = {
            '_detect_temporal_anomaly': 0.2,
            '_detect_statistical_outliers': 0.3,
            '_detect_behavioral_anomaly': 0.4,
            '_detect_contextual_anomaly': 0.5,
            '_detect_text_anomaly': 0.6
        }
        
        total_confidence = 0
        total_weight = 0
        
        for method, (is_anomaly, confidence) in anomalies.items():
            if is_anomaly:
                weight = weights.get(method, 0.1)
                total_confidence += confidence * weight
                total_weight += weight
        
        return total_confidence / total_weight if total_weight > 0 else 0

    def detect_anomalies(self, log_entry):
        """주어진 로그 엔트리에 대해 여러 유형의 이상을 감지합니다."""
        self.log_data.append(log_entry)
        self._train_model()
        
        anomalies = {
            '_detect_temporal_anomaly': self._detect_temporal_anomaly(log_entry),
            '_detect_statistical_outliers': self._detect_statistical_outliers(log_entry),
            '_detect_behavioral_anomaly': self._detect_behavioral_anomaly(log_entry),
            '_detect_contextual_anomaly': self._detect_contextual_anomaly(log_entry),
            '_detect_text_anomaly': self._detect_text_anomaly(log_entry)
        }
        
        total_confidence = self._calculate_confidence(anomalies)
        
        is_anomaly = any(v[0] for v in anomalies.values())
        
        return {
            "is_anomaly": is_anomaly,
            "confidence": total_confidence,
            "details": {
                "message": log_entry.get('msg', ''),
                "entities": log_entry.get('entities', {})
            }
        }