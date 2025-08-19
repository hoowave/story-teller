# log_analyzer
"""통계 기반 이상 탐지 모듈"""
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math
import json
from pathlib import Path

class StatisticalAnomalyDetector:
    """통계적 이상 탐지 엔진"""
    
    def __init__(self, baseline_config_path: Optional[str] = None):
        # 베이스라인 설정 (실제로는 과거 데이터로부터 학습)
        self.baseline = self._initialize_baseline(baseline_config_path)
        self.sliding_window = defaultdict(lambda: deque(maxlen=100))  # 최근 100개 이벤트
        self.thresholds = self._initialize_thresholds()
        
    def _initialize_baseline(self, config_path: Optional[str]) -> Dict[str, Any]:
        """베이스라인 초기화 (정상 행동 패턴)"""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        # 기본 베이스라인 (실제로는 과거 데이터에서 학습)
        return {
            'hourly_events': {
                'mean': 50,  # 시간당 평균 이벤트 수
                'std': 15,   # 표준편차
                'distribution': [30, 25, 20, 18, 15, 12, 10, 8, 15, 25, 35, 45,
                                50, 55, 60, 58, 55, 50, 45, 40, 35, 30, 28, 25]  # 24시간
            },
            'user_activity': {
                'avg_files_per_day': 20,
                'avg_logins_per_day': 5,
                'avg_processes_per_session': 10,
                'working_hours': (9, 18),  # 9 AM to 6 PM
                'typical_users': ['admin', 'user1', 'user2', 'service_account']
            },
            'network_patterns': {
                'avg_connections_per_hour': 100,
                'typical_ports': [22, 80, 443, 3306, 5432],
                'internal_subnet': ['192.168.', '10.', '172.'],
                'avg_data_transfer_mb': 50
            },
            'file_access_patterns': {
                'avg_file_access_per_user': 30,
                'sensitive_file_access_threshold': 5,
                'bulk_download_threshold': 100,
                'typical_extensions': ['.txt', '.log', '.csv', '.json', '.xml']
            },
            'authentication_patterns': {
                'failed_login_threshold': 5,
                'password_spray_threshold': 3,  # 다수 계정에 대한 시도
                'brute_force_time_window': 300  # 5분
            }
        }
    
    def _initialize_thresholds(self) -> Dict[str, float]:
        """이상 탐지 임계값 설정"""
        return {
            'z_score_threshold': 3.0,  # 3 표준편차 이상
            'iqr_multiplier': 1.5,     # IQR 방법의 배수
            'entropy_threshold': 0.8,   # 엔트로피 임계값
            'deviation_threshold': 2.0, # 편차 임계값
            'correlation_threshold': 0.7  # 상관관계 임계값
        }
    
    def detect_anomalies(self, log_entry: Dict[str, Any], 
                        historical_context: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """종합적인 이상 탐지"""
        anomalies = {
            'is_anomalous': False,
            'anomaly_scores': {},
            'anomaly_types': [],
            'statistical_indicators': {},
            'behavioral_anomalies': [],
            'contextual_anomalies': [],
            'detection_confidence': 0.0
        }
        
        # 1. 시간 기반 이상 탐지
        temporal_anomaly = self._detect_temporal_anomaly(log_entry)
        if temporal_anomaly['is_anomalous']:
            anomalies['anomaly_types'].append('temporal')
            anomalies['anomaly_scores']['temporal'] = temporal_anomaly['score']
        
        # 2. 볼륨 기반 이상 탐지
        volume_anomaly = self._detect_volume_anomaly(log_entry, historical_context)
        if volume_anomaly['is_anomalous']:
            anomalies['anomaly_types'].append('volume')
            anomalies['anomaly_scores']['volume'] = volume_anomaly['score']
        
        # 3. 패턴 기반 이상 탐지
        pattern_anomaly = self._detect_pattern_anomaly(log_entry, historical_context)
        if pattern_anomaly['is_anomalous']:
            anomalies['anomaly_types'].append('pattern')
            anomalies['anomaly_scores']['pattern'] = pattern_anomaly['score']
        
        # 4. 행동 기반 이상 탐지
        behavioral_anomaly = self._detect_behavioral_anomaly(log_entry)
        if behavioral_anomaly['is_anomalous']:
            anomalies['anomaly_types'].append('behavioral')
            anomalies['anomaly_scores']['behavioral'] = behavioral_anomaly['score']
            anomalies['behavioral_anomalies'] = behavioral_anomaly['details']
        
        # 5. 통계적 이상치 탐지
        statistical_anomaly = self._detect_statistical_outliers(log_entry, historical_context)
        anomalies['statistical_indicators'] = statistical_anomaly
        if statistical_anomaly['is_outlier']:
            anomalies['anomaly_types'].append('statistical')
            anomalies['anomaly_scores']['statistical'] = statistical_anomaly['outlier_score']
        
        # 6. 컨텍스트 기반 이상 탐지
        contextual_anomaly = self._detect_contextual_anomaly(log_entry, historical_context)
        if contextual_anomaly['is_anomalous']:
            anomalies['anomaly_types'].append('contextual')
            anomalies['anomaly_scores']['contextual'] = contextual_anomaly['score']
            anomalies['contextual_anomalies'] = contextual_anomaly['details']
        
        # 종합 평가
        if anomalies['anomaly_scores']:
            anomalies['is_anomalous'] = True
            anomalies['detection_confidence'] = self._calculate_confidence(anomalies['anomaly_scores'])
        
        return anomalies
    
    def _detect_temporal_anomaly(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """시간 기반 이상 탐지"""
        result = {'is_anomalous': False, 'score': 0.0, 'details': []}
        
        timestamp = datetime.fromisoformat(log_entry['timestamp'].replace('+00:00', '+00:00'))
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        
        # 업무 시간 외 활동
        working_hours = self.baseline['user_activity']['working_hours']
        if not (working_hours[0] <= hour <= working_hours[1]) and day_of_week < 5:
            result['is_anomalous'] = True
            result['score'] = 0.7
            result['details'].append(f"Non-business hours activity at {hour}:00")
        
        # 주말 활동
        if day_of_week >= 5:
            result['is_anomalous'] = True
            result['score'] = max(result['score'], 0.6)
            result['details'].append("Weekend activity detected")
        
        # 새벽 시간대 활동 (0-5시)
        if 0 <= hour < 5:
            result['is_anomalous'] = True
            result['score'] = max(result['score'], 0.8)
            result['details'].append("Early morning activity (suspicious hours)")
        
        # 예상 활동량과의 편차
        expected_events = self.baseline['hourly_events']['distribution'][hour]
        if hasattr(self, 'hourly_counter'):
            current_hour_events = self.hourly_counter.get(hour, 0)
            if current_hour_events > expected_events * 2:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.75)
                result['details'].append(f"Unusual activity volume for hour {hour}")
        
        return result
    
    def _detect_volume_anomaly(self, log_entry: Dict[str, Any], 
                              historical_context: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """볼륨 기반 이상 탐지"""
        result = {'is_anomalous': False, 'score': 0.0, 'details': []}
        
        entities = log_entry.get('entities', {}).get('raw', {})
        
        # 파일 접근 볼륨 체크
        files = entities.get('files', [])
        if len(files) > 10:  # 단일 이벤트에서 많은 파일 접근
            result['is_anomalous'] = True
            result['score'] = min(len(files) / 20, 1.0)
            result['details'].append(f"High file access volume: {len(files)} files")
        
        # 대량 다운로드 탐지 (파일명이나 메시지에서)
        msg = log_entry.get('original_log', {}).get('msg', '').lower()
        if any(keyword in msg for keyword in ['download', 'transfer', 'export']):
            # 숫자 추출 (예: "downloaded 150 files")
            import re
            numbers = re.findall(r'\d+', msg)
            for num in numbers:
                if int(num) > self.baseline['file_access_patterns']['bulk_download_threshold']:
                    result['is_anomalous'] = True
                    result['score'] = max(result['score'], 0.9)
                    result['details'].append(f"Bulk operation detected: {num} items")
        
        # 과거 컨텍스트와 비교
        if historical_context:
            # 최근 평균 대비 급증
            recent_file_counts = [
                len(h.get('entities', {}).get('raw', {}).get('files', [])) 
                for h in historical_context[-10:] if h
            ]
            if recent_file_counts:
                avg_files = sum(recent_file_counts) / len(recent_file_counts)
                if len(files) > avg_files * 3:
                    result['is_anomalous'] = True
                    result['score'] = max(result['score'], 0.8)
                    result['details'].append(f"3x higher than recent average")
        
        return result
    
    def _detect_pattern_anomaly(self, log_entry: Dict[str, Any],
                               historical_context: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """패턴 기반 이상 탐지"""
        result = {'is_anomalous': False, 'score': 0.0, 'details': []}
        
        # 비정상적인 접근 패턴
        entities = log_entry.get('entities', {}).get('raw', {})
        
        # 민감한 파일 접근 패턴
        sensitive_files_accessed = 0
        for file_info in entities.get('files', []):
            if file_info.get('sensitivity') == 'high':
                sensitive_files_accessed += 1
        
        if sensitive_files_accessed > self.baseline['file_access_patterns']['sensitive_file_access_threshold']:
            result['is_anomalous'] = True
            result['score'] = min(sensitive_files_accessed / 10, 1.0)
            result['details'].append(f"Excessive sensitive file access: {sensitive_files_accessed}")
        
        # 순차적 이상 체인 탐지
        chains = self._detect_anomaly_chains(anomalies)
        if chains:
            correlations['anomaly_chains'] = chains
            correlations['attack_campaign_detected'] = any(
                len(chain['events']) > 5 for chain in chains
            )
        
        # 위험도 증폭 계산
        if correlations['correlated_groups'] or correlations['anomaly_chains']:
            # 연관된 이상이 많을수록 위험도 증가
            group_factor = sum(len(g['events']) for g in correlations['correlated_groups'])
            chain_factor = sum(len(c['events']) for c in correlations['anomaly_chains'])
            correlations['risk_amplification'] = 1 + (group_factor + chain_factor) * 0.1
        
        return correlations
    
    def _group_by_time_window(self, anomalies: List[Dict[str, Any]], 
                             window_minutes: int) -> List[List[Dict[str, Any]]]:
        """시간 윈도우별 그룹핑"""
        if not anomalies:
            return []
        
        # 시간순 정렬
        sorted_anomalies = sorted(
            anomalies, 
            key=lambda x: datetime.fromisoformat(x['timestamp'].replace('+00:00', '+00:00'))
        )
        
        groups = []
        current_group = [sorted_anomalies[0]]
        
        for i in range(1, len(sorted_anomalies)):
            current_time = datetime.fromisoformat(
                sorted_anomalies[i]['timestamp'].replace('+00:00', '+00:00')
            )
            group_start = datetime.fromisoformat(
                current_group[0]['timestamp'].replace('+00:00', '+00:00')
            )
            
            if (current_time - group_start).total_seconds() <= window_minutes * 60:
                current_group.append(sorted_anomalies[i])
            else:
                if len(current_group) > 1:
                    groups.append(current_group)
                current_group = [sorted_anomalies[i]]
        
        if len(current_group) > 1:
            groups.append(current_group)
        
        return groups
    
    def _find_common_types(self, group: List[Dict[str, Any]]) -> List[str]:
        """공통 이상 유형 찾기"""
        type_counter = defaultdict(int)
        
        for anomaly in group:
            for anomaly_type in anomaly.get('anomaly_types', []):
                type_counter[anomaly_type] += 1
        
        # 2개 이상의 이벤트에서 나타난 유형
        common_types = [
            atype for atype, count in type_counter.items() 
            if count >= min(2, len(group) / 2)
        ]
        
        return common_types
    
    def _detect_anomaly_chains(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """순차적 이상 체인 탐지"""
        chains = []
        
        # 엔티티 기반 체인 탐지
        entity_chains = defaultdict(list)
        
        for anomaly in anomalies:
            # 주요 엔티티 추출
            entities = anomaly.get('entities', {}).get('raw', {})
            
            # IP 기반 체인
            for ip_info in entities.get('ips', []):
                ip = ip_info['address']
                entity_chains[f'ip:{ip}'].append(anomaly)
            
            # 사용자 기반 체인
            for user_info in entities.get('users', []):
                user = user_info['username']
                entity_chains[f'user:{user}'].append(anomaly)
        
        # 체인 분석
        for entity_key, chain_events in entity_chains.items():
            if len(chain_events) >= 3:  # 3개 이상의 연관 이상
                # 시간순 정렬
                chain_events.sort(
                    key=lambda x: datetime.fromisoformat(x['timestamp'].replace('+00:00', '+00:00'))
                )
                
                chains.append({
                    'entity': entity_key,
                    'events': [e['event_id'] for e in chain_events],
                    'duration_seconds': (
                        datetime.fromisoformat(chain_events[-1]['timestamp'].replace('+00:00', '+00:00')) -
                        datetime.fromisoformat(chain_events[0]['timestamp'].replace('+00:00', '+00:00'))
                    ).total_seconds(),
                    'anomaly_progression': [
                        e.get('attack_classification', {}).get('primary_type', 'unknown')
                        for e in chain_events
                    ]
                })
        
        ports = entities.get('ports', [])
        if len(ports) > 5:
            port_numbers = sorted([p['port'] for p in ports])
            # 연속된 포트 확인
            sequential_count = 0
            for i in range(1, len(port_numbers)):
                if port_numbers[i] - port_numbers[i-1] == 1:
                    sequential_count += 1
            
            if sequential_count > 3:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.85)
                result['details'].append("Sequential port scanning pattern detected")
        
        # 비정상적인 사용자-IP 조합
        ips = [ip['address'] for ip in entities.get('ips', [])]
        users = [u['username'] for u in entities.get('users', [])]
        
        if historical_context and users and ips:
            # 이전에 본 적 없는 조합
            historical_combinations = set()
            for h in historical_context:
                h_ips = [ip['address'] for ip in h.get('entities', {}).get('raw', {}).get('ips', [])]
                h_users = [u['username'] for u in h.get('entities', {}).get('raw', {}).get('users', [])]
                for ip in h_ips:
                    for user in h_users:
                        historical_combinations.add((user, ip))
            
            current_combinations = set((user, ip) for user in users for ip in ips)
            new_combinations = current_combinations - historical_combinations
            
            if new_combinations:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.7)
                result['details'].append(f"New user-IP combinations: {list(new_combinations)}")
        
        return result
    
    def _detect_behavioral_anomaly(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """행동 기반 이상 탐지"""
        result = {'is_anomalous': False, 'score': 0.0, 'details': []}
        
        # 인증 실패 후 성공 패턴
        attack_type = log_entry.get('attack_classification', {}).get('primary_type', '')
        
        # 브루트포스 행동 패턴
        if attack_type == 'failed_login':
            # 실패 횟수 추적
            user = log_entry.get('entities', {}).get('raw', {}).get('users', [{}])[0].get('username', '')
            if user:
                self.sliding_window[f'failed_login_{user}'].append(datetime.now())
                recent_failures = len(self.sliding_window[f'failed_login_{user}'])
                
                if recent_failures > self.baseline['authentication_patterns']['failed_login_threshold']:
                    result['is_anomalous'] = True
                    result['score'] = min(recent_failures / 10, 1.0)
                    result['details'].append(f"Brute force behavior: {recent_failures} failures")
        
        # 데이터 수집 행동 패턴
        entities = log_entry.get('entities', {}).get('raw', {})
        files = entities.get('files', [])
        
        # 다양한 디렉토리 탐색 (정찰 활동)
        if len(files) > 5:
            directories = set()
            for file_info in files:
                path = file_info.get('path', '')
                if '/' in path:
                    directories.add('/'.join(path.split('/')[:-1]))
            
            if len(directories) > 5:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.75)
                result['details'].append(f"Directory traversal behavior: {len(directories)} directories")
        
        # 권한 상승 시도 패턴
        processes = entities.get('processes', [])
        suspicious_processes = ['sudo', 'su', 'runas', 'psexec', 'mimikatz']
        for proc in processes:
            if any(susp in proc.get('name', '').lower() for susp in suspicious_processes):
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.85)
                result['details'].append(f"Privilege escalation attempt: {proc.get('name')}")
        
        # 은닉 활동 패턴
        if 'defense_evasion' in log_entry.get('attack_chain', {}).get('detected_stages', []):
            result['is_anomalous'] = True
            result['score'] = max(result['score'], 0.8)
            result['details'].append("Defense evasion behavior detected")
        
        return result
    
    def _detect_statistical_outliers(self, log_entry: Dict[str, Any],
                                    historical_context: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """통계적 이상치 탐지"""
        result = {
            'is_outlier': False,
            'outlier_score': 0.0,
            'z_scores': {},
            'iqr_outliers': [],
            'statistical_metrics': {}
        }
        
        if not historical_context or len(historical_context) < 10:
            return result
        
        # 수치형 특징 추출
        current_features = self._extract_numerical_features(log_entry)
        historical_features = [self._extract_numerical_features(h) for h in historical_context]
        
        # Z-score 계산
        for feature_name, current_value in current_features.items():
            historical_values = [h.get(feature_name, 0) for h in historical_features]
            if historical_values:
                mean = np.mean(historical_values)
                std = np.std(historical_values)
                
                if std > 0:
                    z_score = abs((current_value - mean) / std)
                    result['z_scores'][feature_name] = z_score
                    
                    if z_score > self.thresholds['z_score_threshold']:
                        result['is_outlier'] = True
                        result['outlier_score'] = max(result['outlier_score'], z_score / 5)
        
        # IQR 방법
        for feature_name, current_value in current_features.items():
            historical_values = [h.get(feature_name, 0) for h in historical_features]
            if len(historical_values) > 4:
                q1 = np.percentile(historical_values, 25)
                q3 = np.percentile(historical_values, 75)
                iqr = q3 - q1
                
                lower_bound = q1 - self.thresholds['iqr_multiplier'] * iqr
                upper_bound = q3 + self.thresholds['iqr_multiplier'] * iqr
                
                if current_value < lower_bound or current_value > upper_bound:
                    result['iqr_outliers'].append(feature_name)
                    result['is_outlier'] = True
                    
                    # 이상치 정도 계산
                    if current_value > upper_bound:
                        outlier_degree = (current_value - upper_bound) / (iqr + 1)
                    else:
                        outlier_degree = (lower_bound - current_value) / (iqr + 1)
                    
                    result['outlier_score'] = max(result['outlier_score'], min(outlier_degree, 1.0))
        
        # 통계 메트릭 추가
        result['statistical_metrics'] = {
            'entropy': self._calculate_entropy(current_features),
            'variance_ratio': self._calculate_variance_ratio(current_features, historical_features)
        }
        
        return result
    
    def _detect_contextual_anomaly(self, log_entry: Dict[str, Any],
                                  historical_context: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """컨텍스트 기반 이상 탐지"""
        result = {'is_anomalous': False, 'score': 0.0, 'details': []}
        
        # 사용자 컨텍스트
        users = [u['username'] for u in log_entry.get('entities', {}).get('raw', {}).get('users', [])]
        typical_users = self.baseline['user_activity']['typical_users']
        
        for user in users:
            if user not in typical_users:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.6)
                result['details'].append(f"Unknown user: {user}")
        
        # 네트워크 컨텍스트
        ips = log_entry.get('entities', {}).get('raw', {}).get('ips', [])
        external_ips = [ip for ip in ips if not ip.get('is_internal', True)]
        
        if len(external_ips) > 2:
            result['is_anomalous'] = True
            result['score'] = max(result['score'], 0.7)
            result['details'].append(f"Multiple external IPs: {len(external_ips)}")
        
        # 시스템 컨텍스트 - 비정상적인 프로세스 체인
        processes = [p.get('name', '') for p in log_entry.get('entities', {}).get('raw', {}).get('processes', [])]
        suspicious_chains = [
            ['cmd.exe', 'powershell.exe'],
            ['explorer.exe', 'cmd.exe'],
            ['services.exe', 'nc.exe']
        ]
        
        for chain in suspicious_chains:
            if all(proc in processes for proc in chain):
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.85)
                result['details'].append(f"Suspicious process chain: {' -> '.join(chain)}")
        
        # 지리적 컨텍스트 (시뮬레이션)
        if historical_context:
            # 새로운 지리적 위치에서의 접근
            current_geos = set([ip.get('geolocation', '') for ip in ips])
            historical_geos = set()
            for h in historical_context:
                h_ips = h.get('entities', {}).get('raw', {}).get('ips', [])
                historical_geos.update([ip.get('geolocation', '') for ip in h_ips])
            
            new_geos = current_geos - historical_geos
            if new_geos and 'external' in new_geos:
                result['is_anomalous'] = True
                result['score'] = max(result['score'], 0.75)
                result['details'].append("Access from new geographic location")
        
        return result
    
    def _extract_numerical_features(self, log_entry: Dict[str, Any]) -> Dict[str, float]:
        """수치형 특징 추출"""
        features = {}
        
        entities = log_entry.get('entities', {}).get('raw', {})
        
        # 엔티티 수
        features['ip_count'] = len(entities.get('ips', []))
        features['user_count'] = len(entities.get('users', []))
        features['file_count'] = len(entities.get('files', []))
        features['process_count'] = len(entities.get('processes', []))
        features['port_count'] = len(entities.get('ports', []))
        
        # 위험도 점수
        features['risk_score'] = log_entry.get('risk_assessment', {}).get('score', 0)
        
        # 공격 지표 수
        features['attack_indicator_count'] = len(
            log_entry.get('attack_classification', {}).get('secondary_types', [])
        )
        
        # 시간 특징
        timestamp = datetime.fromisoformat(log_entry['timestamp'].replace('+00:00', '+00:00'))
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        
        # 민감도 점수
        sensitive_count = sum(
            1 for f in entities.get('files', [])
            if f.get('sensitivity') in ['high', 'medium']
        )
        features['sensitive_access_count'] = sensitive_count
        
        return features
    
    def _calculate_entropy(self, features: Dict[str, float]) -> float:
        """엔트로피 계산"""
        if not features:
            return 0.0
        
        values = list(features.values())
        total = sum(values)
        
        if total == 0:
            return 0.0
        
        entropy = 0
        for value in values:
            if value > 0:
                probability = value / total
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_variance_ratio(self, current: Dict[str, float],
                                 historical: List[Dict[str, float]]) -> float:
        """분산 비율 계산"""
        if not historical:
            return 1.0
        
        current_values = list(current.values())
        historical_values = [list(h.values()) for h in historical]
        
        current_var = np.var(current_values) if current_values else 0
        historical_vars = [np.var(h) for h in historical_values if h]
        
        if historical_vars:
            avg_historical_var = np.mean(historical_vars)
            if avg_historical_var > 0:
                return current_var / avg_historical_var
        
        return 1.0
    
    def _calculate_confidence(self, scores: Dict[str, float]) -> float:
        """탐지 신뢰도 계산"""
        if not scores:
            return 0.0
        
        # 가중 평균 (여러 유형에서 탐지될수록 신뢰도 증가)
        weights = {
            'temporal': 0.15,
            'volume': 0.20,
            'pattern': 0.25,
            'behavioral': 0.25,
            'statistical': 0.10,
            'contextual': 0.05
        }
        
        weighted_sum = 0
        weight_total = 0
        
        for anomaly_type, score in scores.items():
            weight = weights.get(anomaly_type, 0.1)
            weighted_sum += score * weight
            weight_total += weight
        
        if weight_total > 0:
            confidence = weighted_sum / weight_total
            # 다중 탐지 보너스
            if len(scores) > 3:
                confidence = min(confidence * 1.2, 1.0)
            return round(confidence, 3)
        
        return 0.0
    
    def update_baseline(self, log_entries: List[Dict[str, Any]]):
        """베이스라인 업데이트 (학습)"""
        # 정상 로그로부터 베이스라인 업데이트
        for entry in log_entries:
            if not entry.get('anomalies', {}).get('is_anomalous', False):
                # 시간별 이벤트 수 업데이트
                timestamp = datetime.fromisoformat(entry['timestamp'].replace('+00:00', '+00:00'))
                hour = timestamp.hour
                
                if not hasattr(self, 'hourly_counter'):
                    self.hourly_counter = defaultdict(int)
                self.hourly_counter[hour] += 1
                
                # 사용자 활동 패턴 업데이트
                entities = entry.get('entities', {}).get('raw', {})
                files = entities.get('files', [])
                
                # 이동 평균으로 베이스라인 업데이트
                alpha = 0.1  # 학습률
                current_file_count = len(files)
                self.baseline['file_access_patterns']['avg_file_access_per_user'] = (
                    (1 - alpha) * self.baseline['file_access_patterns']['avg_file_access_per_user'] +
                    alpha * current_file_count
                )

class AnomalyCorrelator:
    """이상 패턴 상관관계 분석"""
    
    def __init__(self):
        self.anomaly_chains = []
        self.correlation_matrix = defaultdict(lambda: defaultdict(float))
    
    def correlate_anomalies(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """이상 패턴 간 상관관계 분석"""
        correlations = {
            'correlated_groups': [],
            'anomaly_chains': [],
            'risk_amplification': 1.0,
            'attack_campaign_detected': False
        }
        
        # 시간 기반 그룹핑
        time_groups = self._group_by_time_window(anomalies, window_minutes=10)
        
        for group in time_groups:
            if len(group) > 2:
                # 같은 시간대에 여러 이상 발생
                correlations['correlated_groups'].append({
                    'events': [a['event_id'] for a in group],
                    'common_anomaly_types': self._find_common_types(group),
                    'correlation_strength': len(group) / 10  # 정규화
                })
        
        # 순차