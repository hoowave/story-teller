# security_log_analyzer/event_clustering.py
"""이벤트 클러스터링 모듈"""
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from models import LogEntry, Classification, AttackCluster

class EventClusterer:
    """이벤트 클러스터링 엔진"""
    
    def __init__(self, time_window_seconds: int = 60):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.cluster_counter = 0
    
    def cluster_events(self, 
                       logs: List[LogEntry], 
                       classifications: List[Classification]) -> List[AttackCluster]:
        """관련된 이벤트들을 클러스터로 그룹화"""
        
        # 로그와 분류 매핑
        log_dict = {log.event_id: log for log in logs}
        class_dict = {cls.event_id: cls for cls in classifications}
        
        # 클러스터링 수행
        clusters = []
        
        # 1. 시간 기반 클러스터링
        time_clusters = self._cluster_by_time(logs)
        
        # 2. 각 시간 클러스터를 속성별로 세분화
        for time_cluster in time_clusters:
            attribute_clusters = self._cluster_by_attributes(time_cluster, class_dict)
            
            for cluster_logs in attribute_clusters:
                if len(cluster_logs) >= 2:  # 최소 2개 이상의 로그가 있을 때만 클러스터 생성
                    cluster = self._create_cluster(cluster_logs, class_dict)
                    clusters.append(cluster)
        
        return clusters
    
    def _cluster_by_time(self, logs: List[LogEntry]) -> List[List[LogEntry]]:
        """시간 기반으로 로그를 클러스터링"""
        # 시간순 정렬
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        clusters = []
        current_cluster = []
        
        for log in sorted_logs:
            if not current_cluster:
                current_cluster.append(log)
            else:
                # 이전 로그와의 시간 차이 계산
                time_diff = log.timestamp - current_cluster[-1].timestamp
                
                if time_diff <= self.time_window:
                    current_cluster.append(log)
                else:
                    if current_cluster:
                        clusters.append(current_cluster)
                    current_cluster = [log]
        
        if current_cluster:
            clusters.append(current_cluster)
        
        return clusters
    
    def _cluster_by_attributes(self, 
                              logs: List[LogEntry], 
                              classifications: Dict[str, Classification]) -> List[List[LogEntry]]:
        """속성(IP, 사용자, 공격 유형)별로 클러스터링"""
        attribute_groups = defaultdict(list)
        
        for log in logs:
            # 클러스터링 키 생성
            key_parts = []
            
            # IP 기반
            if log.entities.ips:
                key_parts.append(f"ip:{log.entities.ips[0]}")
            
            # 사용자 기반
            if log.entities.users:
                key_parts.append(f"user:{log.entities.users[0]}")
            
            # 공격 유형 기반
            if log.event_id in classifications:
                primary_category = classifications[log.event_id].hybrid_result.get('primary_category', '')
                if primary_category:
                    key_parts.append(f"category:{primary_category}")
            
            # event_type_hint도 고려
            if log.event_type_hint:
                key_parts.append(f"type:{log.event_type_hint}")
            
            if key_parts:
                key = "|".join(key_parts[:3])  # 최대 3개 속성만 사용
                attribute_groups[key].append(log)
            else:
                attribute_groups['unknown'].append(log)
        
        return list(attribute_groups.values())
    
    def _create_cluster(self, 
                       logs: List[LogEntry], 
                       classifications: Dict[str, Classification]) -> AttackCluster:
        """클러스터 객체 생성"""
        self.cluster_counter += 1
        cluster_id = f"cluster_{self.cluster_counter:03d}"
        
        # 시간 윈도우 계산
        timestamps = [log.timestamp for log in logs]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = (end_time - start_time).total_seconds()
        
        # 공통 속성 추출
        common_entities = self._extract_common_entities(logs)
        
        # 공격 진행 패턴 분석
        attack_progression = self._analyze_attack_progression(logs, classifications)
        
        # 클러스터 타입 결정
        cluster_type = self._determine_cluster_type(logs, classifications)
        
        # 패턴 분석
        pattern_analysis = {
            'attack_progression': attack_progression,
            'common_entities': common_entities,
            'escalation_detected': self._detect_escalation(attack_progression),
            'success_rate': self._calculate_success_rate(logs, classifications),
            'severity_distribution': self._analyze_severity(logs)
        }
        
        return AttackCluster(
            cluster_id=cluster_id,
            cluster_type=cluster_type,
            time_window={
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_seconds': int(duration)
            },
            related_events=[log.event_id for log in logs],
            pattern_analysis=pattern_analysis,
            cluster_confidence=self._calculate_cluster_confidence(logs, classifications)
        )
    
    def _extract_common_entities(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """공통 엔티티 추출"""
        entities = {}
        
        # IP 추출
        all_ips = []
        for log in logs:
            all_ips.extend(log.entities.ips)
        if all_ips:
            # 가장 빈번한 IP
            entities['source_ip'] = max(set(all_ips), key=all_ips.count)
            entities['unique_ips'] = list(set(all_ips))
        
        # 사용자 추출
        all_users = []
        for log in logs:
            all_users.extend(log.entities.users)
        if all_users:
            entities['target_user'] = max(set(all_users), key=all_users.count)
            entities['unique_users'] = list(set(all_users))
        
        # 파일 추출
        all_files = []
        for log in logs:
            all_files.extend(log.entities.files)
        if all_files:
            entities['accessed_files'] = list(set(all_files))
        
        # 프로세스 추출
        all_processes = []
        for log in logs:
            all_processes.extend(log.entities.processes)
        if all_processes:
            entities['executed_processes'] = list(set(all_processes))
        
        # 공격 벡터 추출 (event_type_hint 기반)
        event_types = [log.event_type_hint for log in logs if log.event_type_hint]
        if event_types:
            entities['attack_vector'] = max(set(event_types), key=event_types.count)
        
        return entities
    
    def _analyze_attack_progression(self, 
                                   logs: List[LogEntry], 
                                   classifications: Dict[str, Classification]) -> List[str]:
        """공격 진행 과정 분석"""
        progression = []
        
        # 시간순 정렬
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)
        
        for log in sorted_logs:
            if log.event_id in classifications:
                attack_types = classifications[log.event_id].hybrid_result.get('final_attack_types', [])
                if attack_types:
                    # 첫 번째 공격 유형을 진행 과정에 추가
                    progression.append(attack_types[0])
        
        return progression
    
    def _determine_cluster_type(self, 
                               logs: List[LogEntry], 
                               classifications: Dict[str, Classification]) -> str:
        """클러스터 타입 결정"""
        # 공격 유형 수집
        attack_types = []
        for log in logs:
            if log.event_id in classifications:
                types = classifications[log.event_id].hybrid_result.get('final_attack_types', [])
                attack_types.extend(types)
        
        # severity 분포 확인
        severities = [log.severity_hint for log in logs]
        has_warning_or_higher = 'warning' in severities or 'critical' in severities or 'high' in severities
        
        # 가장 빈번한 공격 유형으로 클러스터 타입 결정
        if 'failed_login' in attack_types and 'successful_login' in attack_types:
            return 'brute_force_sequence'
        elif 'successful_login' in attack_types and 'file_access' in attack_types:
            return 'post_compromise_activity'
        elif 'failed_login' in attack_types and attack_types.count('failed_login') >= 3:
            return 'brute_force_attempt'
        elif 'file_access' in attack_types or 'privilege_escalation' in attack_types:
            return 'privilege_escalation_attempt'
        elif 'process_execution' in attack_types:
            return 'malware_execution'
        elif 'data_exfiltration' in attack_types:
            return 'data_theft_attempt'
        elif has_warning_or_higher:
            return 'suspicious_activity'
        else:
            return 'normal_activity'
    
    def _detect_escalation(self, progression: List[str]) -> bool:
        """권한 상승 탐지"""
        escalation_patterns = [
            ['failed_login', 'successful_login'],
            ['successful_login', 'file_access'],
            ['successful_login', 'privilege_escalation'],
            ['file_access', 'process_execution'],
            ['file_access', 'data_exfiltration']
        ]
        
        for pattern in escalation_patterns:
            if len(progression) >= len(pattern):
                for i in range(len(progression) - len(pattern) + 1):
                    if progression[i:i+len(pattern)] == pattern:
                        return True
        return False
    
    def _calculate_success_rate(self, 
                               logs: List[LogEntry], 
                               classifications: Dict[str, Classification]) -> float:
        """성공률 계산"""
        success_count = 0
        total_count = 0
        
        for log in logs:
            if log.event_id in classifications:
                attack_types = classifications[log.event_id].hybrid_result.get('final_attack_types', [])
                if 'failed_login' in attack_types:
                    total_count += 1
                elif 'successful_login' in attack_types:
                    success_count += 1
                    total_count += 1
        
        if total_count > 0:
            return round(success_count / total_count, 2)
        return 0.0
    
    def _analyze_severity(self, logs: List[LogEntry]) -> Dict[str, int]:
        """심각도 분포 분석"""
        severity_count = defaultdict(int)
        for log in logs:
            severity_count[log.severity_hint] += 1
        return dict(severity_count)
    
    def _calculate_cluster_confidence(self, 
                                     logs: List[LogEntry], 
                                     classifications: Dict[str, Classification]) -> float:
        """클러스터 신뢰도 계산"""
        if not classifications:
            return 0.5
        
        # 분류 신뢰도의 평균
        confidences = []
        for log in logs:
            if log.event_id in classifications:
                conf = classifications[log.event_id].hybrid_result.get('combined_confidence', 0.5)
                confidences.append(conf)
        
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            # 로그 개수에 따른 보정
            size_factor = min(len(logs) / 10, 1.0)  # 10개 이상이면 1.0
            # parsing_confidence도 고려
            parsing_conf = sum(log.parsing_confidence for log in logs) / len(logs)
            
            return round(
                avg_confidence * 0.5 + 
                size_factor * 0.3 + 
                parsing_conf * 0.2, 
                2
            )
        
        return 0.5