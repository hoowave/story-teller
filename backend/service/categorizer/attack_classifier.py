# security_log_analyzer/attack_classifier.py
"""공격 분류 모듈"""
import re
from typing import List, Dict, Any, Set
from datetime import datetime
from models import LogEntry, AttackType, SeverityLevel, Classification

class RuleBasedClassifier:
    """규칙 기반 공격 분류기"""
    
    def __init__(self):
        self.patterns = {
            'failed_login': [
                r'failed\s+login',
                r'authentication\s+fail',
                r'invalid\s+password',
                r'login\s+attempt\s+failed',
                r'login\s+denied'
            ],
            'successful_login': [
                r'successful\s+login',
                r'authentication\s+success',
                r'logged\s+in\s+successfully',
                r'login\s+accepted'
            ],
            'file_access': [
                r'file\s+accessed',
                r'accessed\s+.*file',
                r'file\s+opened',
                r'read\s+file',
                r'write\s+file'
            ],
            'sensitive_file': [
                r'/etc/passwd',
                r'/etc/shadow',
                r'\.ssh/',
                r'config\.(ini|xml|json)',
                r'/root/',
                r'sensitive\s+file'
            ],
            'process_execution': [
                r'process\s+exe',
                r'executed\s+command',
                r'nc\.exe',
                r'cmd\.exe',
                r'powershell\.exe',
                r'bash\s+executed'
            ],
            'data_transfer': [
                r'data\s+transfer',
                r'file\s+upload',
                r'file\s+download',
                r'large\s+transfer',
                r'exfiltration'
            ]
        }
    
    def classify(self, log_entry: LogEntry) -> Dict[str, Any]:
        """로그 엔트리를 규칙 기반으로 분류"""
        attack_types = []
        matched_patterns = []
        confidence = 0.0
        
        # msg 필드와 raw 필드 모두 검사
        text_to_check = (log_entry.msg + " " + log_entry.raw).lower()
        
        # 패턴 매칭
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check):
                    if attack_type == 'failed_login':
                        attack_types.append(AttackType.FAILED_LOGIN.value)
                    elif attack_type == 'successful_login':
                        attack_types.append(AttackType.SUCCESSFUL_LOGIN.value)
                    elif attack_type == 'file_access':
                        attack_types.append(AttackType.FILE_ACCESS.value)
                    elif attack_type == 'sensitive_file':
                        attack_types.append(AttackType.PRIVILEGE_ESCALATION.value)
                    elif attack_type == 'process_execution':
                        attack_types.append(AttackType.PROCESS_EXECUTION.value)
                    elif attack_type == 'data_transfer':
                        attack_types.append(AttackType.DATA_EXFILTRATION.value)
                    
                    matched_patterns.append(f"{attack_type}_pattern")
                    confidence = max(confidence, 0.85)
                    break
        
        # event_type_hint도 고려
        if log_entry.event_type_hint == "authentication" and not attack_types:
            if "failed" in text_to_check:
                attack_types.append(AttackType.FAILED_LOGIN.value)
            else:
                attack_types.append(AttackType.SUCCESSFUL_LOGIN.value)
            confidence = max(confidence, 0.7)
        
        # 중복 제거
        attack_types = list(set(attack_types))
        
        if not attack_types:
            attack_types = [AttackType.UNKNOWN.value]
            confidence = 0.3
        
        return {
            'attack_types': attack_types,
            'confidence': confidence,
            'matched_patterns': matched_patterns
        }

class AIClassifier:
    """AI 기반 공격 분류기 (시뮬레이션)"""
    
    def classify(self, log_entry: LogEntry) -> Dict[str, Any]:
        """AI 모델을 사용한 분류 (시뮬레이션)"""
        # 실제로는 여기서 LLM API를 호출하거나 훈련된 모델을 사용
        # 지금은 시뮬레이션을 위한 로직
        
        attack_types = []
        confidence = 0.0
        
        text_lower = (log_entry.msg + " " + log_entry.raw).lower()
        
        # 엔티티 정보도 활용
        has_ip = bool(log_entry.entities.ips)
        has_user = bool(log_entry.entities.users)
        has_file = bool(log_entry.entities.files)
        has_process = bool(log_entry.entities.processes)
        
        if 'failed' in text_lower and 'login' in text_lower:
            attack_types.extend(['authentication_failure', 'brute_force_attempt'])
            confidence = 0.85
        elif 'successful' in text_lower and 'login' in text_lower:
            attack_types.extend(['successful_breach', 'authentication_success'])
            confidence = 0.90
        elif has_file and ('passwd' in text_lower or 'sensitive' in text_lower):
            attack_types.extend(['file_access_violation', 'privilege_abuse'])
            confidence = 0.82
        elif has_process or '.exe' in text_lower:
            attack_types.extend(['malicious_process', 'execution_attempt'])
            confidence = 0.78
        elif has_file:
            attack_types.extend(['file_operation', 'data_access'])
            confidence = 0.75
        else:
            attack_types = ['anomaly_detected']
            confidence = 0.60
        
        # severity_hint를 기반으로 confidence 조정
        if log_entry.severity_hint == "warning":
            confidence = min(confidence * 1.1, 1.0)
        elif log_entry.severity_hint == "critical":
            confidence = min(confidence * 1.2, 1.0)
        
        return {
            'attack_types': attack_types,
            'confidence': confidence,
            'model_used': 'distilbert-base-uncased'
        }

class HybridClassifier:
    """하이브리드 공격 분류기"""
    
    def __init__(self):
        self.rule_classifier = RuleBasedClassifier()
        self.ai_classifier = AIClassifier()
        self.attack_category_map = {
            'failed_login': 'authentication_attack',
            'brute_force_attempt': 'authentication_attack',
            'successful_login': 'successful_breach',
            'file_access': 'file_operation',
            'privilege_escalation': 'privilege_escalation',
            'data_exfiltration': 'data_theft',
            'process_execution': 'malware_activity'
        }
    
    def classify(self, log_entry: LogEntry) -> Classification:
        """규칙 기반과 AI 기반 분류를 결합"""
        # 규칙 기반 분류
        rule_result = self.rule_classifier.classify(log_entry)
        
        # AI 기반 분류
        ai_result = self.ai_classifier.classify(log_entry)
        
        # 결과 병합
        all_attack_types = list(set(
            rule_result['attack_types'] + 
            [self._normalize_attack_type(at) for at in ai_result['attack_types']]
        ))
        
        # parsing_confidence도 고려한 최종 신뢰도 계산
        combined_confidence = (
            rule_result['confidence'] * 0.5 + 
            ai_result['confidence'] * 0.3 +
            log_entry.parsing_confidence * 0.2
        )
        
        # 주요 카테고리 결정
        primary_category = self._determine_primary_category(all_attack_types)
        
        hybrid_result = {
            'final_attack_types': all_attack_types[:2],  # 상위 2개만
            'combined_confidence': round(combined_confidence, 2),
            'primary_category': primary_category
        }
        
        return Classification(
            event_id=log_entry.event_id,
            rule_based=rule_result,
            ai_based=ai_result,
            hybrid_result=hybrid_result
        )
    
    def _normalize_attack_type(self, attack_type: str) -> str:
        """AI 결과를 표준 공격 유형으로 변환"""
        mapping = {
            'authentication_failure': 'failed_login',
            'brute_force_attempt': 'brute_force_attempt',
            'successful_breach': 'successful_login',
            'authentication_success': 'successful_login',
            'file_access_violation': 'file_access',
            'privilege_abuse': 'privilege_escalation',
            'malicious_process': 'process_execution',
            'execution_attempt': 'process_execution',
            'file_operation': 'file_access',
            'data_access': 'file_access',
            'anomaly_detected': 'unknown'
        }
        return mapping.get(attack_type, attack_type)
    
    def _determine_primary_category(self, attack_types: List[str]) -> str:
        """주요 공격 카테고리 결정"""
        for attack_type in attack_types:
            if attack_type in self.attack_category_map:
                return self.attack_category_map[attack_type]
        return 'unknown_attack'