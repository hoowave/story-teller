# config.py (drop-in 교체)

from dataclasses import dataclass
from typing import Dict, List, Tuple

@dataclass
class AnalysisConfig:
    # 시간/버스트
    time_window_threshold: int = 300     # 5분
    burst_threshold: float = 2/60        # 분당 2개
    business_hours: Tuple[int, int] = (9, 19)  # 09~19시 가중 완화

    # 네트워크
    internal_networks: List[str] = None
    maintenance_windows: List[Tuple[int, int]] = None  # [(시작시, 끝시), ...]

    # 계정/화이트리스트
    admin_users: List[str] = None
    service_accounts: List[str] = None
    whitelist_hosts: List[str] = None   # 백업/EDR/배치 호스트 IP/서브넷 식별자 문자열

    # 파일 민감도(패턴→민감도)
    sensitive_files: Dict[str, float] = None

    # 축 가중치
    metric_weights: Dict[str, float] = None

    # 임계/보정
    sensitivity_thresholds: Dict[str, float] = None
    min_axes_for_alert: int = 2              # 최소 충족 축 수(게이트)
    single_signal_penalty: float = 0.2       # 단일 축만 높을 때 패널티
    orthogonality_bonus: float = 0.1         # 서로 다른 축 3개↑ 동시 히트 시 보너스
    parsing_confidence_floor: float = 0.6    # 평균 파싱 신뢰도 < floor면 감산

    def __post_init__(self):
        if self.internal_networks is None:
            self.internal_networks = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']

        if self.maintenance_windows is None:
            # 예: 01~03시는 백업/정비
            self.maintenance_windows = [(1, 3)]

        if self.admin_users is None:
            self.admin_users = ['admin', 'root', 'administrator']

        if self.service_accounts is None:
            self.service_accounts = ['backup', 'batch', 'svc_backup', 'svc_batch']

        if self.whitelist_hosts is None:
            self.whitelist_hosts = ['10.0.0.100', '10.0.0.101']  # 예시: 백업/EDR

        if self.sensitive_files is None:
            self.sensitive_files = {
                '/etc/': 0.9, '/root/': 1.0, '/var/log/': 0.8, '/home/': 0.6,
                'passwd': 1.0, 'shadow': 1.0, '.config': 0.7
            }

        if self.metric_weights is None:
            self.metric_weights = {'time': 0.25,'ip': 0.20,'user': 0.30,'file': 0.25}

        if self.sensitivity_thresholds is None:
            self.sensitivity_thresholds = {'low': 0.4,'medium': 0.6,'high': 0.8,'critical': 0.9}

DEFAULT_CONFIG = AnalysisConfig()
