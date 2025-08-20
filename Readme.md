# story-teller team project!!!

## 1. Front => Streamlit
## 2. Back => FastAPI

### 디렉터리 구조
```
story-teller/
│
├── backend/                                      # 백엔드 서버 코드
│   ├── .env                                      # 환경 변수 설정 (API 키, DB 연결 정보 등)
│   ├── main.py                                   # FastAPI 애플리케이션 진입점
│   │
│   ├── facade/                                   # 외부 서비스 연동 추상화 계층
│   │   └── open_ai_agent.py                      # OpenAI API 연동 및 프롬프트 관리
│   │
│   ├── interfaces/                               # API 엔드포인트 및 DTO 정의
│   │   ├── controller.py                         # 요청 처리 컨트롤러
│   │   └── dto/                                  # 데이터 전송 객체
│   │       ├── request_dto.py                    # API 요청 스키마
│   │       └── response_dto.py                   # API 응답 스키마
│   │
│   └── service/                                  # 비즈니스 로직 계층
│       ├── service.py                            # 핵심 서비스 로직
│       │
│       ├── anomaly/                              # 이상 탐지 모듈
│       │   ├── realtime_detector.py              # 실시간 이상 탐지 로직
│       │   ├── realtime_cluster_engine.py        # 새로 추가: 실시간 클러스터링 엔진
│       │   └── router.py                         # 이상 탐지 API 라우터
│       │
│       └── preprocessor/                         # 로그 전처리 모듈
│           ├── __init__.py                       # 패키지 초기화
│           ├── main.py                           # 전처리 모듈 실행 진입점
│           ├── api.py                            # /ingest 엔드포인트 라우터
│           ├── extractors.py                     # 엔티티 추출 및 힌트 추론
│           ├── parsers.py                        # 로그 형식 파서 (CSV, 텍스트)
│           ├── schema.py                         # Pydantic 모델 정의
│           ├── scenario.zip                      # 시나리오 파일 압축본
│           │
│           └── scenario/                         # 테스트 시나리오 데이터
│               ├── External_Intrusion_Type/      # 외부 침입 시나리오
│               │   ├── auth_log.csv
│               │   ├── db_log.csv
│               │   ├── firewall_log.csv
│               │   ├── proxy_log.csv
│               │   ├── waf_log.csv
│               │   └── web_log.csv
│               │
│               └── Internal_Diffusion_Type/      # 내부 확산 시나리오
│                   ├── db_log.csv
│                   ├── dns_log.csv
│                   ├── edr_log.csv
│                   ├── firewall_log.csv
│                   └── proxy_log.csv
│
├── frontend/                # 프론트엔드 애플리케이션
│   └── main.py              # 프론트엔드 진입점 (Streamlit)
│
├── .gitignore               # Git 무시 파일 설정
└── Readme.md                # 프로젝트 설명 문서
```
### /backend/service/preprocessor/main.py 실행 방법
```
python -m backend.service.preprocessor.main --input <input_path> --full --save-json <output_path>

ex. python -m backend.service.preprocessor.main --input "backend\service\preprocessor\scenario.zip" --full --save-json "out"
    python -m backend.service.preprocessor.main --input "backend\service\preprocessor\scenario\External_Intrusion_Type\auth_log.csv" --full --save-json "auth_log_out"
```
