# story-teller team project!!!

### 1. Front => Streamlit
### 2. Back => FastAPI
- 디렉터리 구조
```
├── backend
│   ├─ main.py                           # FastAPI 엔트리포인트 (라우터 include)
│   ├─ facade/                           # facade 패키지
│   │  └─ open_ai_agent.py               # OpenAI Agent
│   ├─ interfaces/                       # interfaces 패키지
│   │  ├─ controller.py                  # 컨트롤러
│   │  └─ dto/                           # dto 패키지
│   │     ├─ request_dto.py              # 요청 dto
│   │     └─ response_dto.py             # 응답 dto
│   └─ service/                          # service 패키지
│       ├─ service.py                    # 서비스
│       └─ preprocessor/                 # Stage-1 로그 전처리 모듈
│       │  ├─ __init__.py                # (패키지 인식용; router export 선택)
│       │  ├─ schema.py                  # Pydantic 모델: Entities, Event
│       │  ├─ extractors.py              # iso/safe_ip/extract_entities/infer_hints
│       │  ├─ parsers.py                 # parse_text, parse_csv
│       │  └─ api.py                     # APIRouter: POST /v1/ingest
├── frontend
│   ├── app
│   │   ├── components
│   │   ├── pages
│   │   └── utils
│   └── streamlit_app.py
├── README.md
└── requirements.txt
```
