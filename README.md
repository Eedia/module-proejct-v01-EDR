# module-proejct-v01-rename
sk rookies 모듈프로젝트(2) - 3조

# 경량 Windows EDR (스캐너형)

중소기업 환경에서 설치·운영 부담을 최소화한 원클릭 스캐너형 EDR 솔루션. 실행하면 단일 창(UI)이 뜨고 [분석 시작] 버튼을 누르면 그 시점의 보안 관련 아티팩트를 일괄 수집→룰 기반 분석→시각화→AI 가이드 생성까지 한 번에 수행합니다.

## 목차
- [개요](#개요)
- [주요 기능](#주요-기능)
- [프로젝트 구조](#프로젝트-구조)
- [설치 및 실행](#설치-및-실행)
- [사용법](#사용법)
- [기술 스택](#기술-스택)
- [역할 분담](#역할-분담)
- [개발 일정](#개발-일정)

## 개요

경량 Windows EDR은 실시간 센서나 서버형 대시보드 없이도 "지금 우리 PC가 안전한가?"를 즉시 진단할 수 있는 스냅샷 점검 도구입니다.

### 핵심 특징
- **원클릭 점검**: 버튼 한 번으로 수집→분석→결과 표시
- **룰 기반 탐지**: 단순·명확한 체크리스트와 가중치로 위험 점수(100점) 산출
- **AI 기반 조치 가이드**: 발견 항목별 PowerShell 조치/검증/롤백 스크립트 제안
- **자연어 질의**: "지난 24h 관리자 RDP?" 같은 질문으로 결과 필터링
- **경량 배포**: PyInstaller 기반 단일 실행 파일

### 동작 방식
- **플랫폼**: Windows 10/11/Server 2019+
- **언어**: Python 3.9+
- **동작 형태**: 스냅샷 점검(온디맨드)
- **저장 방식**: 메모리+파일 출력(JSON/HTML/PDF, 옵션: PS1 내보내기)

## 주요 기능

### 1. 보안 아티팩트 수집
- **이벤트 로그**: Security, System, PowerShell 등 최근 24시간 로그 수집
- **레지스트리 분석**: 자동실행, 서비스, 보안 설정 상태 점검
- **시스템 상태**: RDP/방화벽 설정, Defender 상태, Windows 업데이트 등

### 2. 룰 기반 탐지 및 점수화
- **LOLBin 실행**: rundll32, regsvr32, mshta, powershell 의심 활동 탐지
- **계정/로그온 분석**: 비업무시간 로그온, RDP 원격 접속 등
- **지속성 메커니즘**: 신규 서비스, 자동실행 항목 변경 탐지
- **점수화 시스템**: 100점 감점형, 90점 이상(양호)/70점 이상(주의)/60점 미만(경고)

### 3. AI for Security
- **AI Remediator**: 발견 항목별 PowerShell 조치/검증/롤백 스크립트 제안 (복사 전용)
- **Ask your Scan**: 자연어 질문으로 점검 결과 필터/검색/설명
- **명령줄 해석기**: 난독화된 인자/플래그 설명 (선택 기능)

### 4. 리포팅
- **Executive Summary**: 점수, Top3 위험 항목 요약
- **상세 분석**: 항목별 결과, 근거 이벤트, AI 조치 가이드
- **다중 포맷**: HTML/PDF 리포트, PowerShell 스크립트 내보내기

## 프로젝트 구조

```
EDR/
├── evtx/                         # 이벤트 로그 수집 및 파싱
│   ├── collector.py              # 이벤트 로그 수집기 (EvtQuery/wevtutil)
│   ├── parser.py                 # EVTX 파일 파싱 및 정규화
│   ├── event_analyzer.py         # 이벤트 로그 분석 룰
│   └── __init__.py
│
├── reg/                          # 레지스트리 분석
│   ├── registry_collector.py     # 레지스트리 키/값 수집
│   ├── autorun_analyzer.py       # 자동실행 항목 분석
│   ├── service_analyzer.py       # 서비스 등록 분석
│   ├── security_settings.py      # 보안 설정 상태 점검
│   └── __init__.py
│
├── utils/                        # 공통 유틸리티
│   ├── data_normalizer.py        # 데이터 정규화 및 변환
│   ├── file_handler.py           # 파일 입출력 처리
│   ├── system_info.py            # 시스템 정보 수집
│   ├── scoring_engine.py         # 점수화 엔진
│   ├── rule_engine.py            # 룰 엔진 및 매칭
│   └── __init__.py
│
├── llm/                          # AI/LLM 관련 기능
│   ├── ai_remediator.py          # AI 조치 스크립트 생성
│   ├── ask_your_scan.py          # 자연어 질의 처리
│   ├── command_interpreter.py    # 명령줄 해석기 (선택)
│   ├── prompt_templates.py       # AI 프롬프트 템플릿
│   └── __init__.py
│
├── ui/                           # 사용자 인터페이스
│   ├── main_window.py            # PyQt5 메인 윈도우
│   ├── dashboard.py              # 대시보드 위젯
│   ├── report_viewer.py          # 리포트 뷰어
│   ├── ai_chat.py                # AI 채팅 인터페이스
│   └── __init__.py
│
├── core/                         # 핵심 엔진
│   ├── scanner_engine.py         # 메인 스캐너 엔진
│   ├── orchestrator.py           # 작업 오케스트레이션
│   ├── data_collector.py         # 통합 데이터 수집기
│   └── __init__.py
│
├── config/                       # 설정 파일
│   ├── rules.json                # 탐지 룰 정의
│   ├── scoring_profile.json      # 점수화 프로필
│   ├── config.yaml               # 애플리케이션 설정
│   └── api_keys.env              # API 키 (gitignore)
│
├── templates/                    # 리포트 템플릿
│   ├── report_template.html      # HTML 리포트 템플릿
│   └── summary_template.html     # 요약 리포트 템플릿
│
├── output/                       # 출력 결과 저장
│   ├── scan_results/             # 스캔 결과 JSON
│   ├── reports/                  # HTML/PDF 리포트
│   └── scripts/                  # 생성된 PS1 스크립트
│
├── tests/                        # 테스트 코드
│   ├── test_evtx/
│   ├── test_reg/
│   ├── test_utils/
│   ├── test_llm/
│   └── test_integration/
│
├── requirements.txt              # 의존성 패키지
├── main.py                       # 애플리케이션 진입점
├── build.py                      # PyInstaller 빌드 스크립트
├── README.md                     # 프로젝트 문서
└── .gitignore                    # Git 제외 파일
```

## 설치 및 실행

### 사전 요구사항
- **운영체제**: Windows 10/11/Server 2019+
- **Python**: 3.9.13 이상
- **권한**: 관리자 권한 (이벤트 로그 및 레지스트리 접근)

### 개발 환경 설정
```bash
# 저장소 클론
git clone <repository-url>
cd module-project-v01-EDR/EDR

# 가상환경 생성
python -m venv .venv
.venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정 (config/api_keys.env)
OPENAI_API_KEY=your_openai_api_key_here
```

### 실행 방법
```bash
# 개발 모드
python main.py

# 빌드된 실행 파일
python build.py  # EDR-Scanner.exe 생성
./EDR-Scanner.exe
```

## 사용법

### 기본 스캔
1. 애플리케이션 실행
2. [분석 시작] 버튼 클릭
3. 스캔 진행 상황 모니터링
4. 결과 대시보드에서 위험 항목 확인
5. AI 조치 제안 확인 및 스크립트 복사

### AI 질의 (Ask your Scan)
```
"지난 24시간 관리자 RDP 접속은?"
"regsvr32 외부 호출이 있었나?"
"신규 서비스 설치 내역을 보여줘"
```

### 리포트 생성
- HTML 리포트: 상세 분석 결과 및 시각화
- PDF 리포트: Executive Summary 포함
- PowerShell 스크립트: AI 추천 조치 스크립트

## 기술 스택

### 핵심 기술
- **Python 3.9+**: 메인 개발 언어
- **PyQt5**: GUI 프레임워크
- **OpenAI GPT-4**: AI 기반 분석 및 조치 제안
- **Windows API**: 이벤트 로그 및 레지스트리 접근

### 주요 라이브러리
- **python-evtx**: 이벤트 로그 파싱
- **winreg**: 레지스트리 접근
- **jinja2**: 리포트 템플릿 엔진
- **pyinstaller**: 실행 파일 빌드
- **pandas**: 데이터 처리 및 분석

## 역할 분담

| 역할 | 담당자 | 주요 책임 | 산출물 |
|------|--------|-----------|--------|
| **PM/아키텍트** | 오준서 | 요구사항 정의, 아키텍처 설계, 일정 관리 | 아키텍처 다이어그램, 데모 시나리오 |
| **이벤트 로그 수집** | 오준서 | evtx/ 모듈 구현, 이벤트 로그 파싱 | collector.py, parser.py |
| **레지스트리 분석** | 고보경 | reg/ 모듈 구현, 시스템 설정 분석 | registry_collector.py, analyzers |
| **LLM/AI 기능** | 이윤지 | llm/ 모듈 구현, AI 기반 분석/조치 | ai_remediator.py, ask_your_scan.py |
| **UI/UX 개발** | 최민정 | ui/ 모듈 구현, PyQt5 인터페이스 | main_window.py, dashboard.py |
| **자료 정리/통합** | 최우창 | 문서화, 테스트 | 문서, 테스트 코드, 빌드 스크립트 |

## 개발 일정

### Day 1 - 스캐너 뼈대 (수요일)
- **목표**: 핵심 기능 구현 및 통합
- **이벤트 로그**: 수집/파싱 함수 → findings.json 생성
- **레지스트리**: 자동실행/서비스/보안설정 수집
- **LLM**: AI Remediator v1 (프롬프트·스키마·폴백)
- **UI**: PyQt5 기본 레이아웃, 버튼 기능
- **통합**: 데모 시나리오 3건 확정

### Day 2 - 폴리싱/리포트/배포 (목요일)
- **목표**: 완성도 향상 및 배포 준비
- **안정성**: 권한/에러 처리, 성능 튜닝
- **품질**: 룰 튜닝, 중복 억제, 임계값 조정
- **리포트**: HTML/PDF 생성, 아이콘/색상
- **배포**: PyInstaller 빌드, 테스트

### (선택) Day 3 - 고급 기능 (금요일)
- **Ask your Scan**: 자연어 질의 기능
- **명령줄 해석기**: 난독화 스크립트 분석
- **UI 개선**: 대화 탭, 검색 기능

---

**개발 환경**: VSCode + Git 브랜치 관리  
**프로젝트 경로**: `E:\module2\module-project-v01-EDR\EDR\`  
**목표**: 중소기업을 위한 실용적이고 직관적인 EDR 스캐너 개발