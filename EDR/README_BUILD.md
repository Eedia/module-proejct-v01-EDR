# EDR Scanner 빌드 가이드

## 개요
PyInstaller를 사용하여 EDR Scanner를 단일 실행 파일(.exe)로 빌드합니다.

## 빌드 환경 요구사항
### 의존성 버전 (고정)
```txt
PyQt6==6.9.1
PyQt6-Charts==6.9.0
qt-material==2.17
psutil==7.0.0
python-dotenv==1.1.1
json-repair==0.50.0
google-generativeai==0.8.5
pyinstaller==6.15.0
pywin32>=306 ; sys_platform == "win32"
```

- **OS**: Windows 10/11 또는 Windows Server 2019+
- **Python**: 3.8 이상 (권장: 3.9-3.11)
- **관리자 권한**: 일부 시스템 정보 수집을 위해 필요

## 빌드 방법

### 방법 1: 배치 파일 사용 (권장)
```batch
# 1. 자동 빌드 (의존성 설치 + 빌드 + 포터블 패키지 생성)
build.bat

# 2. 빌드 정리만
clean.bat
```

### 방법 2: Python 스크립트 직접 사용
```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. 기본 빌드
python build.py

# 3. 포터블 패키지 포함 빌드
python build.py --portable

# 4. 빌드 전 정리 생략
python build.py --no-clean

# 5. 디버그 모드 빌드
python build.py --debug

# 6. Spec 파일만 생성
python build.py --spec-only

# 7. 정리만 수행
python build.py --clean-only
```

## 빌드 옵션 설명

### 기본 빌드 설정
- **이름**: EDR-Scanner.exe
- **타입**: 단일 파일 (--onefile)
- **콘솔**: 숨김 (GUI 애플리케이션)
- **압축**: UPX 사용

### 포함되는 데이터 파일
- `ui/main_window.ui` - 메인 UI 파일
- `ui/templates/*` - UI 템플릿들
- `config/config.yaml` - 설정 파일
- `rules/detection_rules.json` - 탐지 룰
- `rules/scoring_weights.json` - 점수 가중치
- `templates/*` - 리포트 템플릿

### Hidden Imports / Data Collection
- 빌드 스크립트에서 `--collect-all=qt_material` 옵션을 사용해 테마/리소스를 수집합니다.

### Hidden Imports (자동 포함)
- PyQt6 관련 모듈
- qt_material
- Windows API (pywin32)
- Google Generative AI
- JSON 처리 모듈

### 제외되는 모듈 (크기 최적화)
- matplotlib, scipy, jupyter 등 불필요한 대용량 모듈

## 빌드 결과물

### 디렉토리 구조
```
dist/
├── EDR-Scanner.exe                 # 메인 실행 파일
├── README.md                       # 사용 설명서 (복사됨)
├── .env.example                    # 환경 변수 예제 (복사됨)
└── EDR-Scanner_Portable/           # 포터블 패키지 (--portable 옵션)
    ├── EDR-Scanner.exe
    ├── config/
    │   └── config.yaml
    ├── README.md
    ├── .env.example
    └── 사용설명서.txt
```

### 파일 크기
- 일반적으로 80-150MB 내외 (의존성에 따라 변동)
- UPX 압축 적용으로 크기 최적화

## 사용법

### 개발자용 빌드 (디버깅)
```bash
# 디버그 모드로 빌드
python build.py --debug

# 문제 발생 시 로그 확인
# build/ 폴더의 로그 파일 참조
```

### 배포용 빌드
```bash
# 포터블 패키지 포함 릴리즈 빌드
python build.py --portable
```

### 빌드 문제 해결
```bash
# 완전 정리 후 재빌드
python build.py --clean-only
python build.py --portable
```

## 트러블슈팅

### 자주 발생하는 문제

#### 1. 모듈 import 오류
**증상**: 실행 시 "ModuleNotFoundError" 발생
**해결**: `build.py`의 `hidden_imports`에 누락된 모듈 추가

#### 2. 데이터 파일 없음 오류
**증상**: 실행 시 UI 파일 또는 설정 파일을 찾을 수 없음
**해결**: `data_files` 리스트에 필요한 파일 경로 추가

#### 3. 빌드 실패
**증상**: PyInstaller 실행 중 오류
**해결**:
```bash
# 정리 후 재시도
python build.py --clean-only
python -m pip install -r requirements.txt
python build.py
```

#### 4. 실행 파일 크기 과대
**증상**: 200MB 이상의 큰 실행 파일
**해결**: `exclude_modules`에 불필요한 모듈 추가

#### 5. Windows Defender 오탐
**증상**: 실행 파일이 바이러스로 오탐지
**해결**: 
- 코드 사이닝 인증서 사용
- 또는 백신 예외 설정

## 배포 전 체크리스트

- [ ] 빌드 성공 확인
- [ ] 실행 파일 정상 동작 확인
- [ ] 모든 기능 테스트 (분석, UI, 리포트 생성)
- [ ] 다른 Windows 환경에서 테스트
- [ ] 관리자 권한으로 실행 테스트
- [ ] 포터블 패키지 압축 및 배포 준비

## 고급 설정

### 아이콘 추가
```python
# build.py에서 수정
BUILD_CONFIG = {
    "icon": "assets/edr_icon.ico",  # 아이콘 파일 경로
    # ...
}
```

### 버전 정보 추가
```python
# build.py에서 수정
BUILD_CONFIG = {
    "version_file": "version_info.txt",  # 버전 정보 파일
    # ...
}
```

### 사용자 정의 빌드 설정
`build.py` 파일의 `BUILD_CONFIG` 딕셔너리를 수정하여 빌드 옵션을 커스터마이징할 수 있습니다.

## 성능 최적화

### 빌드 시간 단축
- `--no-clean` 옵션으로 정리 과정 생략
- `--spec-only`로 spec 파일만 생성 후 수동으로 pyinstaller 실행

### 실행 파일 크기 최적화
- 불필요한 모듈을 `exclude_modules`에 추가
- UPX 압축률 조정
- 데이터 파일 최소화

---

## 문의 및 지원
빌드 관련 문제 발생 시 개발팀에 문의하거나 이슈 트래커를 활용해주세요.
