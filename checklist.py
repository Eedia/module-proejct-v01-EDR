# 추출할 경로 설정
paths_to_extract = [
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows NT\\CurrentVersion",
        "filename": "1. 시스템 정보",
        "recurse": False,
        "message": "Windows 운영 체제의 버전, 설치 날짜, 빌드 번호 등 시스템의 기본 정보를 확인할 수 있는 경로입니다. 디지털 포렌식에서는 사건 발생 당시 시스템의 OS 환경을 파악하는 데 활용됩니다.\n\n확인할 주요 값:\n- **`ProductName`**: 설치된 Windows의 이름 (예: Windows 10 Pro). 이를 통해 시스템이 어떤 OS를 실행 중인지 확인할 수 있습니다.\n- **`CurrentVersion`**: Windows의 현재 버전 번호 (예: 10.0). OS의 정확한 버전을 파악할 때 유용합니다.\n- **`CurrentBuildNumber`**: Windows의 빌드 번호 (예: 19044). 특정 빌드의 보안 패치 여부나 취약점을 분석할 수 있습니다.\n- **`InstallDate`**: 시스템이 설치된 날짜를 나타내는 Unix 타임스탬프. 이를 통해 시스템 사용 기간과 초기 설치 시점을 분석할 수 있습니다.",
        "values": ["ProductName", "CurrentVersion", "CurrentBuildNumber", "InstallDate"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "filename": "2. 설치된 프로그램 목록",
        "recurse": True,
        "message": "시스템에 설치된 프로그램 목록과 관련된 정보를 확인할 수 있는 경로입니다. 포렌식 분석 시 사용자가 설치한 프로그램과 의심스러운 소프트웨어를 탐지하는 데 유용합니다.\n\n확인할 주요 값:\n- **`DisplayName`**: 프로그램의 이름 (예: Google Chrome). 사용자가 어떤 프로그램을 설치했는지 파악할 수 있습니다.\n- **`InstallDate`**: 프로그램이 설치된 날짜. 특정 프로그램의 설치 시점을 확인해 사건의 시나리오를 재구성할 수 있습니다.\n- **`Publisher`**: 프로그램의 발행자 (예: Microsoft Corporation). 프로그램이 신뢰할 수 있는 출처에서 제공되었는지 여부를 확인할 수 있습니다.\n- **`Version`**: 프로그램의 버전. 소프트웨어의 버전 정보를 통해 보안 취약점이 있는지 확인할 수 있습니다.",
        "values": ["DisplayName", "InstallDate", "Publisher", "Version"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "path": "ControlSet001\\Control\\ComputerName\\ComputerName",
        "filename": "3. 컴퓨터이름",
        "recurse": False,
        "message": "현재 시스템의 컴퓨터 이름이 저장된 경로입니다. 네트워크 분석 시 특정 컴퓨터를 식별할 때 사용됩니다.\n\n확인할 주요 값:\n- **`ComputerName`**: 시스템의 컴퓨터 이름. 이 값은 네트워크 로그와 비교하여 특정 컴퓨터를 식별하는 데 사용됩니다.",
        "values": ["ComputerName"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-18",
        "filename": "4. SID정보",
        "recurse": False,
        "message": "각 사용자 계정의 보안 식별자(SID)와 관련된 정보가 저장된 경로입니다. 사용자 계정 활동을 추적할 때 유용합니다. 이 경로는 Windows 시스템에 등록된 사용자 계정의 SID 목록을 포함하고 있으며, 각 SID 아래에는 사용자 프로필 정보가 저장됩니다.\n\n각 SID의 의미:\n- **`S-1-5-18`**: Local System 계정으로, Windows 시스템의 내부 작업에 사용됩니다.\n- **`S-1-5-19`**: Local Service 계정으로, 제한된 권한으로 시스템 서비스를 실행할 때 사용됩니다.\n- **`S-1-5-20`**: Network Service 계정으로, 네트워크 관련 서비스를 실행할 때 사용됩니다.\n- **`S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxx-1000`**: 표준 사용자 계정으로, 마지막 숫자가 1000 이상인 경우가 많습니다. 이는 사용자별 고유한 계정을 나타냅니다.\n- **`S-1-5-32-544`**: Administrators 그룹으로, 관리자 권한을 가진 계정을 포함합니다.\n\n확인할 주요 값:\n- **`ProfileImagePath`**: 각 SID에 연결된 사용자 계정의 프로필 경로 (예: `C:\\Users\\user`). 특정 사용자의 활동 내역을 추적하고, 해당 경로에 저장된 파일을 분석할 수 있습니다.",
        "values": ["ProfileImagePath"]
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "filename": "5. 사용자 기본 폴더",
        "recurse": False,
        "message": "현재 사용자가 설정한 기본 폴더의 경로를 확인할 수 있는 경로입니다. 파일 접근 기록 분석 시 기본 폴더 정보를 확인하여 경로를 추적할 수 있습니다.\n\n확인할 주요 값:\n- **`Desktop`**: 바탕화면의 경로 (예: `C:\\Users\\user\\Desktop`). 사용자 바탕화면의 파일을 조사할 때 사용됩니다.\n- **`Personal`**: 문서 폴더의 경로 (예: `C:\\Users\\user\\Documents`). 사용자가 저장한 문서 파일의 위치를 확인할 수 있습니다.",
        "values": ["Desktop", "Personal"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "filename": "6. 마지막 로그인한 사용자 정보",
        "recurse": False,
        "message": "마지막으로 로그인한 사용자 정보가 저장된 경로입니다. 보안 분석 시 어떤 계정이 시스템에 접속했는지 확인할 수 있습니다.\n\n확인할 주요 값:\n- **`DefaultUserName`**: 자동 로그인 시 사용하는 기본 사용자 이름.\n- **`LastUsedUsername`**: 마지막으로 시스템에 로그인한 사용자 이름. 이를 통해 사건 발생 당시 시스템에 접속한 사용자를 파악할 수 있습니다.",
        "values": ["DefaultUserName", "LastUsedUsername"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "path": "ControlSet001\\Control\\Windows",
        "filename": "7. 시스템 마지막 종료시간",
        "recurse": False,
        "message": "시스템의 마지막 정상 종료 시각을 확인할 수 있는 경로입니다. 예기치 않은 종료 여부를 분석할 때 유용합니다.\n\n확인할 주요 값:\n- **`ShutdownTime`**: 시스템 마지막 종료 시각의 타임스탬프 (바이너리 값). 이를 변환하여 사건 발생 시점에 시스템이 정상적으로 종료되었는지 여부를 확인할 수 있습니다.",
        "values": ["ShutdownTime"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "path": "ControlSet001\\Control\\TimeZoneInformation",
        "filename": "8. 표준 시간대",
        "recurse": False,
        "message": "시스템의 표준 시간대 정보가 포함된 경로입니다. 로그 분석 및 사건의 정확한 시간 해석 시 중요합니다.\n\n확인할 주요 값:\n- **`TimeZoneKeyName`**: 현재 설정된 시간대 이름 (예: `Pacific Standard Time`). 로그 파일의 타임스탬프 해석 시 필요합니다.\n- **`ActiveTimeBias`**: 시간대 오프셋 값으로, 타임스탬프를 올바르게 해석하기 위해 사용됩니다.",
        "values": ["TimeZoneKeyName", "ActiveTimeBias"]
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
        "filename": "9. 응용 프로그램 사용 흔적",
        "recurse": True,
        "message": "사용자가 실행한 응용 프로그램의 사용 흔적이 기록된 경로입니다. 최근 사용자 활동을 추적하여 사건과 관련된 행동을 분석할 수 있습니다.\n\n추가 설명: UserAssist 값은 암호화된 형태로 저장되어 있어 해독이 필요합니다. 프로그램의 실행 횟수와 마지막 실행 시간을 분석할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
        "filename": "10. 검색기 이용 검색어 목록",
        "recurse": False,
        "message": "Windows 탐색기에서 사용자가 입력한 검색어가 저장된 경로입니다. 특정 파일이나 정보를 찾으려는 시도를 분석할 수 있습니다.\n\n추가 설명: 사용자가 어떤 키워드를 탐색했는지 분석하여 특정 파일이나 정보에 대한 탐색 시도를 확인할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "filename": "11. 최근 열어본 파일 흔적",
        "recurse": False,
        "message": "사용자가 최근에 열어본 파일 목록이 기록된 경로입니다. 사용자 활동 추적 및 특정 시점의 파일 접근 여부를 분석할 수 있습니다.\n\n추가 설명: 특정 파일을 언제 열어봤는지를 분석하여 사건 시점에 대한 중요한 단서를 제공합니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "filename": "12. 최근 실행창 검색 흔적",
        "recurse": False,
        "message": "사용자가 실행 창에 입력한 명령어 목록이 저장된 경로입니다. 프로그램 실행 내역을 분석할 수 있습니다.\n\n추가 설명: 사용자가 어떤 프로그램이나 명령어를 실행했는지 확인하여 특정 시점의 활동을 분석할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER\\SOFTWARE\\Classes",
        "path": "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "filename": "13. 사용한 프로그램의 창 제목",
        "recurse": False,
        "message": "사용자가 실행한 프로그램의 창 제목이 저장된 경로입니다. 어떤 프로그램이 사용되었는지 확인하는 데 유용합니다.\n\n추가 설명: 프로그램의 창 제목은 사용자가 어떤 작업을 했는지에 대한 단서를 제공합니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        "filename": "14. 탐색기 주소 창에 입력한 경로 리스트",
        "recurse": False,
        "message": "Windows 탐색기 주소 창에 사용자가 입력한 경로가 저장된 경로입니다. 특정 경로나 폴더 접근 시도를 분석할 수 있습니다.\n\n추가 설명: 특정 경로나 폴더에 접근한 기록을 분석하여 사용자가 최근에 접근한 경로를 파악할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        "filename": "15. 최근 읽거나 저장한 파일 목록",
        "recurse": True,
        "message": "사용자가 최근에 열거나 저장한 파일 목록이 기록된 경로입니다. 파일 접근 활동을 확인할 수 있어 사건과 관련된 파일을 찾을 때 유용합니다.\n\n추가 설명: 사용자가 열거나 저장한 파일의 시점과 파일명을 분석하여 중요한 증거를 확인할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "path": "ControlSet001\\Services",
        "filename": "16. 서비스 및 드라이버 목록",
        "recurse": True,
        "message": "시스템에 설치된 서비스 및 드라이버의 목록이 포함된 경로입니다. 악성코드 탐지 및 시스템 부팅 시 자동 실행 항목을 파악할 수 있습니다.\n\n확인할 주요 값:\n- **`DisplayName`**: 서비스의 표시 이름. 시스템에 설치된 서비스 목록을 파악할 수 있습니다.\n- **`ImagePath`**: 서비스의 실행 파일 경로. 서비스가 정상적인 경로에 있는지, 또는 의심스러운 경로에 있는지를 확인할 수 있습니다.",
        "values": ["DisplayName", "ImagePath"]
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs",
        "filename": "17. 타이핑한 URL 목록",
        "recurse": False,
        "message": "Internet Explorer에서 사용자가 입력한 URL 목록이 저장된 경로입니다. 웹 활동 추적 시 사용됩니다.\n\n확인할 주요 값:\n- **`url1`, `url2` 등**: 사용자가 입력한 URL 주소. 웹 활동을 추적하여 특정 사이트 방문 여부를 파악할 수 있습니다.",
        "values": ["url1", "url2"]
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MenuOrder\\Favorites\\Links",
        "filename": "18. 즐겨찾기 목록",
        "recurse": False,
        "message": "Windows 탐색기 즐겨찾기 목록이 저장된 경로입니다. 사용자가 자주 방문하는 웹사이트를 파악할 수 있습니다.\n\n추가 설명: 사용자의 관심 웹사이트와 자주 방문하는 사이트 목록을 분석할 수 있습니다.",
        "values": []
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "filename": "19. 부팅 시 자동 실행 되는 SW 흔적",
        "recurse": False,
        "message": "시스템 부팅 시 자동으로 실행되는 프로그램 목록이 저장된 경로입니다. 보안 분석 시 악성 소프트웨어 탐지에 사용됩니다.\n\n확인할 주요 값:\n- **각 프로그램 이름**: 프로그램이 실행되는 파일 경로. 악성코드가 부팅 시 자동 실행되도록 설정된 경우 이를 탐지할 수 있습니다.",
        "values": ["*"]
    },
    
    # {
    #     "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
    #     "path": "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    #     "filename": "20. 부팅 시 자동 실행 되는 SW 흔적",
    #     "recurse": False,
    #     "message": "시스템 부팅 시 자동 실행되는 32비트 소프트웨어가 저장된 경로입니다. 보안 분석 시 악성 소프트웨어 탐지에 유용합니다.\n\n확인할 주요 값:\n- **각 프로그램 이름**: 32비트 소프트웨어의 실행 파일 경로. 의심스러운 자동 실행 항목을 확인할 수 있습니다.",
    #     "values": ["*"]
    # },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "filename": "20. 부팅 시 자동 실행 되는 SW 흔적",
        "recurse": False,
        "message": "현재 사용자의 프로필에서 시스템 부팅 시 자동으로 실행되는 프로그램 목록이 저장된 경로입니다. 사용자 계정과 관련된 부팅 시 자동 실행 소프트웨어를 파악할 수 있습니다.\n\n확인할 주요 값:\n- **각 프로그램 이름**: 현재 사용자 계정에 설정된 자동 실행 프로그램의 경로. 사용자가 인지하지 못한 프로그램이 자동 실행되도록 설정되어 있는지 확인할 수 있습니다.",
        "values": ["*"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Command Processor",
        "filename": "21. 명령프롬프트 실행 시 자동 시작되는 SW",
        "recurse": False,
        "message": "명령 프롬프트 실행 시 자동으로 실행되는 소프트웨어가 저장된 경로입니다. 악성코드가 설정된 경우 탐지할 수 있습니다.\n\n확인할 주요 값:\n- **`AutoRun`**: 명령 프롬프트 실행 시 자동으로 실행되는 명령어. 악성 스크립트가 자동 실행되도록 설정된 경우 이를 탐지할 수 있습니다.",
        "values": ["AutoRun"]
    },
    
    {
        "hive": "HKEY_CURRENT_USER",
        "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit",
        "filename": "22. 레지스트리 편집기에서 마지막으로 접근한 키에 대한 정보",
        "recurse": False,
        "message": "사용자가 레지스트리 편집기에서 마지막으로 접근한 키에 대한 정보가 저장된 경로입니다. 사용자가 최근에 어떤 레지스트리 키를 변경했는지 분석할 수 있습니다.\n\n확인할 주요 값:\n- **`LastKey`**: 사용자가 마지막으로 접근한 레지스트리 키 경로. 사용자가 최근에 변경하거나 확인한 설정을 분석할 수 있습니다.",
        "values": ["LastKey"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "path": "Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "filename": "23. User Account Control (UAC) 시스템 보안 및 권한 제어 정책 설정 확인",
        "recurse": False,
        "message": "User Account Control (UAC)과 관련된 시스템 보안 및 권한 설정이 저장된 경로입니다. 시스템 보안 수준을 분석하고 권한 상승 시도를 탐지하는 데 유용합니다.\n\n확인할 주요 값:\n- **`EnableLUA`**: UAC 기능 활성화 여부 (1: 활성화, 0: 비활성화). 시스템 보안 설정을 확인할 수 있습니다.\n- **`ConsentPromptBehaviorAdmin`**: 관리자 권한 요청 시 동작 방식 (예: 5: 동의 필요, 0: 동의 없음). 권한 상승 공격 여부를 파악할 수 있습니다.",
        "values": ["EnableLUA", "ConsentPromptBehaviorAdmin"]
    },
    
    {
        "hive": "HKEY_LOCAL_MACHINE\\SYSTEM",
        "path": "ControlSet001\\Services\\EventLog\\Security",
        "filename": "24. Security 이벤트 로그 maxSize 확인",
        "recurse": False,
        "message": "보안 이벤트 로그의 최대 크기 설정이 저장된 경로입니다. 로그 조작 여부를 파악하고 사건 발생 시 보안 로그 분석에 활용할 수 있습니다.\n\n확인할 주요 값:\n- **`MaxSize`**: 보안 이벤트 로그의 최대 크기 설정. 로그가 특정 크기 이상으로 커지지 않도록 설정되었는지 확인하여, 로그 조작 시도를 파악할 수 있습니다.",
        "values": ["MaxSize"]
    }
]