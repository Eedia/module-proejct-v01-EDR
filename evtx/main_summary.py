import re
from datetime import datetime

def convert_to_am_pm(time_str):
    """
    UTC 시간 문자열을 입력 받아 오전/오후 형식으로 변환하는 함수
    """
    try:
        dt = datetime.strptime(time_str.split('.')[0], '%Y-%m-%dT%H:%M:%S')
        formatted_time = dt.strftime('%Y-%m-%d %p %I:%M:%S')  # 오전/오후 형식으로 변환
        formatted_time = formatted_time.replace("AM", "오전").replace("PM", "오후")  # AM/PM을 한글로 변환
        return formatted_time
    except ValueError:
        return time_str  # 변환이 실패한 경우 원본 시간 문자열을 반환

def preprocess_description_by_log_event_source(log_name: str, event_id: str, source: str, description: str) -> str:
    """
    Log Name, Event ID, Source에 따라 Description을 전처리하는 함수.
    """
    processed_description = description

    if log_name == "System" and event_id == "1" and source == "Microsoft-Windows-Kernel-General":
        # 시스템 시간이 2024-04-03T13:06:41.488004100Z. 패턴 추출 및 변환
        match = re.search(r'시스템 시간이\s+([0-9\-T:\.]+Z)', description)
        if match:
            original_time = match.group(1)
            am_pm_time = convert_to_am_pm(original_time)
            processed_description = processed_description.replace(original_time, am_pm_time)

        # 시간 델타에서 변경된 시간 패턴 추출 및 변환
        match = re.search(r'시간 델타에서\s+([0-9\-T:\.]+Z)\s+변경', description)
        if match:
            original_time = match.group(1)
            am_pm_time = convert_to_am_pm(original_time)
            processed_description = processed_description.replace(original_time, am_pm_time)

     # Event ID가 12 또는 13일 때 시간 변환 처리
     # Event ID가 12 또는 13일 때 시간 변환 처리
    elif log_name == "System" and event_id in ["12", "13"] and source == "Microsoft-Windows-Kernel-General":
        # 종료 시간 변환 (Event ID가 12인 경우)
        if event_id == "13":
            match = re.search(r'운영 체제가 시스템 시간\s+([0-9\-T:\.]+Z)+에', description)
            if match:
                original_time = match.group(1)
                am_pm_time = convert_to_am_pm(original_time)
                processed_description = processed_description.replace(original_time, am_pm_time)
        
        # 시작 시간 변환 (Event ID가 13인 경우)
        elif event_id == "12":
            match = re.search(r'운영 체제가 시스템 시간\s+([0-9\-T:\.]+Z)+에', description)
            if match:
                original_time = match.group(1)
                am_pm_time = convert_to_am_pm(original_time)
                processed_description = processed_description.replace(original_time, am_pm_time)

    return processed_description

def seconds_to_dhms(seconds):
    """
    주어진 초를 일, 시, 분, 초로 변환하는 함수
    """
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    result = []
    
    if days > 0:
        result.append(f"{days}일")
    if hours > 0:
        result.append(f"{hours}시간")
    if minutes > 0:
        result.append(f"{minutes}분")
    result.append(f"{seconds}초")
    
    return ' '.join(result)

def extract_summary_by_log_event_source(log_name: str, event_id: str, source: str, description: str) -> str:
    """
    Log Name이 'System', Event ID가 '1', Source가 'Microsoft-Windows-Kernel-General'일 때만
    또는 Event ID가 '6013'인 경우 처리
    Description에서 '변경 이유'와 '프로세스' 정보를 추출하여 Summary를 생성하는 함수.
    다른 경우에는 기본적인 Summary를 생성.
    """
    summary_lines = []

    # 특정 조건에 해당할 때만 변경 이유와 프로세스 정보 추출
    if log_name == "System" and event_id == "1" and source == "Microsoft-Windows-Kernel-General":
        # 변경 이유 추출
        reason_match = re.search(r'변경 이유:\s+(.+)', description)
        if reason_match:
            summary_lines.append(f"변경 이유: {reason_match.group(1)}")

        # 프로세스 정보 추출 (PID 4는 System으로 변환)
        process_match = re.search(r'프로세스:\s+(.+)', description)
        if process_match:
            process_info = process_match.group(1)
            if "PID 4" in process_info:
                process_info = "System"
            summary_lines.append(f"프로세스: {process_info}")
    
    # Event ID가 6013인 경우 작동 시간 계산
    elif log_name == "System" and event_id == "6013" and source == "EventLog":
        # 시스템 작동 시간 추출 (초 단위)
        uptime_match = re.search(r'시스템 작동 시간은\s+([0-9]+)\s*초입니다', description)
        if uptime_match:
            uptime_seconds = int(uptime_match.group(1))
            dhms = seconds_to_dhms(uptime_seconds)
            summary_lines.append(f"작동시간: {dhms}")

    # Event ID가 12일 때 시스템 종료 시간을 요약
    if log_name == "System" and event_id == "13" and source == "Microsoft-Windows-Kernel-General":
        print(description)
        print()
        shutdown_match = re.search(r'운영 체제가 시스템 시간\s+([0-9\-T:\.]+Z)+에', description)
        if shutdown_match:
            shutdown_time = shutdown_match.group(1)
            am_pm_time = convert_to_am_pm(shutdown_time)
            summary_lines.append(f"SHUTDOWN: {am_pm_time}")
    
    # Event ID가 13일 때 시스템 시작 시간을 요약
    elif log_name == "System" and event_id == "12" and source == "Microsoft-Windows-Kernel-General":
        start_match = re.search(r'운영 체제가 시스템 시간\s+([0-9\-T:\.]+Z)+에', description)
        if start_match:
            start_time = start_match.group(1)
            am_pm_time = convert_to_am_pm(start_time)
            summary_lines.append(f"START: {am_pm_time}")

    elif log_name == "Microsoft-Windows-NetworkProfile/Operational" and event_id == "10000" and source == "Microsoft-Windows-NetworkProfile":
        summary_lines.append("네트워크 연결 됨")
    elif log_name == "Microsoft-Windows-NetworkProfile/Operational" and event_id == "10001" and source == "Microsoft-Windows-NetworkProfile":
        summary_lines.append("네트워크 연결 끊김")

    elif log_name == "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" and event_id in ["24","25","40","41","42"]:
        summary_lines.append(description)

    elif log_name == "Security" and event_id in ["4624", "4625", "4634", "4647"]:
        if not re.search(r"로그온 유형:\s*10", description):
            return "-1"
        
    elif log_name == "Security" and event_id in ["4648"]:
        summary_lines.append(description)

    elif log_name == "Security" and event_id == "4688" and source == "Microsoft-Windows-Security-Auditing":
        process_id_match = re.search(r'새 프로세스 ID:\s+([^\s]+)', description)
        process_name_match = re.search(r'새 프로세스 이름:\s+([^\s]+)', description)
        token_elevation_match = re.search(r'토큰 상승 유형:\s+([^\s]+)', description)
        creator_process_id_match = re.search(r'생성자 프로세스 ID:\s+([^\s]+)', description)
        # 생성자 프로세스 이름에 줄바꿈을 포함하지 않도록 '\n' 전까지만 파싱
        creator_process_name_match = re.search(r'생성자 프로세스 이름:\s*([^\n\r]*)', description)

        if process_id_match and process_name_match and token_elevation_match and creator_process_id_match:
            summary_lines.append("새 프로세스가 만들어졌습니다.")
            creator_process_name = creator_process_name_match.group(1).strip()
            
            # 생성자 프로세스 이름이 없으면 "이름 없음"으로 처리
            if creator_process_name == "프로세스 명령줄:":
                creator_process_name = "이름 없음"

            summary_lines.append(f'생성자 프로세스: {creator_process_name} ({creator_process_id_match.group(1)})')
            summary_lines.append(f' -> 프로세스: {process_name_match.group(1)} ({process_id_match.group(1)})')
            summary_lines.append(f'토큰 상승 유형: {token_elevation_match.group(1)}')

    elif log_name == "Security" and event_id == "4616" and source == "Microsoft-Windows-Security-Auditing":
        # 공백을 포함한 "계정 이름"을 추출하기 위해 정규 표현식 수정
        name_match = re.search(r'계정 이름:\s+(.*)', description)  # "계정 이름"을 전체 추출
        if name_match:
            name = name_match.group(1).strip()  # 계정 이름 앞뒤 공백 제거
            summary_lines.append(f"{name}에 의해 시스템 시간이 변경되었습니다.")



    # 조건이 맞지 않으면 기본 요약 생성
    if not summary_lines:
        summary_lines.append("N/A")

    # Summary 내용이 있으면 줄을 구분하여 반환
    return "\n".join(summary_lines)

def process_description_and_summary(log_name: str, event_id: str, source: str, description: str) -> dict:
    """
    Description을 전처리하고, Summary도 함께 생성하여 반환하는 함수.
    """
    # 1. Description 전처리 (전처리는 원본을 그대로 유지)
    processed_description = preprocess_description_by_log_event_source(log_name, event_id, source, description)
    
    # 2. Summary 생성
    summary = extract_summary_by_log_event_source(log_name, event_id, source, description)


    return {
        "processed_description": processed_description,
        "summary": summary
    }
