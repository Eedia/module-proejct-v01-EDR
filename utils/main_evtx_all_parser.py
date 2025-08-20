import subprocess
import csv
import re
from datetime import datetime

def format_date(date_str):
    # 'Z'와 소수점 이하 6자리 초를 제거하여 처리
    clean_date_str = re.sub(r'\.\d+Z$', 'Z', date_str)
    
    # 소수점 이하 초 정보 제거 및 파싱
    try:
        dt = datetime.strptime(clean_date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        dt = datetime.strptime(clean_date_str, '%Y-%m-%dT%H:%M:%SZ')
    
    # 원하는 형식으로 변환 (YYYY-MM-DD HH:MM:SS)
    formatted_date = dt.strftime('%Y-%m-%d %H:%M:%S')

    return formatted_date

def extract_level(level_str):
    level_types = {
        "정보": "Info",
        "경고": "Warning",
        "오류": "Error",
        "위험": "Critical",
        "자세한 정보 표시": "Verbose"
    }
    
    for level in level_types:
        if level_str.startswith(level):
            return level_types[level]
    return level_str

def clean_text(text):
    # 한글 뒤에 붙는 불필요한 영문자 제거
    cleaned_text = re.sub(r'([가-힣]+)[a-zA-Z]', r'\1', text)
    
    # 특수문자 제거
    cleaned_text = re.sub(r'[^\w\s가-힣]', '', cleaned_text)

    return cleaned_text

def clean_description(description_lines):
    # 각 줄에서 Event[n] 패턴만 제거 (n은 숫자)
    cleaned_lines = [re.sub(r'Event\[\d+\]', '', line) for line in description_lines]
    
    # 빈 줄 제거
    cleaned_lines = [line for line in cleaned_lines if line.strip()]
    
    return "\n".join(cleaned_lines).strip()



def convert_level_to_eng(level):
    level_mapping = {
        '위험\x00': "Critical",
        '오류': "Error",
        '경고': "Warning",
        '정보': "Information",
    }
    return level_mapping.get(level, level)

def export_event_log_to_csv(log_name, csv_file):
    """
    지정된 이벤트 로그를 CSV 파일로 내보냅니다.

    Args:
        log_name (str): 이벤트 로그의 이름 (예: "System").
        csv_file (str): 출력 CSV 파일의 경로.
    """

    command = f'wevtutil qe "{log_name}" /f:text'
    
    with open(csv_file, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        
        # CSV 헤더 정의
        header = ['Log Name', 'Source', 'Date', 'Event ID', 'Task', 'Level', 
                  'Opcode', 'Keyword', 'User', 'User Name', 'Computer', 'Description']
        writer.writerow(header)

        try:
            # wevtutil 명령어 실행
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, timeout=300)
            
            if result.returncode != 0:
                print(f"명령어 실행 오류 (Log: {log_name}): {result.stderr}")
                return

            lines = result.stdout.splitlines()

            # 이벤트 데이터 추출을 위한 변수 초기화
            event_data = {}
            description_lines = []

            for line in lines:
                line = line.strip()
                if not line:
                    continue  # 빈 줄 건너뛰기

                if line.startswith("Log Name:"):
                    if event_data:
                        # 이전 이벤트 데이터 저장
                        event_data['Description'] = clean_description(description_lines)
                        writer.writerow([
                            event_data.get('Log Name', ''),
                            event_data.get('Source', ''),
                            event_data.get('Date', ''),
                            event_data.get('Event ID', ''),
                            event_data.get('Task', ''),
                            event_data.get('Level', ''),
                            event_data.get('Opcode', ''),
                            event_data.get('Keyword', ''),
                            event_data.get('User', ''),
                            event_data.get('User Name', ''),
                            event_data.get('Computer', ''),
                            event_data.get('Description', '')
                        ])
                        event_data = {}
                        description_lines = []

                    # 새로운 이벤트 시작
                    event_data['Log Name'] = line.split(":", 1)[1].strip()
                elif line.startswith("Source:"):
                    event_data['Source'] = line.split(":", 1)[1].strip()
                elif line.startswith("Date:"):
                    date_iso= line.split(":", 1)[1].strip()
                    event_data['Date'] = format_date(date_iso)
                elif line.startswith("Event ID:"):
                    event_data['Event ID'] = line.split(":", 1)[1].strip()
                elif line.startswith("Task:"):
                    task_pre =line.split(":", 1)[1].strip()
                    event_data['Task'] = clean_text(task_pre)    
                elif line.startswith("Level:"):
                    level_ko = line.split(":", 1)[1].strip()
                    level_ko = re.sub(r'[a-zA-Z]', '', level_ko).strip()
                    # # 'extract_level' 함수를 사용하여 level을 정리
                    event_data['Level'] = extract_level(level_ko)

                    # event_data['Level'] = level_ko
                    
                elif line.startswith("Opcode:"):
                    event_data['Opcode'] = line.split(":", 1)[1].strip()
                elif line.startswith("Keyword:"):
                    keyword_pre = line.split(":", 1)[1].strip()
                    event_data['Keyword'] = clean_text(keyword_pre)
                elif line.startswith("User:"):
                    event_data['User'] = line.split(":", 1)[1].strip()
                elif line.startswith("User Name:"):
                    event_data['User Name'] = line.split(":", 1)[1].strip()
                elif line.startswith("Computer:"):
                    event_data['Computer'] = line.split(":", 1)[1].strip()
                elif line.startswith("Description:"):
                    # Description 시작
                    description_content = line.split(":", 1)[1].strip()
                    description_lines.append(description_content)
                elif description_lines:
                    # Description 이어서 추가
                    description_lines.append(line)

            # 마지막 이벤트 데이터 저장
            if event_data:
                event_data['Description'] = clean_description(description_lines)
                writer.writerow([
                    event_data.get('Log Name', ''),
                    event_data.get('Source', ''),
                    event_data.get('Date', ''),
                    event_data.get('Event ID', ''),
                    event_data.get('Task', ''),
                    event_data.get('Level', ''),
                    event_data.get('Opcode', ''),
                    event_data.get('Keyword', ''),
                    event_data.get('User', ''),
                    event_data.get('User Name', ''),
                    event_data.get('Computer', ''),
                    event_data.get('Description', '')
                ])
        
        except subprocess.TimeoutExpired:
            print(f"명령어 실행 시간 초과 (Log: {log_name})")
        except Exception as e:
            print(f"오류 발생 (Log: {log_name}): {e}")