import subprocess
import csv
import re
from datetime import datetime
from .main_summary import process_description_and_summary

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

    return formatted_date, dt  # datetime 객체도 반환하여 정렬에 사용

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
    cleaned_text = re.sub(r'([가-힣]+)[a-zA-Z]', r'\1', text)
    cleaned_text = re.sub(r'[^\w\s가-힣]', '', cleaned_text)
    return cleaned_text

def clean_description(description_lines):
    cleaned_lines = [re.sub(r'Event\[\d+\]', '', line) for line in description_lines]
    cleaned_lines = [line for line in cleaned_lines if line.strip()]
    return "\n".join(cleaned_lines).strip()

def replace_question_marks(description: str) -> str:
    return description.replace("?", "")

def export_event_log_to_csv(log_names_and_ids, csv_file):
    events_data = []  # 모든 로그 데이터를 저장할 리스트

    for log_name, event_id_sources in log_names_and_ids:
        for event_id, source_list in event_id_sources:
            event_id_filter = f"EventID={event_id}"
            command = f'wevtutil qe "{log_name}" /q:"*[System[({event_id_filter})]]" /f:text'
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
            if result.returncode != 0:
                print(f"Error executing command for Log {log_name}: {result.stderr}")
                continue

            lines = result.stdout.splitlines()
            event_data = {}
            description_lines = []
            valid_event = True

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("Log Name:"):
                    if event_data and valid_event:
                        event_data['Description'] = clean_description(description_lines)
                        event_data['Description'] = replace_question_marks(event_data['Description'])
                        processed_data = process_description_and_summary(
                            event_data['Log Name'], event_data['Event ID'], event_data['Source'], event_data['Description']
                        )
                        event_data['Description'] = processed_data["processed_description"]
                        event_data['Summary'] = processed_data["summary"]

                        if event_data["Summary"] != "-1":  # Summary가 "-1"이 아닌 경우에만 저장
                            events_data.append(event_data)

                    event_data = {}
                    description_lines = []
                    valid_event = True
                    event_data['Log Name'] = line.split(":", 1)[1].strip()

                elif line.startswith("Source:"):
                    source = line.split(":", 1)[1].strip()
                    event_data['Source'] = source
                    if source_list and source_list != [] and source not in source_list:
                        valid_event = False

                elif line.startswith("Date:"):
                    date_iso = line.split(":", 1)[1].strip()
                    formatted_date, dt_obj = format_date(date_iso)
                    event_data['Date'] = formatted_date
                    event_data['DateObj'] = dt_obj  # 정렬을 위해 datetime 객체 저장

                elif line.startswith("Event ID:"):
                    event_data['Event ID'] = line.split(":", 1)[1].strip()

                elif line.startswith("Task:"):
                    task_pre = line.split(":", 1)[1].strip()
                    event_data['Task'] = clean_text(task_pre)

                elif line.startswith("Level:"):
                    level_ko = line.split(":", 1)[1].strip()
                    event_data['Level'] = extract_level(level_ko)

                elif line.startswith("Opcode:"):
                    event_data['Opcode'] = line.split(":", 1)[1].strip()

                elif line.startswith("Keyword:"):
                    event_data['Keyword'] = line.split(":", 1)[1].strip()

                elif line.startswith("User:"):
                    event_data['User'] = line.split(":", 1)[1].strip()

                elif line.startswith("User Name:"):
                    event_data['User Name'] = line.split(":", 1)[1].strip()

                elif line.startswith("Computer:"):
                    event_data['Computer'] = line.split(":", 1)[1].strip()

                elif line.startswith("Description:"):
                    description_lines.append(line.split(":", 1)[1].strip())

                elif description_lines:
                    description_lines.append(line)

            if event_data and valid_event:
                event_data['Description'] = clean_description(description_lines)
                event_data['Description'] = replace_question_marks(event_data['Description'])
                processed_data = process_description_and_summary(
                    log_name, event_data['Event ID'], event_data['Source'], event_data['Description']
                )
                event_data['Description'] = processed_data["processed_description"]
                event_data['Summary'] = processed_data["summary"]

                if event_data["Summary"] != "-1":  # Summary가 "-1"이 아닌 경우에만 저장
                    events_data.append(event_data)

    # Date 필드 (datetime 객체) 기준으로 정렬
    events_data.sort(key=lambda x: x['DateObj'])

    # 정렬된 데이터를 CSV로 저장
    with open(csv_file, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        header = ['Log Name', 'Source', 'Date', 'Event ID', 'Task', 'Level', 'Opcode', 'Keyword', 'User', 'User Name', 'Computer', 'Description', 'Summary']
        writer.writerow(header)

        for event in events_data:
            writer.writerow([
                event.get('Log Name', ''),
                event.get('Source', ''),
                event.get('Date', ''),
                event.get('Event ID', ''),
                event.get('Task', ''),
                event.get('Level', ''),
                event.get('Opcode', ''),
                event.get('Keyword', ''),
                event.get('User', ''),
                event.get('User Name', ''),
                event.get('Computer', ''),
                event.get('Description', ''),
                event.get('Summary', '')  # Summary 추가
            ])
