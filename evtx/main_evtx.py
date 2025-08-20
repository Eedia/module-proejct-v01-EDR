import threading
import os
from utils.main_parser import export_event_log_to_csv as export_by_event_id
from utils.main_evtx_all_parser import export_event_log_to_csv as export_all_logs
import time
# from elevate import elevate

def run_specific_logs(directory):
    # 특정 이벤트 ID 로그 파일을 저장
    
    actions = [
        {
            'name': '원격데스크톱_연결_해제',
            'log_names_and_ids': [
                ('Security', [
                    ('4624', []),
                    ('4625', []),
                    ('4634', []),
                    ('4647', []),
                    ('4689', []),
                    # ('4648', []),
                    ('4779', []),
                    ('4778', [])
                ]),
                ('Microsoft-Windows-TerminalServices-RDPClient/Operational', [
                    ('1024', []),
                    ('1025', []),
                    ('1027', []),
                    ('1028', []),
                    ('1029', []),
                    ('1102', [])
                ]),
                ('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', [
                    ('261', []),
                    ('1149', [])
                ]),
                ('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', [
                    ('24', []),
                    ('25', []),
                    ('40', []),
                    ('41', []),
                    ('42', [])
                ]),
            ]
        },
        {
            'name': '시스템시작_종료 관련',
            'log_names_and_ids': [
                ('System', [
                    ('12',['Microsoft-Windows-Kernel-General']),
                    ('13',['Microsoft-Windows-Kernel-General']),
                    # ('6013', [])
                ])
            ]
        },
        {
            'name': '네트워크연결_해제',
            'log_names_and_ids': [
                ('Microsoft-Windows-NetworkProfile/Operational', [
                    ('10000', []),
                    ('10001', [])
                ])
            ]
        },
        {
            'name': '공유폴더 관련',
            'log_names_and_ids': [
                ('Security', [
                    ('4656', []),
                    ('4658', []),
                    ('4663', []),
                    ('5140', []),
                    ('5145', [])
                ])
            ]
        },
        {
            'name': '이벤트 로그 삭제 관련',
            'log_names_and_ids': [
                ('System', [
                    ('1100', []),
                    ('1102', []),
                    ('104', [])
                ])
            ]
        },
        {
            'name': '레지스트리 조작',
            'log_names_and_ids': [
                ('Security', [
                    ('4663', []),
                    ('4656', []),
                    ('4657', []),
                    ('4670', []),
                    ('4658', [])
                ])
            ]
        },
        {
            'name': '시스템 시간 변경',
            'log_names_and_ids': [
                ('System', [
                    ('1', ['Microsoft-Windows-Kernel-General'])
                ]),
                ('Security', [
                    ('4616', [])
                ]),
                ('Microsoft-Windows-DateTimeControlPanel%4Operational', [
                    ('20000', []),
                    ('20001', [])
                ])
            ]
        },
        {
            'name': '프로세스 생성_종료',
            'log_names_and_ids': [
                ('Security', [
                    ('4688', []),
                    ('4689', [])
                ])
            ]
        },
        {
            'name': '응용프로그램 설치',
            'log_names_and_ids': [
                ('Microsoft-Windows-Application-Experience%4Program-Inventory', [
                    ('903', []),
                    ('904', [])
                ]),
                ('Microsoft-Windows-Application-Experience%4Program-Compatibility-Assistant', [
                    ('17', [])
                ])
            ]
        }
    ]  # 사용할 로그와 ID들

    print("이벤트 로그 파싱 시작...")

    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)  # ./testing/Eventslogs_analysis 디렉토리가 없다면 생성

    for action in actions:
        log_names_and_ids = action['log_names_and_ids']
        csv_filename = f"{action['name']}.csv"
        csv_path = os.path.join(directory, csv_filename)
        print(f"Exporting events from logs {log_names_and_ids} to '{csv_filename}'...")
        export_by_event_id(log_names_and_ids, csv_path)
    print(f"ID별 로그가 '{csv_path}'에 저장되었습니다.")

def run_all_logs(directory):
    # 모든 이벤트 로그 파일을 저장
    # 이벤트 로그 파일들이 위치한 디렉토리 경로 설정
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)  # ./testing/Eventslogs_total 디렉토리가 없다면 생성

    print(f"저장할 디렉토리 : {directory}\n")
    logs_dir = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'system32', 'winevt', 'Logs')
    if not os.path.exists(logs_dir):
        print(f"로그 디렉토리 '{logs_dir}'가 존재하지 않습니다.")
        return

    # .evtx 파일 목록 가져오기
    log_files = [f for f in os.listdir(logs_dir) if f.lower().endswith('.evtx')]
    if not log_files:
        print(f"'{logs_dir}'에 이벤트 로그 파일이 없습니다.")
        return

    for log_file in log_files:
        log_name = os.path.splitext(log_file)[0]  # .evtx 확장자 제거
        log_dir = os.path.join(directory, log_name)  # 저장될 로그 디렉토리
        print(log_dir)
        print()

        os.makedirs(log_dir, exist_ok=True)  # 로그 이름으로 디렉토리 생성
        csv_filename = f"{log_name}.csv"
        csv_path = os.path.join(log_dir, csv_filename)
        print(f"Exporting '{log_name}' to '{csv_filename}'...")
        try:
            export_all_logs(log_name, csv_path)
            print(f"'{csv_filename}' 파일이 '{log_dir}'에 저장되었습니다.\n")
        except Exception as e:
            print(f"'{log_name}' 로그를 내보내는 중 오류 발생: {e}\n")
    print("이벤트 로그 파싱 완료.")

def main():
    # elevate()

    # 모든 로그 파일 저장할 디렉토리 선택
    all_logs_dir = "./testing/EventLogs_total"

    # 특정 로그 파일 저장할 디렉토리 선택
    specific_logs_dir = "./testing/EventLogs_analysis"

    start_time = time.time()  # 시작 시간 기록
    if all_logs_dir and specific_logs_dir:
        # 멀티스레딩으로 두 작업 동시에 실행
        all_logs_thread = threading.Thread(target=run_all_logs, args=(all_logs_dir,))
        specific_logs_thread = threading.Thread(target=run_specific_logs, args=(specific_logs_dir,))

        all_logs_thread.start()
        specific_logs_thread.start()

        all_logs_thread.join()
        specific_logs_thread.join()
    else:
        print("디렉토리가 선택되지 않았습니다.")
    print("모든 작업이 완료되었습니다.")
    end_time = time.time()  # 종료 시간 기록
    execution_time = end_time - start_time
    print(f"CSV로 내보내는 데 걸린 시간: {execution_time:.2f}초")

if __name__ == "__main__":
    main()
