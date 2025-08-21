"""
AI 모듈 공통 유틸리티 함수
실제 EDR 스캔 결과를 AI 모듈 호환 형식으로 변환
"""
from typing import Dict

def normalize_findings_data(raw_data: Dict) -> Dict:
    """실제 EDR 스캔 결과를 AI 모듈 호환 형식으로 변환"""
    
    # 메타데이터 추출
    metadata = raw_data.get('scan_metadata', {})
    summary = raw_data.get('scan_summary', {})
    findings = raw_data.get('findings', [])
    
    print(f"📊 레지스트리 원본 데이터: {len(findings)}개 발견사항")
    findings_by_severity = summary.get('findings_by_severity', {})
    print(f"   🔴 Critical: {findings_by_severity.get('critical', 0)}개")
    print(f"   🟠 High: {findings_by_severity.get('high', 0)}개") 
    print(f"   🟡 Medium: {findings_by_severity.get('medium', 0)}개")
    
    # 🔧 findings를 event_logs 형식으로 변환
    event_logs = []
    registry_data = {}
    
    for finding in findings:
        evidence = finding.get('evidence', {})
        
        # 레지스트리 증거가 있는 경우 이벤트로그 형태로 변환
        if 'registry_evidence' in evidence:
            for reg_evidence in evidence['registry_evidence']:
                # 가상의 이벤트 로그 형태로 변환
                event_log = {
                    "event_id": 4657,  # 레지스트리 값 변경 이벤트
                    "finding_id": finding.get('finding_id'),
                    "rule_id": finding.get('rule_id'),
                    "severity": finding.get('severity'),
                    "category": finding.get('category'),  
                    "title": finding.get('title'),
                    "description": finding.get('description'),
                    "confidence": finding.get('confidence', 0) / 100.0,  # 80 → 0.8
                    "registry_key": reg_evidence.get('key'),
                    "registry_value": reg_evidence.get('value'),
                    "registry_data": reg_evidence.get('data'),
                    "hive": reg_evidence.get('hive'),
                    "time_created": finding.get('timestamp'),
                    "mitre_techniques": finding.get('mitre_attack', {}).get('techniques', [])
                }
                event_logs.append(event_log)
                
                # 레지스트리 데이터도 구성
                full_key = f"{reg_evidence.get('hive')}\\{reg_evidence.get('key')}"
                if full_key not in registry_data:
                    registry_data[full_key] = {}
                registry_data[full_key][reg_evidence.get('value')] = reg_evidence.get('data')
        
        # 프로세스 증거가 있는 경우
        if 'process_evidence' in evidence:
            for proc_evidence in evidence['process_evidence']:
                event_log = {
                    "event_id": 4688,  # 프로세스 생성 이벤트
                    "finding_id": finding.get('finding_id'),
                    "rule_id": finding.get('rule_id'),
                    "severity": finding.get('severity'),
                    "category": finding.get('category'),
                    "title": finding.get('title'),
                    "description": finding.get('description'),
                    "confidence": finding.get('confidence', 0) / 100.0,
                    "process_name": proc_evidence.get('process_name'),
                    "process_id": proc_evidence.get('process_id'),
                    "command_line": proc_evidence.get('command_line'),
                    "parent_process": proc_evidence.get('parent_process'),
                    "time_created": finding.get('timestamp'),
                    "mitre_techniques": finding.get('mitre_attack', {}).get('techniques', [])
                }
                event_logs.append(event_log)
    
    return {
        'event_logs': event_logs,
        'registry_data': registry_data,
        'collection_timestamp': metadata.get('timestamp', '2025-08-20T15:36:00Z'),
        'hostname': metadata.get('hostname', 'Unknown'),
        'scan_metadata': metadata,
        'scan_summary': summary,
        # AI 모듈들이 기존 탐지 이슈를 그대로 분석할 수 있도록 전달
        'existing_findings': findings,
        'original_findings': findings  # 원본 보존
    }

def convert_to_alerts_format(findings: list) -> list:
    """EDR findings를 alerts 형식으로 변환"""
    alerts = []
    
    for finding in findings:
        alert = {
            'issue_id': finding.get('finding_id'),
            'title': finding.get('title'),
            'severity': finding.get('severity', 'medium').lower(),
            'category': finding.get('category', 'unknown'),
            'description': finding.get('description'),
            'confidence': finding.get('confidence', 50) / 100.0,  # 퍼센트를 소수점으로
            'timestamp': finding.get('timestamp'),
            'rule_name': finding.get('rule_id'),
            'evidence': finding.get('evidence', {})
        }
        alerts.append(alert)
    
    return alerts

def create_test_data() -> Dict:
    """테스트용 데이터 생성"""
    return {
        'event_logs': [
            {
                'event_id': 4688,
                'process_name': 'powershell.exe',
                'command_line': 'powershell -encodedcommand SGVsbG8gV29ybGQ=',
                'process_id': 1234,
                'time_created': '2025-08-21T10:30:00Z'
            },
            {
                'event_id': 4657,
                'registry_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                'registry_value': 'TestApp',
                'registry_data': 'C:\\Temp\\malware.exe',
                'time_created': '2025-08-21T10:31:00Z'
            }
        ],
        'registry_data': {
            'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection': {
                'DisableRealtimeMonitoring': 1
            },
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run': {
                'TestApp': 'C:\\Temp\\malware.exe'
            }
        },
        'collection_timestamp': '2025-08-21T10:30:00Z',
        'hostname': 'TEST-PC-001'
    }
