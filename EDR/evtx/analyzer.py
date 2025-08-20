"""
evtx/analyzer.py
이벤트 로그 분석기 - 보안 위협 탐지 룰 엔진

"""

import re
import base64
from datetime import datetime, time
from typing import List, Dict, Any, Optional
import logging
from urllib.parse import urlparse

# utils 모듈에서 필요한 클래스 임포트
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.data_structures import generate_finding_id, get_current_timestamp

logger = logging.getLogger(__name__)

class EventAnalyzer:
    """이벤트 로그 분석기"""
    
    def __init__(self):
        # LOLBin 실행 파일 목록
        self.lolbin_processes = [
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'msiexec.exe', 'wmic.exe', 'powershell.exe',
            'cmd.exe', 'wscript.exe', 'cscript.exe'
        ]
        
        # 의심스러운 명령줄 패턴
        self.suspicious_patterns = {
            'url_download': r'(http[s]?://[^\s]+|ftp://[^\s]+)',
            'base64_encoded': r'[A-Za-z0-9+/]{20,}={0,2}',
            'powershell_encoded': r'-[eE]([ncodedComad]{12}|nc)',
            'javascript_execution': r'javascript:|vbscript:',
            'bypass_execution_policy': r'-[eE]xecution[pP]olicy\s+[bB]ypass',
            'amsi_bypass': r'AmsiScanBuffer|AmsiInitialize',
            'registry_manipulation': r'reg\s+(add|delete|query)',
            'service_manipulation': r'sc\s+(create|delete|config)',
            'temp_directory': r'[cC]:\\[uU]sers\\[^\\]+\\[aA]pp[dD]ata\\[lL]ocal\\[tT]emp'
        }
        
        # 업무 시간 정의 (09:00 - 18:00)
        self.business_hours = (time(9, 0), time(18, 0))
        
        # 위험한 로그온 타입
        self.risky_logon_types = {
            '2': 'Interactive',
            '3': 'Network', 
            '4': 'Batch',
            '5': 'Service',
            '7': 'Unlock',
            '8': 'NetworkCleartext',
            '9': 'NewCredentials',
            '10': 'RemoteInteractive',  # RDP
            '11': 'CachedInteractive'
        }
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """이벤트 목록을 분석하여 Finding 생성"""
        findings = []
        
        for event in events:
            event_findings = self._analyze_single_event(event)
            findings.extend(event_findings)
        
        # 중복 제거 및 정렬
        findings = self._deduplicate_findings(findings)
        findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        logger.info(f"Generated {len(findings)} findings from {len(events)} events")
        return findings
    
    def _analyze_single_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """단일 이벤트 분석"""
        findings = []
        event_id = event.get('event_id')
        
        # 이벤트 ID별 분석
        if event_id == 4688:  # 프로세스 생성
            findings.extend(self._analyze_process_creation(event))
        elif event_id in [4624, 4625]:  # 로그온/로그온 실패
            findings.extend(self._analyze_logon_events(event))
        elif event_id == 7045:  # 서비스 설치
            findings.extend(self._analyze_service_installation(event))
        elif event_id == 4104:  # PowerShell 스크립트 블록
            findings.extend(self._analyze_powershell_activity(event))
        elif event_id in [21, 24, 25]:  # RDP 이벤트
            findings.extend(self._analyze_rdp_events(event))
        elif event_id in [1100, 1102, 104]:  # 로그 조작
            findings.extend(self._analyze_log_manipulation(event))
        
        return findings
    
    def _analyze_process_creation(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """프로세스 생성 이벤트 분석"""
        findings = []
        
        process_name = event.get('process_name', '').lower()
        command_line = event.get('command_line', '')
        parent_process = event.get('parent_process', '').lower()
        
        # LOLBin 실행 탐지
        for lolbin in self.lolbin_processes:
            if lolbin in process_name:
                lolbin_findings = self._analyze_lolbin_execution(event, lolbin, command_line)
                findings.extend(lolbin_findings)
        
        # 의심스러운 실행 경로
        if self._is_suspicious_path(process_name):
            findings.append(self._create_suspicious_path_finding(event))
        
        # 의심스러운 부모-자식 프로세스 관계
        if self._is_suspicious_parent_child(parent_process, process_name):
            findings.append(self._create_suspicious_process_relationship_finding(event))
        
        return findings
    
    def _analyze_lolbin_execution(self, event: Dict[str, Any], lolbin: str, command_line: str) -> List[Dict[str, Any]]:
        """LOLBin 실행 분석"""
        findings = []
        
        # rundll32 분석
        if 'rundll32' in lolbin:
            if re.search(self.suspicious_patterns['javascript_execution'], command_line, re.IGNORECASE):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_LOLBIN_RUNDLL32_JS",
                    "severity": "high",
                    "score_impact": -15,
                    "category": "execution",
                    "title": "rundll32.exe JavaScript 실행",
                    "description": f"rundll32.exe가 JavaScript 코드를 실행하여 악성 페이로드 다운로드 가능성이 있습니다.",
                    "confidence": 85,
                    "timestamp": event.get('timestamp'),
                    "evidence": {
                        "primary_event": event,
                        "supporting_events": [],
                        "registry_evidence": [],
                        "file_evidence": []
                    },
                    "mitre_attack": {
                        "tactics": ["TA0002"],
                        "techniques": ["T1218.011"],
                        "sub_techniques": []
                    }
                })
            
            # URL 다운로드 패턴
            if re.search(self.suspicious_patterns['url_download'], command_line, re.IGNORECASE):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_LOLBIN_RUNDLL32_URL",
                    "severity": "high",
                    "score_impact": -15,
                    "category": "execution",
                    "title": "rundll32.exe URL 다운로드",
                    "description": f"rundll32.exe가 외부 URL에서 파일을 다운로드하려고 시도했습니다.",
                    "confidence": 90,
                    "timestamp": event.get('timestamp'),
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0002"],
                        "techniques": ["T1218.011"]
                    }
                })
        
        # regsvr32 분석
        elif 'regsvr32' in lolbin:
            if re.search(self.suspicious_patterns['url_download'], command_line, re.IGNORECASE):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_LOLBIN_REGSVR32_URL",
                    "severity": "high",
                    "score_impact": -15,
                    "category": "execution",
                    "title": "regsvr32.exe 원격 스크립트 실행",
                    "description": f"regsvr32.exe가 원격 스크립트를 실행하여 악성코드 감염 위험이 있습니다.",
                    "confidence": 85,
                    "timestamp": event.get('timestamp'),
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0002"],
                        "techniques": ["T1218.010"]
                    }
                })
        
        # PowerShell 분석
        elif 'powershell' in lolbin:
            # 인코딩된 명령어
            if re.search(self.suspicious_patterns['powershell_encoded'], command_line, re.IGNORECASE):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_POWERSHELL_ENCODED",
                    "severity": "medium",
                    "score_impact": -10,
                    "category": "execution",
                    "title": "PowerShell 인코딩된 명령어 실행",
                    "description": f"PowerShell이 인코딩된 명령어를 실행했습니다. 악성 활동일 가능성이 있습니다.",
                    "confidence": 75,
                    "timestamp": event.get('timestamp'),
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0002"],
                        "techniques": ["T1059.001"]
                    }
                })
            
            # 실행 정책 우회
            if re.search(self.suspicious_patterns['bypass_execution_policy'], command_line, re.IGNORECASE):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_POWERSHELL_BYPASS_POLICY",
                    "severity": "medium",
                    "score_impact": -8,
                    "category": "execution",
                    "title": "PowerShell 실행 정책 우회",
                    "description": f"PowerShell 실행 정책이 우회되어 실행되었습니다.",
                    "confidence": 80,
                    "timestamp": event.get('timestamp'),
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0005"],
                        "techniques": ["T1562.001"]
                    }
                })
        
        return findings
    
    def _analyze_logon_events(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """로그온 이벤트 분석"""
        findings = []
        
        event_id = event.get('event_id')
        logon_type = event.get('logon_type', '')
        user = event.get('user', '')
        source_ip = event.get('source_ip', '')
        timestamp = event.get('timestamp', '')
        
        # RDP 로그온 (Type 10)
        if logon_type == '10':
            # 업무 외 시간 RDP 접속
            if self._is_outside_business_hours(timestamp):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_RDP_NONBUSINESS_HOURS",
                    "severity": "medium",
                    "score_impact": -8,
                    "category": "remote_access",
                    "title": "업무 외 시간 RDP 접속",
                    "description": f"업무 시간 외에 {user} 계정으로 RDP 원격 접속이 발생했습니다.",
                    "confidence": 75,
                    "timestamp": timestamp,
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0008"],
                        "techniques": ["T1021.001"]
                    }
                })
            
            # 관리자 계정 RDP 접속
            if 'admin' in user.lower() or user.lower() == 'administrator':
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_ADMIN_RDP_LOGON",
                    "severity": "medium",
                    "score_impact": -6,
                    "category": "remote_access",
                    "title": "관리자 계정 RDP 접속",
                    "description": f"관리자 계정 {user}으로 RDP 원격 접속이 발생했습니다.",
                    "confidence": 70,
                    "timestamp": timestamp,
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0008"],
                        "techniques": ["T1021.001"]
                    }
                })
        
        # 로그온 실패 (4625)
        if event_id == 4625:
            findings.append({
                "finding_id": generate_finding_id(),
                "rule_id": "R_LOGON_FAILURE",
                "severity": "info",
                "score_impact": -1,
                "category": "account_logon",
                "title": "로그온 실패",
                "description": f"{user} 계정 로그온 실패가 발생했습니다.",
                "confidence": 60,
                "timestamp": timestamp,
                "evidence": {"primary_event": event},
                "mitre_attack": {
                    "tactics": ["TA0006"],
                    "techniques": ["T1110"]
                }
            })
        
        return findings
    
    def _analyze_service_installation(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """서비스 설치 이벤트 분석"""
        findings = []
        
        service_name = event.get('service_name', '')
        service_file_name = event.get('service_file_name', '')
        
        # 임시 디렉토리에서 실행되는 서비스
        if re.search(self.suspicious_patterns['temp_directory'], service_file_name, re.IGNORECASE):
            findings.append({
                "finding_id": generate_finding_id(),
                "rule_id": "R_SERVICE_TEMP_PATH",
                "severity": "medium",
                "score_impact": -10,
                "category": "persistence",
                "title": "임시 폴더 서비스 설치",
                "description": f"서비스 '{service_name}'이 임시 폴더에서 실행되도록 설치되었습니다.",
                "confidence": 80,
                "timestamp": event.get('timestamp'),
                "evidence": {"primary_event": event},
                "mitre_attack": {
                    "tactics": ["TA0003"],
                    "techniques": ["T1543.003"]
                }
            })
        
        # 사용자 쓰기 가능 경로의 서비스
        user_writable_paths = [r'c:\\users\\', r'c:\\programdata\\', r'c:\\windows\\temp\\']
        for path in user_writable_paths:
            if path in service_file_name.lower():
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_SERVICE_USER_WRITABLE",
                    "severity": "medium",
                    "score_impact": -8,
                    "category": "persistence",
                    "title": "사용자 쓰기 가능 경로 서비스",
                    "description": f"서비스 '{service_name}'이 사용자 쓰기 가능 경로에 설치되었습니다.",
                    "confidence": 70,
                    "timestamp": event.get('timestamp'),
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0003"],
                        "techniques": ["T1543.003"]
                    }
                })
                break
        
        return findings
    
    def _analyze_powershell_activity(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """PowerShell 활동 분석"""
        findings = []
        
        script_block = event.get('script_block', '')
        
        # AMSI 우회 시도
        if re.search(self.suspicious_patterns['amsi_bypass'], script_block, re.IGNORECASE):
            findings.append({
                "finding_id": generate_finding_id(),
                "rule_id": "R_POWERSHELL_AMSI_BYPASS",
                "severity": "high",
                "score_impact": -12,
                "category": "execution",
                "title": "PowerShell AMSI 우회 시도",
                "description": f"PowerShell 스크립트에서 AMSI(Antimalware Scan Interface) 우회를 시도했습니다.",
                "confidence": 90,
                "timestamp": event.get('timestamp'),
                "evidence": {"primary_event": event},
                "mitre_attack": {
                    "tactics": ["TA0005"],
                    "techniques": ["T1562.001"]
                }
            })
        
        # 다운로드 활동
        if 'downloadstring' in script_block.lower() or 'downloadfile' in script_block.lower():
            findings.append({
                "finding_id": generate_finding_id(),
                "rule_id": "R_POWERSHELL_DOWNLOAD",
                "severity": "medium",
                "score_impact": -8,
                "category": "execution",
                "title": "PowerShell 파일 다운로드",
                "description": f"PowerShell을 통해 외부에서 파일을 다운로드했습니다.",
                "confidence": 85,
                "timestamp": event.get('timestamp'),
                "evidence": {"primary_event": event},
                "mitre_attack": {
                    "tactics": ["TA0011"],
                    "techniques": ["T1105"]
                }
            })
        
        return findings
    
    def _analyze_rdp_events(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """RDP 이벤트 분석"""
        findings = []
        
        event_id = event.get('event_id')
        timestamp = event.get('timestamp')
        user = event.get('user', '')
        
        if event_id == 21:  # RDP 로그온 성공
            if self._is_outside_business_hours(timestamp):
                findings.append({
                    "finding_id": generate_finding_id(),
                    "rule_id": "R_RDP_SESSION_NONBUSINESS",
                    "severity": "medium",
                    "score_impact": -6,
                    "category": "remote_access",
                    "title": "업무 외 시간 RDP 세션",
                    "description": f"업무 시간 외에 RDP 세션이 시작되었습니다.",
                    "confidence": 70,
                    "timestamp": timestamp,
                    "evidence": {"primary_event": event},
                    "mitre_attack": {
                        "tactics": ["TA0008"],
                        "techniques": ["T1021.001"]
                    }
                })
        
        return findings
    
    def _analyze_log_manipulation(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """로그 조작 이벤트 분석"""
        findings = []
        
        event_id = event.get('event_id')
        
        if event_id in [1100, 1102]:  # 로그 서비스 종료/로그 삭제
            findings.append({
                "finding_id": generate_finding_id(),
                "rule_id": "R_LOG_MANIPULATION",
                "severity": "high",
                "score_impact": -15,
                "category": "security_settings",
                "title": "이벤트 로그 조작",
                "description": f"이벤트 로그가 삭제되거나 로그 서비스가 중단되었습니다.",
                "confidence": 95,
                "timestamp": event.get('timestamp'),
                "evidence": {"primary_event": event},
                "mitre_attack": {
                    "tactics": ["TA0005"],
                    "techniques": ["T1070.001"]
                }
            })
        
        return findings
    
    def _is_suspicious_path(self, process_path: str) -> bool:
        """의심스러운 실행 경로 확인"""
        suspicious_paths = [
            r'\\temp\\', r'\\tmp\\', r'\\appdata\\local\\temp\\',
            r'\\programdata\\', r'\\users\\public\\',
            r'\\windows\\tasks\\', r'\\recycler\\'
        ]
        
        for path in suspicious_paths:
            if path in process_path.lower():
                return True
        return False
    
    def _is_suspicious_parent_child(self, parent: str, child: str) -> bool:
        """의심스러운 부모-자식 프로세스 관계 확인"""
        # Office 프로그램에서 시스템 도구 실행
        office_processes = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
        system_tools = ['cmd.exe', 'powershell.exe', 'wmic.exe', 'certutil.exe']
        
        parent_name = os.path.basename(parent).lower()
        child_name = os.path.basename(child).lower()
        
        if parent_name in office_processes and child_name in system_tools:
            return True
        
        return False
    
    def _is_outside_business_hours(self, timestamp: str) -> bool:
        """업무 시간 외 확인"""
        if not timestamp:
            return False
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = dt.time()
            
            # 주말 확인 (토요일: 5, 일요일: 6)
            if dt.weekday() >= 5:
                return True
            
            # 업무 시간 확인
            start_time, end_time = self.business_hours
            if not (start_time <= current_time <= end_time):
                return True
        
        except Exception as e:
            logger.warning(f"Error checking business hours for timestamp {timestamp}: {e}")
        
        return False
    
    def _create_suspicious_path_finding(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """의심스러운 경로 실행 Finding 생성"""
        return {
            "finding_id": generate_finding_id(),
            "rule_id": "R_SUSPICIOUS_EXECUTION_PATH",
            "severity": "medium",
            "score_impact": -8,
            "category": "execution",
            "title": "의심스러운 경로에서 프로세스 실행",
            "description": f"임시 폴더나 사용자 쓰기 가능 경로에서 프로세스가 실행되었습니다.",
            "confidence": 70,
            "timestamp": event.get('timestamp'),
            "evidence": {"primary_event": event},
            "mitre_attack": {
                "tactics": ["TA0002"],
                "techniques": ["T1204"]
            }
        }
    
    def _create_suspicious_process_relationship_finding(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """의심스러운 프로세스 관계 Finding 생성"""
        return {
            "finding_id": generate_finding_id(),
            "rule_id": "R_SUSPICIOUS_PARENT_CHILD",
            "severity": "medium",
            "score_impact": -10,
            "category": "execution",
            "title": "의심스러운 부모-자식 프로세스 관계",
            "description": f"Office 애플리케이션에서 시스템 도구가 실행되었습니다.",
            "confidence": 75,
            "timestamp": event.get('timestamp'),
            "evidence": {"primary_event": event},
            "mitre_attack": {
                "tactics": ["TA0002"],
                "techniques": ["T1566.001"]
            }
        }
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """중복 Finding 제거"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # 룰 ID + 타임스탬프 + 주요 증거로 중복 확인
            key = (
                finding.get('rule_id'),
                finding.get('timestamp'),
                str(finding.get('evidence', {}).get('primary_event', {}).get('process_name', ''))
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings

# 전역 분석기 인스턴스
event_analyzer = EventAnalyzer()

def analyze_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """전역 함수로 이벤트 분석"""
    return event_analyzer.analyze_events(events)
