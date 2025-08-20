"""
reg/autorun_analyzer.py
자동실행 항목 분석기
"""

import os
import logging
from typing import Dict, List, Any, Optional

# utils 모듈에서 공통 구조 import
from utils.data_structures import ( 
    generate_finding_id, get_current_timestamp,
    RegistryEvidence, Category, Severity
)


from .registry_collector import registry_collector

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutoRunAnalyzer:
    """자동실행 항목 분석 클래스"""
    
    def __init__(self):
        """초기화"""
        # 자동실행 레지스트리 위치들
        self.autorun_registry_locations = {
            'current_user_run': ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            'local_machine_run': ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            'wow64_run': ('HKLM', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
        }
        
        # 의심스러운 패턴들
        self.suspicious_patterns = {
            'temp_paths': [r'\temp\\', r'\tmp\\', r'\\appdata\\local\\temp\\', r'\\windows\\temp\\'],
            'user_paths': [r'\\users\\', r'\\documents and settings\\'],
            'suspicious_extensions': ['.bat', '.cmd', '.vbs', '.js', '.jar', '.scr'],
            'suspicious_names': ['svchost', 'explorer', 'winlogon', 'csrss', 'lsass', 'smss'],
            'suspicious_locations': [r'\\programdata\\', r'\\public\\', r'\\temp\\', r'\\tmp\\'],
            'encoded_commands': ['powershell', 'cmd', '/c ', '-enc', '-e ', 'invoke-expression'],
            'network_indicators': ['http://', 'https://', 'ftp://', '.php', '.asp', '.jsp'],
            'obfuscation': ['%comspec%', '%temp%', '%appdata%', '$env:', 'invoke-', 'iex'],
        }
    
    def analyze_autorun_entries(self) -> List[Dict[str, Any]]:
        """자동실행 항목 분석 및 의심스러운 항목 탐지"""
        logger.info("자동실행 항목 분석 시작")
        
        findings = []
        
        # 레지스트리 자동실행 항목 분석
        for location_name, (hive, key_path) in self.autorun_registry_locations.items():
            try:
                values = registry_collector.enumerate_registry_values(hive, key_path)
                if values:
                    for value in values:
                        analysis_result = self._analyze_registry_autorun_entry(
                            location_name, hive, key_path, value
                        )
                        if analysis_result:
                            findings.append(analysis_result)
            except Exception as e:
                logger.debug(f"Could not access {location_name}: {e}")
        
        logger.info(f"자동실행 분석 완료: {len(findings)}개 의심스러운 항목 발견")
        return findings
    
    def _analyze_registry_autorun_entry(self, location_name: str, hive: str, key_path: str, value: Dict) -> Optional[Dict[str, Any]]:
        """레지스트리 자동실행 항목 분석"""
        value_name = value.get('name', '')
        value_data = str(value.get('data', ''))
        
        # 의심도 점수 계산
        suspicion_score = 0
        suspicion_reasons = []
        
        # 1. 경로 기반 의심도 체크
        suspicion_score += self._check_path_suspicion(value_data, suspicion_reasons)
        
        # 2. 파일명 기반 의심도 체크
        suspicion_score += self._check_filename_suspicion(value_data, suspicion_reasons)
        
        # 3. 명령어 기반 의심도 체크
        suspicion_score += self._check_command_suspicion(value_data, suspicion_reasons)
        
        # 4. 네트워크 지표 체크
        suspicion_score += self._check_network_indicators(value_data, suspicion_reasons)
        
        # 5. 파일 존재 여부 체크
        file_exists = self._check_file_existence(value_data)
        if not file_exists:
            suspicion_score += 15
            suspicion_reasons.append("참조된 파일이 존재하지 않음")
        
        # 의심스러우면 Finding 생성
        if suspicion_score >= 10 or not file_exists:
            severity = self._determine_severity(suspicion_score)
            
            finding = {
                'finding_id': generate_finding_id(),
                'rule_id': 'R_AUTORUN_SUSPICIOUS',
                'severity': severity,
                'score_impact': -min(suspicion_score, 20),
                'category': Category.PERSISTENCE.value,
                'title': f'의심스러운 자동실행 항목: {value_name}',
                'description': f'레지스트리 자동실행 위치({location_name})에서 의심스러운 항목이 발견되었습니다.',
                'timestamp': get_current_timestamp(),
                'confidence': min(90, 50 + suspicion_score * 2),
                'evidence': {
                    'registry_evidence': [{
                        'source': 'registry',
                        'hive': hive,
                        'key': key_path,
                        'value': value_name,
                        'data': value_data,
                        'type': value.get('type_name', 'Unknown'),
                        'timestamp': get_current_timestamp()
                    }],
                    'suspicion_details': {
                        'score': suspicion_score,
                        'reasons': suspicion_reasons,
                        'file_exists': file_exists,
                        'location_type': 'registry_autorun'
                    }
                },
                'mitre_attack': {
                    'tactics': ['Persistence'],
                    'techniques': ['T1547.001'],  # Registry Run Keys / Startup Folder
                    'sub_techniques': []
                }
            }
            
            return finding
        
        return None
    
    def _check_path_suspicion(self, path_string: str, reasons: List[str]) -> int:
        """경로 기반 의심도 체크"""
        score = 0
        path_lower = path_string.lower()
        
        # 임시 경로 체크
        for temp_pattern in self.suspicious_patterns['temp_paths']:
            if temp_pattern in path_lower:
                score += 25
                reasons.append(f"임시 디렉토리 경로 사용: {temp_pattern}")
                break
        
        # 사용자 경로 체크
        for user_pattern in self.suspicious_patterns['user_paths']:
            if user_pattern in path_lower:
                score += 15
                reasons.append(f"사용자 디렉토리 경로 사용: {user_pattern}")
                break
        
        # 의심스러운 위치 체크
        for suspicious_location in self.suspicious_patterns['suspicious_locations']:
            if suspicious_location in path_lower:
                score += 20
                reasons.append(f"의심스러운 경로: {suspicious_location}")
                break
        
        return score
    
    def _check_filename_suspicion(self, filename: str, reasons: List[str]) -> int:
        """파일명 기반 의심도 체크"""
        score = 0
        filename_lower = filename.lower()
        
        # 시스템 프로세스 이름 사칭 체크
        for suspicious_name in self.suspicious_patterns['suspicious_names']:
            if suspicious_name in filename_lower and not filename_lower.startswith('c:\\windows\\system32\\'):
                score += 30
                reasons.append(f"시스템 프로세스 이름 사칭: {suspicious_name}")
                break
        
        # 의심스러운 확장자 체크
        for ext in self.suspicious_patterns['suspicious_extensions']:
            if filename_lower.endswith(ext):
                score += 15
                reasons.append(f"의심스러운 파일 확장자: {ext}")
                break
        
        return score
    
    def _check_command_suspicion(self, command: str, reasons: List[str]) -> int:
        """명령어 기반 의심도 체크"""
        score = 0
        command_lower = command.lower()
        
        # 인코딩된 명령어 체크
        for encoded_indicator in self.suspicious_patterns['encoded_commands']:
            if encoded_indicator in command_lower:
                score += 25
                reasons.append(f"인코딩된 명령어 사용: {encoded_indicator}")
        
        # 난독화 기법 체크
        for obfuscation_indicator in self.suspicious_patterns['obfuscation']:
            if obfuscation_indicator in command_lower:
                score += 20
                reasons.append(f"난독화 기법 사용: {obfuscation_indicator}")
        
        return score
    
    def _check_network_indicators(self, command: str, reasons: List[str]) -> int:
        """네트워크 지표 체크"""
        score = 0
        command_lower = command.lower()
        
        # 네트워크 URL 체크
        for network_indicator in self.suspicious_patterns['network_indicators']:
            if network_indicator in command_lower:
                score += 30
                reasons.append(f"네트워크 연결 지표: {network_indicator}")
        
        return score
    
    def _check_file_existence(self, command: str) -> bool:
        """파일 존재 여부 체크"""
        try:
            # 명령어에서 실행 파일 경로 추출
            command = command.strip().strip('"')
            
            # 명령어 인자 제거 (첫 번째 공백까지)
            if ' ' in command:
                file_path = command.split(' ')[0].strip('"')
            else:
                file_path = command
            
            # 환경 변수 확장
            file_path = os.path.expandvars(file_path)
            
            return os.path.exists(file_path)
        except:
            return True  # 오류 시 존재하는 것으로 간주
    
    def _determine_severity(self, suspicion_score: int) -> str:
        """의심도 점수에 따른 심각도 결정"""
        if suspicion_score >= 50:
            return Severity.CRITICAL.value
        elif suspicion_score >= 30:
            return Severity.HIGH.value
        elif suspicion_score >= 15:
            return Severity.MEDIUM.value
        else:
            return Severity.LOW.value
    
    def get_all_autorun_locations(self) -> Dict[str, Any]:
        """모든 자동실행 위치 수집"""
        logger.info("자동실행 위치 수집 중...")
        
        autorun_data = {
            'registry_locations': {},
            'collection_timestamp': get_current_timestamp()
        }
        
        # 레지스트리 자동실행 위치 수집
        for location_name, (hive, key_path) in self.autorun_registry_locations.items():
            try:
                values = registry_collector.enumerate_registry_values(hive, key_path)
                if values:
                    autorun_data['registry_locations'][location_name] = {
                        'hive': hive,
                        'path': key_path,
                        'values': values,
                        'count': len(values)
                    }
                    logger.debug(f"Found {len(values)} entries in {location_name}")
            except Exception as e:
                logger.debug(f"Could not access {location_name}: {e}")
        
        return autorun_data

# 전역 인스턴스
autorun_analyzer = AutoRunAnalyzer()

# 편의 함수들
def analyze_autorun_entries() -> List[Dict[str, Any]]:
    """전역 함수로 자동실행 항목 분석"""
    return autorun_analyzer.analyze_autorun_entries()

def get_all_autorun_locations() -> Dict[str, Any]:
    """전역 함수로 자동실행 위치 수집"""
    return autorun_analyzer.get_all_autorun_locations()
