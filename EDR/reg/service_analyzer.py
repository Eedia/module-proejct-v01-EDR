"""
reg/service_analyzer.py
서비스 등록 분석기
"""

import logging
import subprocess
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

# utils 모듈에서 공통 구조 import
from utils.data_structures import (
    generate_finding_id, get_current_timestamp,
    RegistryEvidence, Category, Severity
)

from .registry_collector import registry_collector

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ServiceAnalyzer:
    """서비스 등록 분석 클래스"""
    
    def __init__(self):
        """초기화"""
        # 서비스 관련 레지스트리 경로
        self.service_registry_paths = {
            'services': ('HKLM', r'SYSTEM\CurrentControlSet\Services'),
            'services_wow64': ('HKLM', r'SYSTEM\CurrentControlSet\Services\WOW6432Node')
        }
        
        # 의심스러운 서비스 패턴
        self.suspicious_patterns = {
            'temp_paths': [r'\temp\\', r'\tmp\\', r'\\appdata\\local\\temp\\', r'\\windows\\temp\\'],
            'user_paths': [r'\\users\\', r'\\documents and settings\\', r'\\programdata\\'],
            'suspicious_extensions': ['.bat', '.cmd', '.vbs', '.js', '.jar', '.scr', '.ps1'],
            'suspicious_names': ['svchost', 'services', 'winlogon', 'csrss', 'lsass', 'smss'],
            'suspicious_locations': [r'\\public\\', r'\\downloads\\', r'\\desktop\\'],
            'network_indicators': ['http://', 'https://', 'ftp://', '.php', '.asp', '.jsp'],
            'obfuscation': ['%comspec%', '%temp%', '%appdata%', '$env:', 'powershell'],
        }
        
        # 정상적인 Windows 서비스 경로들
        self.legitimate_service_paths = [
            r'c:\windows\system32\\',
            r'c:\windows\syswow64\\',
            r'c:\program files\\',
            r'c:\program files (x86)\\',
        ]
        
        # 높은 권한이 필요한 서비스 타입
        self.privileged_service_types = [
            'kernel driver',
            'file system driver', 
            'system',
            'interactive'
        ]
    
    def get_all_services(self) -> Dict[str, Any]:
        """모든 서비스 정보 수집"""
        logger.info("서비스 정보 수집 중...")
        
        services_data = {
            'registry_services': {},
            'running_services': {},
            'collection_timestamp': get_current_timestamp()
        }
        
        # 1. 레지스트리에서 서비스 정보 수집
        services_data['registry_services'] = self._collect_registry_services()
        
        # 2. 실행 중인 서비스 정보 수집 (sc 명령어 사용)
        services_data['running_services'] = self._collect_running_services()
        
        return services_data
    
    def _collect_registry_services(self) -> Dict[str, Any]:
        """레지스트리에서 서비스 정보 수집"""
        registry_services = {}
        
        try:
            # Services 키 하위의 모든 서비스 열거
            service_names = registry_collector.enumerate_registry_keys('HKLM', 
                self.service_registry_paths['services'][1])
            
            logger.debug(f"Found {len(service_names)} services in registry")
            
            for service_name in service_names[:100]:  # 처리량 제한 (상위 100개)
                try:
                    service_path = f"{self.service_registry_paths['services'][1]}\\{service_name}"
                    service_values = registry_collector.enumerate_registry_values('HKLM', service_path)
                    
                    if service_values:
                        # 서비스 정보 파싱
                        service_info = self._parse_service_registry_data(service_name, service_values)
                        if service_info:
                            registry_services[service_name] = service_info
                            
                except Exception as e:
                    logger.debug(f"Error collecting service {service_name}: {e}")
            
        except Exception as e:
            logger.error(f"Error collecting registry services: {e}")
        
        return registry_services
    
    def _parse_service_registry_data(self, service_name: str, values: List[Dict]) -> Optional[Dict[str, Any]]:
        """서비스 레지스트리 데이터 파싱"""
        service_info = {
            'name': service_name,
            'display_name': '',
            'image_path': '',
            'start_type': '',
            'service_type': '',
            'description': '',
            'object_name': '',
            'error_control': '',
            'dependencies': []
        }
        
        try:
            for value in values:
                value_name = value.get('name', '').lower()
                value_data = value.get('data', '')
                
                if value_name == 'displayname':
                    service_info['display_name'] = str(value_data)
                elif value_name == 'imagepath':
                    service_info['image_path'] = str(value_data)
                elif value_name == 'start':
                    service_info['start_type'] = self._get_start_type_name(value_data)
                elif value_name == 'type':
                    service_info['service_type'] = self._get_service_type_name(value_data)
                elif value_name == 'description':
                    service_info['description'] = str(value_data)
                elif value_name == 'objectname':
                    service_info['object_name'] = str(value_data)
                elif value_name == 'errorcontrol':
                    service_info['error_control'] = self._get_error_control_name(value_data)
                elif value_name == 'dependonservice':
                    if isinstance(value_data, list):
                        service_info['dependencies'] = value_data
                    else:
                        service_info['dependencies'] = [str(value_data)]
            
            return service_info
            
        except Exception as e:
            logger.debug(f"Error parsing service data for {service_name}: {e}")
            return None
    
    def _collect_running_services(self) -> Dict[str, Any]:
        """실행 중인 서비스 정보 수집"""
        running_services = {}
        
        try:
            # sc query 명령어로 실행 중인 서비스 조회
            result = subprocess.run(['sc', 'query'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                services_text = result.stdout
                running_services = self._parse_sc_query_output(services_text)
                logger.debug(f"Found {len(running_services)} running services")
            else:
                logger.warning("Failed to query running services with sc command")
                
        except subprocess.TimeoutExpired:
            logger.warning("Service query timed out")
        except Exception as e:
            logger.error(f"Error collecting running services: {e}")
        
        return running_services
    
    def _parse_sc_query_output(self, output: str) -> Dict[str, Any]:
        """sc query 출력 파싱"""
        services = {}
        current_service = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current_service.get('name'):
                    services[current_service['name']] = current_service
                    current_service = {}
                continue
            
            if line.startswith('SERVICE_NAME:'):
                current_service['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('DISPLAY_NAME:'):
                current_service['display_name'] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE'):
                state_info = line.split(':', 1)[1].strip()
                current_service['state'] = state_info.split()[0]
        
        # 마지막 서비스 추가
        if current_service.get('name'):
            services[current_service['name']] = current_service
        
        return services
    
    def analyze_services(self) -> List[Dict[str, Any]]:
        """서비스 분석 및 의심스러운 서비스 탐지"""
        logger.info("서비스 분석 시작")
        
        findings = []
        
        # 1. 서비스 데이터 수집
        services_data = self.get_all_services()
        
        # 2. 레지스트리 서비스 분석
        for service_name, service_info in services_data.get('registry_services', {}).items():
            analysis_result = self._analyze_service(service_name, service_info)
            if analysis_result:
                findings.append(analysis_result)
        
        logger.info(f"서비스 분석 완료: {len(findings)}개 의심스러운 서비스 발견")
        return findings
    
    def _analyze_service(self, service_name: str, service_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """개별 서비스 분석"""
        image_path = service_info.get('image_path', '').lower()
        if not image_path:
            return None
        
        # 의심도 점수 계산
        suspicion_score = 0
        suspicion_reasons = []
        
        # 1. 이미지 경로 분석
        suspicion_score += self._check_service_path_suspicion(image_path, suspicion_reasons)
        
        # 2. 서비스 타입 분석
        suspicion_score += self._check_service_type_suspicion(service_info, suspicion_reasons)
        
        # 3. 서비스 이름 분석
        suspicion_score += self._check_service_name_suspicion(service_name, service_info, suspicion_reasons)
        
        # 4. 실행 권한 분석
        suspicion_score += self._check_service_privileges(service_info, suspicion_reasons)
        
        # 5. 파일 존재 여부 체크
        file_exists = self._check_service_file_existence(image_path)
        if not file_exists:
            suspicion_score += 20
            suspicion_reasons.append("서비스 실행 파일이 존재하지 않음")
        
        # 의심스러우면 Finding 생성
        if suspicion_score >= 15:
            severity = self._determine_severity(suspicion_score)
            
            finding = {
                'finding_id': generate_finding_id(),
                'rule_id': 'R_SERVICE_SUSPICIOUS',
                'severity': severity,
                'score_impact': -min(suspicion_score, 25),
                'category': Category.PERSISTENCE.value,
                'title': f'의심스러운 서비스: {service_name}',
                'description': f'시스템에서 의심스러운 서비스가 발견되었습니다.',
                'timestamp': get_current_timestamp(),
                'confidence': min(95, 60 + suspicion_score),
                'evidence': {
                    'registry_evidence': [{
                        'source': 'registry',
                        'hive': 'HKLM',
                        'key': f"{self.service_registry_paths['services'][1]}\\{service_name}",
                        'service_info': service_info,
                        'timestamp': get_current_timestamp()
                    }],
                    'suspicion_details': {
                        'score': suspicion_score,
                        'reasons': suspicion_reasons,
                        'file_exists': file_exists
                    }
                },
                'mitre_attack': {
                    'tactics': ['Persistence', 'Privilege Escalation'],
                    'techniques': ['T1543.003'],  # Windows Service
                    'sub_techniques': []
                }
            }
            
            return finding
        
        return None
    
    def _check_service_path_suspicion(self, image_path: str, reasons: List[str]) -> int:
        """서비스 경로 의심도 체크"""
        score = 0
        
        # 정상적인 경로인지 체크
        is_legitimate = False
        for legitimate_path in self.legitimate_service_paths:
            if image_path.startswith(legitimate_path):
                is_legitimate = True
                break
        
        if not is_legitimate:
            score += 20
            reasons.append("비정상적인 서비스 경로")
        
        # 의심스러운 경로 패턴 체크
        for temp_pattern in self.suspicious_patterns['temp_paths']:
            if temp_pattern in image_path:
                score += 30
                reasons.append(f"임시 디렉토리 경로: {temp_pattern}")
                break
        
        for user_pattern in self.suspicious_patterns['user_paths']:
            if user_pattern in image_path:
                score += 25
                reasons.append(f"사용자 디렉토리 경로: {user_pattern}")
                break
        
        # 네트워크 지표 체크
        for network_indicator in self.suspicious_patterns['network_indicators']:
            if network_indicator in image_path:
                score += 35
                reasons.append(f"네트워크 지표 포함: {network_indicator}")
                break
        
        return score
    
    def _check_service_type_suspicion(self, service_info: Dict, reasons: List[str]) -> int:
        """서비스 타입 의심도 체크"""
        score = 0
        service_type = service_info.get('service_type', '').lower()
        start_type = service_info.get('start_type', '').lower()
        
        # 커널 드라이버나 시스템 서비스의 경우 더 엄격하게 체크
        if service_type in ['kernel driver', 'file system driver']:
            score += 10
            reasons.append("커널 레벨 서비스")
        
        # 자동 시작 서비스인 경우
        if start_type in ['automatic', 'boot', 'system']:
            score += 5
            reasons.append("자동 시작 서비스")
        
        return score
    
    def _check_service_name_suspicion(self, service_name: str, service_info: Dict, reasons: List[str]) -> int:
        """서비스 이름 의심도 체크"""
        score = 0
        service_name_lower = service_name.lower()
        display_name = service_info.get('display_name', '').lower()
        
        # 시스템 서비스 이름 사칭 체크
        for suspicious_name in self.suspicious_patterns['suspicious_names']:
            if suspicious_name in service_name_lower and service_name_lower != suspicious_name:
                score += 25
                reasons.append(f"시스템 서비스 이름 사칭: {suspicious_name}")
                break
        
        # 랜덤한 이름 패턴 체크
        if len(service_name) <= 3:
            score += 15
            reasons.append("서비스 이름이 너무 짧음")
        
        # 숫자로만 이루어진 서비스명
        if service_name.isdigit():
            score += 20
            reasons.append("숫자로만 이루어진 서비스명")
        
        # Display Name이 없는 경우
        if not display_name:
            score += 5
            reasons.append("Display Name이 없음")
        
        return score
    
    def _check_service_privileges(self, service_info: Dict, reasons: List[str]) -> int:
        """서비스 실행 권한 체크"""
        score = 0
        object_name = service_info.get('object_name', '').lower()
        
        # LocalSystem 권한으로 실행되는 서비스
        if object_name == 'localsystem':
            score += 10
            reasons.append("LocalSystem 권한으로 실행")
        
        return score
    
    def _check_service_file_existence(self, image_path: str) -> bool:
        """서비스 파일 존재 여부 체크"""
        try:
            import os
            import re
            
            # 명령어 인자 제거
            clean_path = image_path.strip().strip('"')
            
            # 인자가 있는 경우 제거
            if ' ' in clean_path:
                clean_path = clean_path.split(' ')[0].strip('"')
            
            # 환경 변수 확장
            clean_path = os.path.expandvars(clean_path)
            
            return os.path.exists(clean_path)
        except:
            return True  # 오류 시 존재하는 것으로 간주
    
    def _determine_severity(self, suspicion_score: int) -> str:
        """의심도 점수에 따른 심각도 결정"""
        if suspicion_score >= 60:
            return Severity.CRITICAL.value
        elif suspicion_score >= 40:
            return Severity.HIGH.value
        elif suspicion_score >= 20:
            return Severity.MEDIUM.value
        else:
            return Severity.LOW.value
    
    def _get_start_type_name(self, start_value: int) -> str:
        """서비스 시작 타입 변환"""
        start_types = {
            0: 'Boot',
            1: 'System', 
            2: 'Automatic',
            3: 'Manual',
            4: 'Disabled'
        }
        return start_types.get(start_value, f'Unknown({start_value})')
    
    def _get_service_type_name(self, type_value: int) -> str:
        """서비스 타입 변환"""
        service_types = {
            1: 'Kernel Driver',
            2: 'File System Driver',
            4: 'Adapter',
            16: 'Win32 Own Process',
            32: 'Win32 Share Process',
            256: 'Interactive Process'
        }
        return service_types.get(type_value, f'Unknown({type_value})')
    
    def _get_error_control_name(self, error_value: int) -> str:
        """에러 컨트롤 타입 변환"""
        error_controls = {
            0: 'Ignore',
            1: 'Normal',
            2: 'Severe',
            3: 'Critical'
        }
        return error_controls.get(error_value, f'Unknown({error_value})')
    
    def get_suspicious_services(self) -> List[Dict[str, Any]]:
        """의심스러운 서비스 목록만 반환"""
        return self.analyze_services()

# 전역 인스턴스
service_analyzer = ServiceAnalyzer()

# 편의 함수들
def analyze_services() -> List[Dict[str, Any]]:
    """전역 함수로 서비스 분석"""
    return service_analyzer.analyze_services()

def get_suspicious_services() -> List[Dict[str, Any]]:
    """전역 함수로 의심스러운 서비스 조회"""
    return service_analyzer.get_suspicious_services()
