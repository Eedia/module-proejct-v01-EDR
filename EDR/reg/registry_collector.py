"""
reg/registry_collector.py
레지스트리 데이터 수집기
"""

import winreg
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import os

# utils 모듈에서 공통 구조 import
from utils.data_structures import ( 
    generate_finding_id, get_current_timestamp,
    RegistryEvidence, EvidenceSource
)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RegistryCollector:
    """레지스트리 데이터 수집 클래스"""
    
    def __init__(self):
        """초기화"""
        self.hives = {
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKCR': winreg.HKEY_CLASSES_ROOT,
            'HKU': winreg.HKEY_USERS,
            'HKCC': winreg.HKEY_CURRENT_CONFIG
        }
        
        # 보안 관련 주요 레지스트리 경로들
        self.security_keys = {
            # Windows Defender
            'defender': r"SOFTWARE\Microsoft\Windows Defender",
            'defender_features': r"SOFTWARE\Microsoft\Windows Defender\Features",
            'defender_rt_protection': r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            
            # 방화벽 설정
            'firewall_domain': r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
            'firewall_standard': r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
            'firewall_public': r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            
            # RDP 설정
            'rdp': r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            'rdp_security': r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            
            # UAC 설정
            'uac': r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            
            # SMB 설정
            'smb_client': r"SYSTEM\CurrentControlSet\Services\lanmanserver\parameters",
            'smb_server': r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            
            # 보안 정책
            'security_policy': r"SYSTEM\CurrentControlSet\Control\Lsa",
            
            # Windows Update
            'windows_update': r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        }
    
    def get_registry_value(self, hive: str, key_path: str, value_name: str = None) -> Optional[Any]:
        """레지스트리 값 조회"""
        try:
            hive_key = self.hives.get(hive.upper())
            if not hive_key:
                logger.error(f"Invalid hive: {hive}")
                return None
            
            with winreg.OpenKey(hive_key, key_path, 0, winreg.KEY_READ) as key:
                if value_name is None:
                    # 기본값 조회
                    value, reg_type = winreg.QueryValueEx(key, "")
                else:
                    value, reg_type = winreg.QueryValueEx(key, value_name)
                
                return {
                    'value': value,
                    'type': reg_type,
                    'type_name': self._get_reg_type_name(reg_type)
                }
                
        except FileNotFoundError:
            logger.debug(f"Registry key not found: {hive}\\{key_path}")
            return None
        except PermissionError:
            logger.warning(f"Permission denied accessing: {hive}\\{key_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading registry {hive}\\{key_path}\\{value_name}: {e}")
            return None
    
    def enumerate_registry_keys(self, hive: str, key_path: str) -> List[str]:
        """레지스트리 서브키 열거"""
        try:
            hive_key = self.hives.get(hive.upper())
            if not hive_key:
                return []
            
            subkeys = []
            with winreg.OpenKey(hive_key, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        subkeys.append(subkey_name)
                        index += 1
                    except OSError:
                        break
            
            return subkeys
            
        except Exception as e:
            logger.error(f"Error enumerating keys in {hive}\\{key_path}: {e}")
            return []
    
    def enumerate_registry_values(self, hive: str, key_path: str) -> List[Dict[str, Any]]:
        """레지스트리 값들 열거"""
        try:
            hive_key = self.hives.get(hive.upper())
            if not hive_key:
                return []
            
            values = []
            with winreg.OpenKey(hive_key, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                        values.append({
                            'name': value_name,
                            'data': value_data,
                            'type': value_type,
                            'type_name': self._get_reg_type_name(value_type)
                        })
                        index += 1
                    except OSError:
                        break
            
            return values
            
        except Exception as e:
            logger.error(f"Error enumerating values in {hive}\\{key_path}: {e}")
            return []
    
    def collect_security_registry_data(self) -> Dict[str, Any]:
        """보안 관련 레지스트리 데이터 수집"""
        logger.info("보안 관련 레지스트리 데이터 수집 중...")
        
        security_data = {}
        
        for category, key_path in self.security_keys.items():
            logger.debug(f"Collecting {category}: {key_path}")
            
            # HKLM에서 조회 시도
            registry_info = self._collect_key_info('HKLM', key_path)
            if registry_info:
                security_data[category] = registry_info
        
        return security_data
    
    def _collect_key_info(self, hive: str, key_path: str) -> Optional[Dict[str, Any]]:
        """특정 키의 전체 정보 수집"""
        try:
            # 키 존재 여부 확인
            hive_key = self.hives.get(hive.upper())
            if not hive_key:
                return None
            
            key_info = {
                'hive': hive,
                'path': key_path,
                'exists': False,
                'values': [],
                'subkeys': [],
                'timestamp': get_current_timestamp()
            }
            
            try:
                with winreg.OpenKey(hive_key, key_path, 0, winreg.KEY_READ) as key:
                    key_info['exists'] = True
                    
                    # 값들 수집
                    key_info['values'] = self.enumerate_registry_values(hive, key_path)
                    
                    # 서브키 수집 (1단계만)
                    key_info['subkeys'] = self.enumerate_registry_keys(hive, key_path)
                    
            except FileNotFoundError:
                key_info['exists'] = False
            except PermissionError:
                key_info['error'] = 'Permission denied'
            
            return key_info
            
        except Exception as e:
            logger.error(f"Error collecting key info for {hive}\\{key_path}: {e}")
            return None
    
    def collect_registry_data(self, target_keys: List[Tuple[str, str]] = None) -> Dict[str, Any]:
        """레지스트리 데이터 수집 (메인 함수)"""
        logger.info("레지스트리 데이터 수집 시작")
        
        collected_data = {
            'collection_timestamp': get_current_timestamp(),
            'collector_version': '1.0.0',
            'security_settings': {},
            'autorun_locations': {},
            'services': {},
            'custom_keys': {}
        }
        
        try:
            # 1. 보안 설정 수집
            collected_data['security_settings'] = self.collect_security_registry_data()
            
            # 2. 사용자 지정 키 수집 (있는 경우)
            if target_keys:
                for hive, key_path in target_keys:
                    key_name = f"{hive}_{key_path.replace('\\', '_')}"
                    collected_data['custom_keys'][key_name] = self._collect_key_info(hive, key_path)
            
            logger.info(f"레지스트리 데이터 수집 완료: {len(collected_data['security_settings'])}개 보안 키")
            return collected_data
            
        except Exception as e:
            logger.error(f"레지스트리 데이터 수집 중 오류: {e}")
            raise
    
    def _get_reg_type_name(self, reg_type: int) -> str:
        """레지스트리 타입 번호를 이름으로 변환"""
        type_map = {
            winreg.REG_NONE: 'REG_NONE',
            winreg.REG_SZ: 'REG_SZ', 
            winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
            winreg.REG_BINARY: 'REG_BINARY',
            winreg.REG_DWORD: 'REG_DWORD',
            winreg.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
            winreg.REG_LINK: 'REG_LINK',
            winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
            winreg.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
            winreg.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
            winreg.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
            winreg.REG_QWORD: 'REG_QWORD'
        }
        return type_map.get(reg_type, f'UNKNOWN_TYPE_{reg_type}')

# 전역 인스턴스
registry_collector = RegistryCollector()

# 편의 함수들
def collect_registry_data(target_keys: List[Tuple[str, str]] = None) -> Dict[str, Any]:
    """전역 함수로 레지스트리 데이터 수집"""
    return registry_collector.collect_registry_data(target_keys)

def get_registry_value(hive: str, key_path: str, value_name: str = None) -> Optional[Any]:
    """전역 함수로 레지스트리 값 조회"""
    return registry_collector.get_registry_value(hive, key_path, value_name)

def enumerate_registry_keys(hive: str, key_path: str) -> List[str]:
    """전역 함수로 레지스트리 키 열거"""
    return registry_collector.enumerate_registry_keys(hive, key_path)
