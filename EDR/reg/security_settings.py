"""
reg/security_settings.py
보안 설정 상태 점검 분석기 - 새로운 룰 엔진 기반
"""

import logging
import subprocess
from typing import Dict, List, Any, Optional

# 새로운 룰 엔진 임포트
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from rules.legacy_adapter import LegacyAdapter
from utils.data_structures import Finding, generate_finding_id, get_current_timestamp
from .registry_collector import registry_collector

logger = logging.getLogger(__name__)

class SecuritySettingsAnalyzer:
    """보안 설정 상태 점검 분석 클래스 - 룰 엔진 기반"""
    
    def __init__(self, rules_dir: str = "rules"):
        """초기화"""
        self.rule_engine = RuleEngine(rules_dir)
        self.legacy_adapter = LegacyAdapter(rules_dir)
        
        # 중요한 보안 설정들과 경로
        self.security_settings_paths = {

            # Defender 관련 설정
            'windows_defender': ('HKLM', r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'),

            # UAC 관련 설정
            'uac_settings': ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
            
            # RDP 관련 설정
            'rdp_settings': ('HKLM', r'SYSTEM\CurrentControlSet\Control\Terminal Server'),
            'rdp_tcp':  ('HKLM', r'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'),
            'rdp_policy': ('HKLM', r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'),


            # FireWall 관련 설정
            'firewall_settings': ('HKLM', r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'),
            'firewall_standard': ('HKLM', r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'),
            'firewall_domain':   ('HKLM', r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'),
            'firewall_public':   ('HKLM', r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'),

            # SMB 관련 설정
            'smb_settings': ('HKLM', r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'),
            'lanman_workstation': ('HKLM', r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'),

            # Windows Update 관련 설정
            'update_settings': ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'),
            # IE 캐시
            'ie_cache_persistent': ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache'),

            'ps_execpolicy':    ('HKLM', r'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'),

            'wdigest': ('HKLM', r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'),
            'lsa':     ('HKLM', r'SYSTEM\CurrentControlSet\Control\Lsa'),
        }
        
        logger.info("보안 설정 분석기 초기화 완료 - 룰 엔진 기반")
    
    def analyze_security_settings(self) -> List[Dict[str, Any]]:
        """보안 설정 상태 점검 및 취약점 탐지"""
        logger.info("보안 설정 분석 시작")
        
        all_findings = []
        
        # 레지스트리 기반 보안 설정 분석
        all_findings.extend(self._analyze_registry_settings())
        
        # PowerShell 기반 추가 설정 분석
        all_findings.extend(self._analyze_powershell_settings())
        
        logger.info(f"보안 설정 분석 완료: {len(all_findings)}개 탐지")
        return all_findings
    
    def _analyze_registry_settings(self) -> List[Dict[str, Any]]:
        """레지스트리 기반 보안 설정 분석"""
        findings = []
        
        for setting_name, (hive, subkey) in self.security_settings_paths.items():
            try:
                # 레지스트리 값 수집
                registry_values = registry_collector.get_registry_values(hive, subkey)
                
                for value_name, value_data in registry_values.items():
                    # 룰 엔진용 데이터 구조 생성
                    security_data = {
                        'key_path': f"{hive}\\{subkey}",
                        'value_name': value_name,
                        'value_data': str(value_data),
                        'setting_category': setting_name,
                        'timestamp': get_current_timestamp()
                    }
                    
                    # 룰 엔진으로 분석
                    setting_findings = self.rule_engine.analyze_registry_data(security_data)
                    
                    # Finding 객체를 딕셔너리로 변환
                    for finding in setting_findings:
                        finding_dict = self._finding_to_dict(finding)
                        findings.append(finding_dict)
                        
            except Exception as e:
                logger.debug(f"보안 설정 분석 중 오류 ({setting_name}): {e}")
                continue
        
        return findings
    
    def _analyze_powershell_settings(self) -> List[Dict[str, Any]]:
        """PowerShell 기반 추가 보안 설정 분석"""
        findings = []
        
        # Windows Defender 상태 확인
        findings.extend(self._check_windows_defender())
        
        # 방화벽 상태 확인
        findings.extend(self._check_firewall_status())
        
        # Windows Update 상태 확인
        findings.extend(self._check_windows_update())
        
        return findings
    
    def _check_windows_defender(self) -> List[Dict[str, Any]]:
        """Windows Defender 상태 확인"""
        findings = []
        
        try:
            # Get-MpComputerStatus PowerShell 명령어
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus | ConvertTo-Json'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=30
            )
            
            if result.returncode == 0:
                import json
                defender_status = json.loads(result.stdout)
                
                # 룰 엔진용 데이터 구조 생성
                defender_data = {
                    'setting_type': 'windows_defender_status',
                    'real_time_protection': str(defender_status.get('RealTimeProtectionEnabled', False)),
                    'behavior_monitor': str(defender_status.get('BehaviorMonitorEnabled', False)),
                    'antivirus_enabled': str(defender_status.get('AntivirusEnabled', False)),
                    'signature_version': str(defender_status.get('AntivirusSignatureVersion', 'Unknown')),
                    'timestamp': get_current_timestamp()
                }
                
                # 룰 엔진으로 분석
                defender_findings = self.rule_engine.analyze_registry_data(defender_data)
                
                # Finding 객체를 딕셔너리로 변환
                for finding in defender_findings:
                    finding_dict = self._finding_to_dict(finding)
                    findings.append(finding_dict)
                    
        except Exception as e:
            logger.debug(f"Windows Defender 상태 확인 중 오류: {e}")
        
        return findings
    
    def _check_firewall_status(self) -> List[Dict[str, Any]]:
        """방화벽 상태 확인"""
        findings = []
        
        try:
            # netsh advfirewall show allprofiles 명령어
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=30
            )
            
            if result.returncode == 0:
                firewall_output = result.stdout
                
                # 룰 엔진용 데이터 구조 생성
                firewall_data = {
                    'setting_type': 'firewall_status',
                    'firewall_output': firewall_output,
                    'domain_profile': 'ON' if 'Domain Profile' in firewall_output and 'ON' in firewall_output else 'OFF',
                    'private_profile': 'ON' if 'Private Profile' in firewall_output and 'ON' in firewall_output else 'OFF',
                    'public_profile': 'ON' if 'Public Profile' in firewall_output and 'ON' in firewall_output else 'OFF',
                    'timestamp': get_current_timestamp()
                }
                
                # 룰 엔진으로 분석
                firewall_findings = self.rule_engine.analyze_registry_data(firewall_data)
                
                # Finding 객체를 딕셔너리로 변환
                for finding in firewall_findings:
                    finding_dict = self._finding_to_dict(finding)
                    findings.append(finding_dict)
                    
        except Exception as e:
            logger.debug(f"방화벽 상태 확인 중 오류: {e}")
        
        return findings
    
    def _check_windows_update(self) -> List[Dict[str, Any]]:
        """Windows Update 상태 확인"""
        findings = []
        
        try:
            # Get-WUList PowerShell 명령어 (PSWindowsUpdate 모듈 필요)
            # 대신 wuauclt 상태 확인
            result = subprocess.run(
                ['powershell', '-Command', 'Get-Service -Name wuauserv | Select-Object Status, StartType | ConvertTo-Json'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=30
            )
            
            if result.returncode == 0:
                import json
                update_service = json.loads(result.stdout)
                
                # 룰 엔진용 데이터 구조 생성
                update_data = {
                    'setting_type': 'windows_update_status',
                    'service_status': str(update_service.get('Status', 'Unknown')),
                    'start_type': str(update_service.get('StartType', 'Unknown')),
                    'timestamp': get_current_timestamp()
                }
                
                # 룰 엔진으로 분석
                update_findings = self.rule_engine.analyze_registry_data(update_data)
                
                # Finding 객체를 딕셔너리로 변환
                for finding in update_findings:
                    finding_dict = self._finding_to_dict(finding)
                    findings.append(finding_dict)
                    
        except Exception as e:
            logger.debug(f"Windows Update 상태 확인 중 오류: {e}")
        
        return findings
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Finding 객체를 기존 형식의 딕셔너리로 변환"""
        rule = self.rule_engine.get_rule_by_id(finding.rule_id)
        
        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "score_impact": -finding.score_impact,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "confidence": finding.confidence,
            "timestamp": finding.timestamp,
            "evidence": finding.evidence,
            "mitre_attack": {
                "tactics": rule.get('tactics', []) if rule else [],
                "techniques": rule.get('techniques', []) if rule else []
            }
        }

# 전역 분석기 인스턴스
_global_analyzer = None

def get_security_settings_analyzer() -> SecuritySettingsAnalyzer:
    """전역 보안 설정 분석기 인스턴스 반환"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = SecuritySettingsAnalyzer()
    return _global_analyzer

def analyze_security_settings() -> List[Dict[str, Any]]:
    """전역 함수로 보안 설정 분석 (기존 호환성 유지)"""
    analyzer = get_security_settings_analyzer()
    return analyzer.analyze_security_settings()

# 기존 호환성
security_settings_analyzer = get_security_settings_analyzer()
