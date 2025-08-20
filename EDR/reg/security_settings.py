"""
reg/security_settings.py
보안 설정 상태 점검 분석기
"""

import logging
import subprocess
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

class SecuritySettingsAnalyzer:
    """보안 설정 상태 점검 분석 클래스"""
    
    def __init__(self):
        """초기화"""
        # 중요한 보안 설정들과 기대값
        self.security_checks = {
            'windows_defender': {
                'path': ('HKLM', r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'),
                'checks': [
                    ('DisableRealtimeMonitoring', 0, '실시간 보호가 비활성화됨'),
                    ('DisableBehaviorMonitoring', 0, '행동 모니터링이 비활성화됨'),
                    ('DisableOnAccessProtection', 0, '액세스 보호가 비활성화됨'),
                ]
            },
            'uac_settings': {
                'path': ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'),
                'checks': [
                    ('EnableLUA', 1, 'UAC가 비활성화됨'),
                    ('ConsentPromptBehaviorAdmin', [2, 5], 'UAC 관리자 승인 모드가 약함'),
                    ('PromptOnSecureDesktop', 1, 'UAC 보안 데스크톱이 비활성화됨')
                ]
            },
            'rdp_settings': {
                'path': ('HKLM', r'SYSTEM\CurrentControlSet\Control\Terminal Server'),
                'checks': [
                    ('fDenyTSConnections', 1, 'RDP가 활성화됨'),
                ]
            },
            'firewall_domain': {
                'path': ('HKLM', r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'),
                'checks': [
                    ('EnableFirewall', 1, '도메인 방화벽이 비활성화됨'),
                ]
            },
        }
        
        # 심각도별 가중치
        self.severity_weights = {
            'critical': 30,
            'high': 20,
            'medium': 10,
            'low': 5
        }
    
    def analyze_security_settings(self) -> List[Dict[str, Any]]:
        """보안 설정 분석 및 취약점 탐지"""
        logger.info("보안 설정 분석 시작")
        
        findings = []
        
        # 각 보안 설정 카테고리별로 검사
        for category_name, category_config in self.security_checks.items():
            category_findings = self._analyze_security_category(category_name, category_config)
            findings.extend(category_findings)
        
        logger.info(f"보안 설정 분석 완료: {len(findings)}개 취약점 발견")
        return findings
    
    def _analyze_security_category(self, category_name: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """개별 보안 설정 카테고리 분석"""
        findings = []
        hive, reg_path = config['path']
        checks = config['checks']
        
        try:
            # 레지스트리 값들 조회
            registry_values = registry_collector.enumerate_registry_values(hive, reg_path)
            if not registry_values:
                return findings
            
            # 값을 딕셔너리로 변환
            values_dict = {}
            for value in registry_values:
                values_dict[value.get('name', '')] = value.get('data')
            
            # 각 체크 항목 검사
            for check_name, expected_value, issue_description in checks:
                current_value = values_dict.get(check_name)
                
                if current_value is not None and not self._check_value_compliance(current_value, expected_value):
                    # 값이 기대값과 다른 경우
                    finding = self._create_non_compliant_finding(
                        category_name, hive, reg_path, check_name, 
                        current_value, expected_value, issue_description
                    )
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            logger.error(f"Error analyzing security category {category_name}: {e}")
        
        return findings
    
    def _check_value_compliance(self, current_value: Any, expected_value: Any) -> bool:
        """값이 기대값과 일치하는지 확인"""
        if isinstance(expected_value, list):
            return current_value in expected_value
        else:
            return current_value == expected_value
    
    def _create_non_compliant_finding(self, category_name: str, hive: str, reg_path: str,
                                     value_name: str, current_value: Any, expected_value: Any,
                                     issue_description: str) -> Optional[Dict[str, Any]]:
        """값이 기대값과 다른 경우 Finding 생성"""
        severity = self._determine_setting_severity(category_name, issue_description)
        
        finding = {
            'finding_id': generate_finding_id(),
            'rule_id': f'R_SECURITY_{category_name.upper()}_NON_COMPLIANT',
            'severity': severity,
            'score_impact': -self.severity_weights.get(severity, 10),
            'category': Category.SECURITY_SETTINGS.value,
            'title': f'보안 설정 취약: {value_name}',
            'description': f'보안 설정이 권장값과 다릅니다: {issue_description}',
            'timestamp': get_current_timestamp(),
            'confidence': 95,
            'evidence': {
                'registry_evidence': [{
                    'source': 'registry',
                    'hive': hive,
                    'key': reg_path,
                    'value': value_name,
                    'current_value': current_value,
                    'expected_value': expected_value,
                    'issue': issue_description,
                    'timestamp': get_current_timestamp()
                }]
            },
            'mitre_attack': {
                'tactics': ['Defense Evasion'],
                'techniques': ['T1562.001'],  # Disable or Modify Tools
                'sub_techniques': []
            }
        }
        return finding
    
    def _determine_setting_severity(self, category_name: str, issue_description: str) -> str:
        """보안 설정 심각도 결정"""
        # 카테고리와 이슈 설명에 따른 심각도 결정
        high_risk_keywords = ['비활성화', 'RDP가 활성화', '방화벽이 비활성화', 'UAC가 비활성화']
        medium_risk_keywords = ['약함', '필수가 아님', '제한이 비활성화']
        
        issue_lower = issue_description.lower()
        
        if any(keyword in issue_lower for keyword in high_risk_keywords):
            return Severity.HIGH.value
        elif any(keyword in issue_lower for keyword in medium_risk_keywords):
            return Severity.MEDIUM.value
        elif 'defender' in category_name.lower() or 'uac' in category_name.lower():
            return Severity.HIGH.value
        elif 'firewall' in category_name.lower() or 'rdp' in category_name.lower():
            return Severity.MEDIUM.value
        else:
            return Severity.LOW.value
    
    def check_critical_settings(self) -> Dict[str, Any]:
        """중요 보안 설정만 빠르게 체크"""
        critical_results = {
            'total_issues': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'issues': []
        }
        
        critical_checks = ['windows_defender', 'uac_settings', 'firewall_domain']
        
        for check_name in critical_checks:
            if check_name in self.security_checks:
                findings = self._analyze_security_category(check_name, self.security_checks[check_name])
                for finding in findings:
                    critical_results['issues'].append({
                        'category': check_name,
                        'severity': finding['severity'],
                        'title': finding['title'],
                        'description': finding['description']
                    })
                    
                    critical_results['total_issues'] += 1
                    if finding['severity'] == Severity.CRITICAL.value:
                        critical_results['critical_issues'] += 1
                    elif finding['severity'] == Severity.HIGH.value:
                        critical_results['high_issues'] += 1
        
        return critical_results

# 전역 인스턴스
security_settings_analyzer = SecuritySettingsAnalyzer()

# 편의 함수들
def analyze_security_settings() -> List[Dict[str, Any]]:
    """전역 함수로 보안 설정 분석"""
    return security_settings_analyzer.analyze_security_settings()

def check_critical_settings() -> Dict[str, Any]:
    """전역 함수로 중요 보안 설정 체크"""
    return security_settings_analyzer.check_critical_settings()
