"""
마이그레이션 어댑터 - 기존 코드와 새 룰 엔진 연결
기존 분석기들이 새로운 룰 엔진을 사용하도록 어댑터 패턴 적용
"""

import logging
from typing import Dict, List, Any, Optional

from rules.rule_engine import RuleEngine
from utils.data_structures import Finding

class LegacyAdapter:
    """기존 코드와 새 룰 엔진을 연결하는 어댑터"""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rule_engine = RuleEngine(rules_dir)
        self.logger = logging.getLogger(__name__)
    
    # ========== 이벤트 로그 분석기 어댑터 ==========
    
    def analyze_lolbin_activity(self, event_data: Dict[str, Any]) -> List[Finding]:
        """LOLBin 활동 분석 (기존 analyzer.py 대체)"""
        return self._analyze_with_rules(event_data, ['R_LOLBIN_RUNDLL32_JS', 'R_LOLBIN_RUNDLL32_URL', 'R_LOLBIN_REGSVR32_URL'])
    
    def analyze_powershell_activity(self, event_data: Dict[str, Any]) -> List[Finding]:
        """PowerShell 활동 분석 (기존 analyzer.py 대체)"""
        return self._analyze_with_rules(event_data, ['R_POWERSHELL_ENCODED', 'R_POWERSHELL_BYPASS_POLICY', 'R_POWERSHELL_AMSI_BYPASS'])
    
    def analyze_rdp_activity(self, event_data: Dict[str, Any]) -> List[Finding]:
        """RDP 활동 분석 (기존 analyzer.py 대체)"""
        return self._analyze_with_rules(event_data, ['R_RDP_NONBUSINESS_HOURS', 'R_ADMIN_RDP_LOGON'])
    
    def analyze_service_installation(self, event_data: Dict[str, Any]) -> List[Finding]:
        """서비스 설치 분석 (기존 analyzer.py 대체)"""
        return self._analyze_with_rules(event_data, ['R_SERVICE_TEMP_PATH'])
    
    # ========== 레지스트리 분석기 어댑터 ==========
    
    def analyze_autorun_entries(self, registry_data: Dict[str, Any]) -> List[Finding]:
        """자동실행 항목 분석 (기존 autorun_analyzer.py 대체)"""
        return self._analyze_registry_with_rules(registry_data, ['R_AUTORUN_SUSPICIOUS'])
    
    def analyze_service_registry(self, registry_data: Dict[str, Any]) -> List[Finding]:
        """서비스 레지스트리 분석 (기존 service_analyzer.py 대체)"""
        return self._analyze_registry_with_rules(registry_data, ['R_SERVICE_SUSPICIOUS'])
    
    def analyze_security_settings(self, registry_data: Dict[str, Any]) -> List[Finding]:
        """보안 설정 분석 (기존 security_settings.py 대체)"""
        return self._analyze_registry_with_rules(registry_data, ['R_SECURITY_SETTINGS_NON_COMPLIANT'])
    
    # ========== 내부 헬퍼 메서드 ==========
    
    def _analyze_with_rules(self, event_data: Dict[str, Any], rule_ids: List[str]) -> List[Finding]:
        """특정 룰들로 이벤트 분석"""
        findings = []
        
        for rule_id in rule_ids:
            rule = self.rule_engine.get_rule_by_id(rule_id)
            if rule and rule.get('data_source') == 'event_log':
                try:
                    if self.rule_engine._match_event_rule(event_data, rule):
                        finding = self.rule_engine._create_finding(rule_id, rule, event_data)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    self.logger.error(f"룰 {rule_id} 처리 실패: {e}")
        
        return findings
    
    def _analyze_registry_with_rules(self, registry_data: Dict[str, Any], rule_ids: List[str]) -> List[Finding]:
        """특정 룰들로 레지스트리 분석"""
        findings = []
        
        for rule_id in rule_ids:
            rule = self.rule_engine.get_rule_by_id(rule_id)
            if rule and rule.get('data_source') == 'registry':
                try:
                    if self.rule_engine._match_registry_rule(registry_data, rule):
                        finding = self.rule_engine._create_finding(rule_id, rule, registry_data)
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    self.logger.error(f"룰 {rule_id} 처리 실패: {e}")
        
        return findings
    
    # ========== 기존 함수들과 호환성 유지 ==========
    
    def check_rundll32_js_execution(self, event_data: Dict[str, Any]) -> Optional[Finding]:
        """기존 check_rundll32_js_execution 함수 대체"""
        findings = self._analyze_with_rules(event_data, ['R_LOLBIN_RUNDLL32_JS'])
        return findings[0] if findings else None
    
    def check_regsvr32_url_execution(self, event_data: Dict[str, Any]) -> Optional[Finding]:
        """기존 check_regsvr32_url_execution 함수 대체"""
        findings = self._analyze_with_rules(event_data, ['R_LOLBIN_REGSVR32_URL'])
        return findings[0] if findings else None
    
    def check_powershell_encoded_command(self, event_data: Dict[str, Any]) -> Optional[Finding]:
        """기존 check_powershell_encoded_command 함수 대체"""
        findings = self._analyze_with_rules(event_data, ['R_POWERSHELL_ENCODED'])
        return findings[0] if findings else None
    
    def check_rdp_nonbusiness_hours(self, event_data: Dict[str, Any]) -> Optional[Finding]:
        """기존 check_rdp_nonbusiness_hours 함수 대체"""
        findings = self._analyze_with_rules(event_data, ['R_RDP_NONBUSINESS_HOURS'])
        return findings[0] if findings else None
    
    def check_suspicious_autorun(self, registry_data: Dict[str, Any]) -> Optional[Finding]:
        """기존 check_suspicious_autorun 함수 대체"""
        findings = self._analyze_registry_with_rules(registry_data, ['R_AUTORUN_SUSPICIOUS'])
        return findings[0] if findings else None
    
    # ========== 점수 계산 호환성 ==========
    
    def calculate_finding_score(self, finding: Finding) -> int:
        """기존 점수 계산 함수와 호환"""
        rule = self.rule_engine.get_rule_by_id(finding.rule_id)
        if rule:
            return self.rule_engine._calculate_score(rule)
        return finding.score_impact
    
    # ========== 통계 및 유틸리티 ==========
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """룰 통계 정보 반환"""
        rules = self.rule_engine.detection_rules
        
        stats = {
            'total_rules': len(rules),
            'by_category': {},
            'by_severity': {},
            'by_data_source': {},
            'enabled_rules': len([r for r in rules.values() if r.get('enabled', True)])
        }
        
        for rule in rules.values():
            # 카테고리별
            category = rule.get('category', 'unknown')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # 심각도별
            severity = rule.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # 데이터 소스별
            data_source = rule.get('data_source', 'unknown')
            stats['by_data_source'][data_source] = stats['by_data_source'].get(data_source, 0) + 1
        
        return stats
    
    def validate_all_rules(self) -> Dict[str, Any]:
        """모든 룰 검증"""
        errors = self.rule_engine.validate_rules()
        
        return {
            'is_valid': len(errors) == 0,
            'error_count': len(errors),
            'errors': errors,
            'rule_count': len(self.rule_engine.detection_rules)
        }

# ========== 전역 인스턴스 생성 (기존 코드 호환성) ==========

# 기존 코드에서 직접 함수를 호출할 수 있도록 전역 어댑터 인스턴스 생성
_global_adapter = None

def get_rule_adapter() -> LegacyAdapter:
    """전역 룰 어댑터 인스턴스 반환"""
    global _global_adapter
    if _global_adapter is None:
        _global_adapter = LegacyAdapter()
    return _global_adapter

# ========== 기존 함수들과의 호환성을 위한 래퍼 함수들 ==========

def analyze_event_with_rules(event_data: Dict[str, Any]) -> List[Finding]:
    """이벤트 데이터를 모든 룰로 분석"""
    adapter = get_rule_adapter()
    return adapter.rule_engine.analyze_event_log(event_data)

def analyze_registry_with_rules(registry_data: Dict[str, Any]) -> List[Finding]:
    """레지스트리 데이터를 모든 룰로 분석"""
    adapter = get_rule_adapter()
    return adapter.rule_engine.analyze_registry_data(registry_data)

def get_rule_by_id(rule_id: str) -> Optional[Dict[str, Any]]:
    """룰 ID로 룰 조회"""
    adapter = get_rule_adapter()
    return adapter.rule_engine.get_rule_by_id(rule_id)

def reload_detection_rules() -> bool:
    """탐지 룰 다시 로드"""
    adapter = get_rule_adapter()
    return adapter.rule_engine.reload_rules()
