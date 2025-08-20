"""
reg/autorun_analyzer.py
자동실행 항목 분석기 - 새로운 룰 엔진 기반
"""

import os
import logging
from typing import Dict, List, Any, Optional

# 새로운 룰 엔진 임포트
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from rules.legacy_adapter import LegacyAdapter
from utils.data_structures import Finding, generate_finding_id, get_current_timestamp
from .registry_collector import registry_collector

logger = logging.getLogger(__name__)

class AutoRunAnalyzer:
    """자동실행 항목 분석 클래스 - 룰 엔진 기반"""
    
    def __init__(self, rules_dir: str = "rules"):
        """초기화"""
        self.rule_engine = RuleEngine(rules_dir)
        self.legacy_adapter = LegacyAdapter(rules_dir)
        
        # 자동실행 레지스트리 위치들
        self.autorun_registry_locations = {
            'current_user_run': ('HKCU', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            'local_machine_run': ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
            'wow64_run': ('HKLM', r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
        }
        
        logger.info("자동실행 분석기 초기화 완료 - 룰 엔진 기반")
    
    def analyze_autorun_entries(self) -> List[Dict[str, Any]]:
        """자동실행 항목 분석 및 의심스러운 항목 탐지"""
        logger.info("자동실행 항목 분석 시작")
        
        all_findings = []
        
        for location_name, (hive, subkey) in self.autorun_registry_locations.items():
            try:
                # 레지스트리 데이터 수집
                registry_data = registry_collector.get_registry_values(hive, subkey)
                
                for value_name, value_data in registry_data.items():
                    # 룰 엔진용 데이터 구조 생성
                    reg_data = {
                        'key_path': f"{hive}\\{subkey}",
                        'value_name': value_name,
                        'value_data': str(value_data),
                        'location_type': location_name,
                        'timestamp': get_current_timestamp()
                    }
                    
                    # 룰 엔진으로 분석
                    findings = self.rule_engine.analyze_registry_data(reg_data)
                    
                    # Finding 객체를 딕셔너리로 변환
                    for finding in findings:
                        finding_dict = self._finding_to_dict(finding)
                        all_findings.append(finding_dict)
                        
            except Exception as e:
                logger.error(f"자동실행 항목 분석 중 오류 ({location_name}): {e}")
                continue
        
        logger.info(f"자동실행 분석 완료: {len(all_findings)}개 탐지")
        return all_findings
    
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

def get_autorun_analyzer() -> AutoRunAnalyzer:
    """전역 자동실행 분석기 인스턴스 반환"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = AutoRunAnalyzer()
    return _global_analyzer

def analyze_autorun_entries() -> List[Dict[str, Any]]:
    """전역 함수로 자동실행 분석 (기존 호환성 유지)"""
    analyzer = get_autorun_analyzer()
    return analyzer.analyze_autorun_entries()

# 기존 호환성
autorun_analyzer = get_autorun_analyzer()
