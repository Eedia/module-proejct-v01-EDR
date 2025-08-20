"""
evtx/analyzer.py
이벤트 로그 분석기 - 새로운 JSON 기반 룰 엔진 사용
기존 하드코딩된 룰들을 중앙화된 룰 시스템으로 교체
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

# 새로운 룰 엔진 임포트
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from rules.legacy_adapter import LegacyAdapter
from utils.data_structures import Finding

logger = logging.getLogger(__name__)

class EventAnalyzer:
    """이벤트 로그 분석기 - 룰 엔진 기반"""
    
    def __init__(self, rules_dir: str = "rules"):
        """
        분석기 초기화
        
        Args:
            rules_dir: 룰 파일들이 있는 디렉토리
        """
        self.rule_engine = RuleEngine(rules_dir)
        self.legacy_adapter = LegacyAdapter(rules_dir)
        
        logger.info("이벤트 분석기 초기화 완료 - 룰 엔진 기반")
        logger.info(f"로드된 룰 수: {len(self.rule_engine.detection_rules)}개")
    
    def analyze_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        이벤트 목록을 분석하여 Finding 생성
        
        Args:
            events: 분석할 이벤트 목록
            
        Returns:
            탐지된 Finding들의 딕셔너리 목록
        """
        all_findings = []
        
        logger.info(f"이벤트 분석 시작: {len(events)}개 이벤트")
        
        for event in events:
            try:
                # 룰 엔진으로 이벤트 분석
                findings = self.rule_engine.analyze_event_log(event)
                
                # Finding 객체를 딕셔너리로 변환
                for finding in findings:
                    finding_dict = self._finding_to_dict(finding)
                    all_findings.append(finding_dict)
                    
            except Exception as e:
                logger.error(f"이벤트 분석 중 오류 발생: {e}")
                continue
        
        # 중복 제거 및 정렬
        unique_findings = self._deduplicate_findings(all_findings)
        unique_findings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        logger.info(f"분석 완료: {len(events)}개 이벤트에서 {len(unique_findings)}개 탐지")
        return unique_findings
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Finding 객체를 기존 형식의 딕셔너리로 변환"""
        rule = self.rule_engine.get_rule_by_id(finding.rule_id)
        
        # MITRE ATT&CK 정보 추출
        mitre_info = {
            "tactics": rule.get('tactics', []) if rule else [],
            "techniques": rule.get('techniques', []) if rule else [],
            "sub_techniques": []
        }
        
        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "score_impact": -finding.score_impact,  # 기존 형식에 맞춰 음수로 변환
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "confidence": finding.confidence,
            "timestamp": finding.timestamp,
            "evidence": finding.evidence,
            "mitre_attack": mitre_info
        }
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """중복 Finding 제거"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # 룰 ID + 타임스탬프 + 주요 증거로 중복 확인
            primary_event = finding.get('evidence', {}).get('primary_event', {})
            key = (
                finding.get('rule_id'),
                finding.get('timestamp'),
                str(primary_event.get('process_name', '')),
                str(primary_event.get('command_line', ''))[:50]  # 명령줄 일부만 사용
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                logger.debug(f"중복 Finding 제거: {finding.get('rule_id')}")
        
        return unique_findings
    
    def analyze_single_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        단일 이벤트 분석 (기존 호환성 유지)
        
        Args:
            event: 분석할 이벤트
            
        Returns:
            탐지된 Finding들의 딕셔너리 목록
        """
        return self.analyze_events([event])
    
    # ========== 기존 호환성을 위한 개별 분석 함수들 ==========
    
    def analyze_lolbin_activity(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """LOLBin 활동 분석"""
        findings = self.legacy_adapter.analyze_lolbin_activity(event)
        return [self._finding_to_dict(f) for f in findings]
    
    def analyze_powershell_activity(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """PowerShell 활동 분석"""
        findings = self.legacy_adapter.analyze_powershell_activity(event)
        return [self._finding_to_dict(f) for f in findings]
    
    def analyze_rdp_activity(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """RDP 활동 분석"""
        findings = self.legacy_adapter.analyze_rdp_activity(event)
        return [self._finding_to_dict(f) for f in findings]
    
    def analyze_service_installation(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """서비스 설치 분석"""
        findings = self.legacy_adapter.analyze_service_installation(event)
        return [self._finding_to_dict(f) for f in findings]
    
    # ========== 기존 개별 검사 함수들 (하위 호환성) ==========
    
    def check_rundll32_js_execution(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """rundll32 JavaScript 실행 검사"""
        finding = self.legacy_adapter.check_rundll32_js_execution(event)
        return self._finding_to_dict(finding) if finding else None
    
    def check_regsvr32_url_execution(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """regsvr32 URL 실행 검사"""
        finding = self.legacy_adapter.check_regsvr32_url_execution(event)
        return self._finding_to_dict(finding) if finding else None
    
    def check_powershell_encoded_command(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """PowerShell 인코딩 명령어 검사"""
        finding = self.legacy_adapter.check_powershell_encoded_command(event)
        return self._finding_to_dict(finding) if finding else None
    
    def check_rdp_nonbusiness_hours(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """비업무시간 RDP 검사"""
        finding = self.legacy_adapter.check_rdp_nonbusiness_hours(event)
        return self._finding_to_dict(finding) if finding else None
    
    # ========== 유틸리티 함수들 ==========
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """룰 통계 정보 반환"""
        return self.legacy_adapter.get_rule_statistics()
    
    def reload_rules(self) -> bool:
        """룰 파일 다시 로드"""
        success = self.rule_engine.reload_rules()
        if success:
            logger.info("룰 파일 다시 로드 완료")
        else:
            logger.error("룰 파일 다시 로드 실패")
        return success
    
    def validate_rules(self) -> Dict[str, Any]:
        """룰 검증"""
        return self.legacy_adapter.validate_all_rules()

# ========== 전역 인스턴스 (기존 호환성) ==========

# 전역 분석기 인스턴스 생성
_global_analyzer = None

def get_event_analyzer() -> EventAnalyzer:
    """전역 이벤트 분석기 인스턴스 반환"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = EventAnalyzer()
    return _global_analyzer

# ========== 기존 코드와의 호환성을 위한 전역 함수들 ==========

def analyze_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    전역 함수로 이벤트 분석 (기존 호환성 유지)
    
    Args:
        events: 분석할 이벤트 목록
        
    Returns:
        탐지된 Finding들의 딕셔너리 목록
    """
    analyzer = get_event_analyzer()
    return analyzer.analyze_events(events)

def analyze_single_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """단일 이벤트 분석"""
    analyzer = get_event_analyzer()
    return analyzer.analyze_single_event(event)

# 개별 분석 함수들
def analyze_lolbin_activity(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """LOLBin 활동 분석"""
    analyzer = get_event_analyzer()
    return analyzer.analyze_lolbin_activity(event)

def analyze_powershell_activity(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """PowerShell 활동 분석"""
    analyzer = get_event_analyzer()
    return analyzer.analyze_powershell_activity(event)

def analyze_rdp_activity(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """RDP 활동 분석"""
    analyzer = get_event_analyzer()
    return analyzer.analyze_rdp_activity(event)

def analyze_service_installation(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """서비스 설치 분석"""
    analyzer = get_event_analyzer()
    return analyzer.analyze_service_installation(event)

# 개별 검사 함수들
def check_rundll32_js_execution(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """rundll32 JavaScript 실행 검사"""
    analyzer = get_event_analyzer()
    return analyzer.check_rundll32_js_execution(event)

def check_regsvr32_url_execution(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """regsvr32 URL 실행 검사"""
    analyzer = get_event_analyzer()
    return analyzer.check_regsvr32_url_execution(event)

def check_powershell_encoded_command(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PowerShell 인코딩 명령어 검사"""
    analyzer = get_event_analyzer()
    return analyzer.check_powershell_encoded_command(event)

def check_rdp_nonbusiness_hours(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """비업무시간 RDP 검사"""
    analyzer = get_event_analyzer()
    return analyzer.check_rdp_nonbusiness_hours(event)

# 유틸리티 함수들
def get_rule_statistics() -> Dict[str, Any]:
    """룰 통계 정보 반환"""
    analyzer = get_event_analyzer()
    return analyzer.get_rule_statistics()

def reload_detection_rules() -> bool:
    """룰 파일 다시 로드"""
    analyzer = get_event_analyzer()
    return analyzer.reload_rules()

def validate_detection_rules() -> Dict[str, Any]:
    """룰 검증"""
    analyzer = get_event_analyzer()
    return analyzer.validate_rules()
