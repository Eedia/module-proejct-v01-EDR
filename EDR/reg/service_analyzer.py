"""
reg/service_analyzer.py
서비스 등록 분석기 - 새로운 룰 엔진 기반
"""

import logging
import subprocess
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

# 새로운 룰 엔진 임포트
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules.rule_engine import RuleEngine
from rules.legacy_adapter import LegacyAdapter
from utils.data_structures import Finding, generate_finding_id, get_current_timestamp
from .registry_collector import registry_collector

logger = logging.getLogger(__name__)

class ServiceAnalyzer:
    """서비스 등록 분석 클래스 - 룰 엔진 기반"""
    
    def __init__(self, rules_dir: str = "rules"):
        """초기화"""
        self.rule_engine = RuleEngine(rules_dir)
        self.legacy_adapter = LegacyAdapter(rules_dir)
        
        # 서비스 관련 레지스트리 경로
        self.service_registry_paths = {
            'services': ('HKLM', r'SYSTEM\CurrentControlSet\Services'),
            'services_wow64': ('HKLM', r'SYSTEM\CurrentControlSet\Services\WOW6432Node')
        }
        
        logger.info("서비스 분석기 초기화 완료 - 룰 엔진 기반")
    
    def analyze_services(self) -> List[Dict[str, Any]]:
        """서비스 분석 및 의심스러운 서비스 탐지"""
        logger.info("서비스 분석 시작")
        
        all_findings = []
        
        # 레지스트리 기반 서비스 분석
        all_findings.extend(self._analyze_registry_services())
        
        # SC 명령어 기반 서비스 분석
        all_findings.extend(self._analyze_running_services())
        
        logger.info(f"서비스 분석 완료: {len(all_findings)}개 탐지")
        return all_findings
    
    def _analyze_registry_services(self) -> List[Dict[str, Any]]:
        """레지스트리 기반 서비스 분석"""
        findings = []
        
        for path_name, (hive, subkey) in self.service_registry_paths.items():
            try:
                # 서비스 키 목록 가져오기
                service_keys = registry_collector.enumerate_registry_keys(hive, subkey)

                for service_name in service_keys:
                    service_key_path = f"{subkey}\\{service_name}"
                    
                    # 서비스 정보 수집
                    service_info = self._get_service_info(hive, service_key_path, service_name)
                    
                    if service_info:
                        # 룰 엔진으로 분석
                        service_findings = self.rule_engine.analyze_registry_data(service_info)
                        
                        # Finding 객체를 딕셔너리로 변환
                        for finding in service_findings:
                            finding_dict = self._finding_to_dict(finding)
                            findings.append(finding_dict)
                            
            except Exception as e:
                logger.error(f"레지스트리 서비스 분석 중 오류 ({path_name}): {e}")
                continue
        
        return findings
    
    def _analyze_running_services(self) -> List[Dict[str, Any]]:
        """실행 중인 서비스 분석"""
        findings = []
        
        try:
            # SC 명령어로 서비스 목록 가져오기
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                services = self._parse_sc_output(result.stdout)
                
                for service in services:
                    # 룰 엔진용 데이터 구조 생성
                    service_data = {
                        'service_name': service.get('service_name', ''),
                        'display_name': service.get('display_name', ''),
                        'service_type': service.get('type', ''),
                        'state': service.get('state', ''),
                        'image_path': service.get('binary_path_name', ''),
                        'timestamp': get_current_timestamp()
                    }
                    
                    # 룰 엔진으로 분석
                    service_findings = self.rule_engine.analyze_registry_data(service_data)
                    
                    # Finding 객체를 딕셔너리로 변환
                    for finding in service_findings:
                        finding_dict = self._finding_to_dict(finding)
                        findings.append(finding_dict)
                        
        except Exception as e:
            logger.error(f"실행 중인 서비스 분석 중 오류: {e}")
        
        return findings
    
    def _get_service_info(self, hive: str, service_key_path: str, service_name: str) -> Optional[Dict[str, Any]]:
        """서비스 정보 수집"""
        try:
            service_values = registry_collector.get_registry_values(hive, service_key_path)
            
            image_path = service_values.get('ImagePath', '')
            display_name = service_values.get('DisplayName', service_name)
            service_type = service_values.get('Type', 0)
            start_type = service_values.get('Start', 0)
            
            return {
                'key_path': f"{hive}\\{service_key_path}",
                'service_name': service_name,
                'display_name': display_name,
                'image_path': str(image_path),
                'service_type': str(service_type),
                'start_type': str(start_type),
                'timestamp': get_current_timestamp()
            }
            
        except Exception as e:
            logger.debug(f"서비스 정보 수집 실패 ({service_name}): {e}")
            return None
    
    def _parse_sc_output(self, sc_output: str) -> List[Dict[str, Any]]:
        """SC 명령어 출력 파싱"""
        services = []
        current_service = {}
        
        for line in sc_output.split('\n'):
            line = line.strip()
            
            if line.startswith('SERVICE_NAME:'):
                if current_service:
                    services.append(current_service)
                current_service = {'service_name': line.split(':', 1)[1].strip()}
            elif line.startswith('DISPLAY_NAME:'):
                current_service['display_name'] = line.split(':', 1)[1].strip()
            elif line.startswith('TYPE'):
                current_service['type'] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE'):
                current_service['state'] = line.split(':', 1)[1].strip()
        
        if current_service:
            services.append(current_service)
        
        return services
    
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

def get_service_analyzer() -> ServiceAnalyzer:
    """전역 서비스 분석기 인스턴스 반환"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = ServiceAnalyzer()
    return _global_analyzer

def analyze_services() -> List[Dict[str, Any]]:
    """전역 함수로 서비스 분석 (기존 호환성 유지)"""
    analyzer = get_service_analyzer()
    return analyzer.analyze_services()

# 기존 호환성
service_analyzer = get_service_analyzer()
