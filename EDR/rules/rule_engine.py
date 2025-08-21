"""
통합 룰 엔진 - JSON 기반 탐지 룰 시스템
기존 분산된 룰들을 중앙화된 JSON 구조로 통합
"""

import json
import logging
import os
from datetime import datetime, time
from typing import Dict, List, Any, Optional

from utils.data_structures import Finding

class RuleEngine:
    """JSON 기반 통합 룰 엔진"""
    
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.logger = logging.getLogger(__name__)
        
        # 룰과 가중치 로드
        self.detection_rules = self._load_detection_rules()
        self.scoring_weights = self._load_scoring_weights()
        
        self.logger.info(f"룰 엔진 초기화: {len(self.detection_rules)}개 룰 로드됨")
    
    def _load_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """탐지 룰 JSON 파일 로드"""
        try:
            rules_file = os.path.join(self.rules_dir, "detection_rules.json")
            
            if not os.path.exists(rules_file):
                self.logger.error(f"룰 파일을 찾을 수 없음: {rules_file}")
                return {}
            
            with open(rules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 룰 ID를 키로 하는 딕셔너리로 변환
            rules_dict = {}
            for rule in data.get('rules', []):
                if rule.get('enabled', True):
                    rules_dict[rule['rule_id']] = rule
            
            self.logger.info(f"탐지 룰 로드 완료: {len(rules_dict)}개")
            return rules_dict
            
        except Exception as e:
            self.logger.error(f"탐지 룰 로드 실패: {e}")
            return {}
    
    def _load_scoring_weights(self) -> Dict[str, Any]:
        """점수 가중치 JSON 파일 로드"""
        try:
            weights_file = os.path.join(self.rules_dir, "scoring_weights.json")
            
            if not os.path.exists(weights_file):
                self.logger.error(f"가중치 파일을 찾을 수 없음: {weights_file}")
                return self._get_default_weights()
            
            with open(weights_file, 'r', encoding='utf-8') as f:
                weights = json.load(f)
            
            self.logger.info("점수 가중치 로드 완료")
            return weights
            
        except Exception as e:
            self.logger.error(f"점수 가중치 로드 실패: {e}")
            return self._get_default_weights()
    
    def _get_default_weights(self) -> Dict[str, Any]:
        """기본 가중치 반환"""
        return {
            "severity_weights": {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.2},
            "category_weights": {"execution": 1.5, "persistence": 1.3, "access": 1.2, "configuration": 0.8},
            "confidence_settings": {"min_confidence": 50, "max_confidence": 100, "weight_factor": 0.01},
            "rule_specific_weights": {}
        }
    
    def analyze_event_log(self, event_data: Dict[str, Any]) -> List[Finding]:
        """이벤트 로그 데이터를 분석하여 탐지 결과 반환"""
        findings = []
        
        # 이벤트 로그 관련 룰들만 필터링
        event_rules = {
            rule_id: rule for rule_id, rule in self.detection_rules.items()
            if rule.get('data_source') == 'event_log'
        }
        
        for rule_id, rule in event_rules.items():
            try:
                if self._match_event_rule(event_data, rule):
                    finding = self._create_finding(rule_id, rule, event_data)
                    if finding:
                        findings.append(finding)
                        
            except Exception as e:
                self.logger.error(f"룰 {rule_id} 처리 중 오류: {e}")
        
        return findings
    
    def analyze_registry_data(self, registry_data: Dict[str, Any]) -> List[Finding]:
        """레지스트리 데이터를 분석하여 탐지 결과 반환"""
        findings = []
        
        # 레지스트리 관련 룰들만 필터링
        registry_rules = {
            rule_id: rule for rule_id, rule in self.detection_rules.items()
            if rule.get('data_source') == 'registry'
        }
        
        for rule_id, rule in registry_rules.items():
            try:
                if self._match_registry_rule(registry_data, rule):
                    finding = self._create_finding(rule_id, rule, registry_data)
                    if finding:
                        findings.append(finding)
                        
            except Exception as e:
                self.logger.error(f"룰 {rule_id} 처리 중 오류: {e}")

        
        
        return findings
    
    def _match_event_rule(self, event_data: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """이벤트 데이터가 룰 조건에 매치되는지 확인"""
        conditions = rule.get('conditions', {})
        
        # 이벤트 ID 확인
        event_ids = rule.get('event_ids', [])
        if event_ids and event_data.get('event_id') not in event_ids:
            return False
        
        # 프로세스 이름 확인
        process_names = conditions.get('process_name', [])
        if process_names:
            process_name = event_data.get('process_name', '').lower()
            if not any(pname.lower() in process_name for pname in process_names):
                return False
        
        # 명령줄 패턴 확인
        command_line_contains = conditions.get('command_line_contains', [])
        if command_line_contains:
            command_line = event_data.get('command_line', '').lower()
            logic = conditions.get('logic', 'OR')
            
            if logic == 'AND':
                if not all(pattern.lower() in command_line for pattern in command_line_contains):
                    return False
            else:  # OR
                if not any(pattern.lower() in command_line for pattern in command_line_contains):
                    return False
        
        # 로그온 타입 확인 (RDP 관련)
        logon_types = conditions.get('logon_type', [])
        if logon_types and event_data.get('logon_type') not in logon_types:
            return False
        
        return True
    
    def _match_registry_rule(self, registry_data: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """레지스트리 데이터가 룰 조건에 매치되는지 확인"""
        conditions = rule.get('conditions', {})
        
        # 레지스트리 키 확인
        registry_keys = rule.get('registry_keys', [])
        if registry_keys:
            reg_key = registry_data.get('key_path', '')
            if not any(key.lower() in reg_key.lower() for key in registry_keys):
                return False
        
        # 값 패턴 확인
        value_contains = conditions.get('value_contains', [])
        if value_contains:
            reg_value = str(registry_data.get('value_data', '')).lower()
            logic = conditions.get('logic', 'OR')
            
            if logic == 'AND':
                if not all(pattern.lower() in reg_value for pattern in value_contains):
                    return False
            else:  # OR
                if not any(pattern.lower() in reg_value for pattern in value_contains):
                    return False
        
        # Ruleset 에 value_name_contains 필터 추가
        value_name_contains = conditions.get('value_name_contains', [])
        if value_name_contains:
            name = str(registry_data.get('value_name', '')).lower()
            logic = conditions.get('logic', 'OR')
            if logic == 'AND':
                if not all(p.lower() in name for p in value_name_contains):
                    return False
            else:
                if not any(p.lower() in name for p in value_name_contains):
                    return False
        
        return True
    
    def _create_finding(self, rule_id: str, rule: Dict[str, Any], data: Dict[str, Any]) -> Optional[Finding]:
        """탐지 결과 Finding 객체 생성"""
        try:
            # 점수 계산
            score = self._calculate_score(rule)
            
            finding = Finding(
                finding_id=f"F_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{rule_id}",
                rule_id=rule_id,
                title=rule['title'],
                description=rule['description'],
                severity=rule['severity'],
                category=rule['category'],
                confidence=rule.get('confidence', 70),
                score_impact=score,
                timestamp=datetime.now().isoformat(),
                evidence={
                    'primary_event': data,
                    'rule_conditions': rule.get('conditions', {}),
                    'tactics': rule.get('tactics', []),
                    'techniques': rule.get('techniques', [])
                }
            )
            
            return finding
            
        except Exception as e:
            self.logger.error(f"Finding 생성 실패 ({rule_id}): {e}")
            return None
    
    def _calculate_score(self, rule: Dict[str, Any]) -> int:
        """룰 기반 점수 계산"""
        try:
            # 기본 점수
            base_score = self.scoring_weights.get('scoring_formula', {}).get('base_score', 10)
            
            # 심각도 가중치
            severity = rule.get('severity', 'medium')
            severity_weight = self.scoring_weights.get('severity_weights', {}).get(severity, 1.0)
            
            # 카테고리 가중치
            category = rule.get('category', 'unknown')
            category_weight = self.scoring_weights.get('category_weights', {}).get(category, 1.0)
            
            # 룰별 가중치
            rule_id = rule.get('rule_id', '')
            rule_weight = self.scoring_weights.get('rule_specific_weights', {}).get(rule_id, 1.0)
            
            # 신뢰도 계수
            confidence = rule.get('confidence', 70)
            confidence_factor = max(0.5, confidence / 100.0)
            
            # 최종 점수 계산
            final_score = int(base_score * severity_weight * category_weight * rule_weight * confidence_factor)
            
            # 점수 범위 제한
            max_score = self.scoring_weights.get('scoring_formula', {}).get('max_score', 100)
            min_score = self.scoring_weights.get('scoring_formula', {}).get('min_score', 1)
            
            return max(min_score, min(max_score, final_score))
            
        except Exception as e:
            self.logger.error(f"점수 계산 실패: {e}")
            return 10
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """룰 ID로 룰 정보 조회"""
        return self.detection_rules.get(rule_id)
    
    def get_rules_by_category(self, category: str) -> Dict[str, Dict[str, Any]]:
        """카테고리별 룰 조회"""
        return {
            rule_id: rule for rule_id, rule in self.detection_rules.items()
            if rule.get('category') == category
        }
    
    def reload_rules(self) -> bool:
        """룰 파일 다시 로드"""
        try:
            self.detection_rules = self._load_detection_rules()
            self.scoring_weights = self._load_scoring_weights()
            self.logger.info("룰 파일 다시 로드 완료")
            return True
        except Exception as e:
            self.logger.error(f"룰 파일 다시 로드 실패: {e}")
            return False
