"""
utils/scoring_engine.py
EDR 스캔 결과 점수화 엔진 - 새로운 룰 엔진 기반
JSON 설정 파일을 사용한 동적 점수 계산
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional

# 새로운 룰 엔진 연동
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.data_structures import Finding, Severity

logger = logging.getLogger(__name__)

class ScoringEngine:
    """EDR 스캔 결과 점수화 엔진 - 룰 엔진 기반"""
    
    DEFAULT_RULES_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
    )

    def __init__(self, rules_dir: Optional[str] = None):
        """
        점수화 엔진 초기화
        
        Args:
            rules_dir: 룰 파일들이 있는 디렉토리
        """
        self.rules_dir = rules_dir or self.DEFAULT_RULES_DIR
        self.scoring_weights = self._load_scoring_weights()
        
        logger.info("점수화 엔진 초기화 완료 - 룰 엔진 기반")
    
    def _load_scoring_weights(self) -> Dict[str, Any]:
        """점수 가중치 설정 로드"""
        weights_file = os.path.join(self.rules_dir, "scoring_weights.json")
        
        try:
            with open(weights_file, 'r', encoding='utf-8') as f:
                weights = json.load(f)
                logger.info(f"점수 가중치 로드 완료: {weights_file}")
                return weights
        except Exception as e:
            logger.warning(f"점수 가중치 로드 실패 ({weights_file}): {e}")
            # 기본 가중치 반환
            return self._get_default_weights()
    
    def _get_default_weights(self) -> Dict[str, Any]:
        """기본 점수 가중치 반환"""
        return {
            "severity_weights": {
                "critical": 3.0,
                "high": 2.0,
                "medium": 1.0,
                "low": 0.5,
                "info": 0.2,
            },
            "category_weights": {
                "execution": 1.5,
                "persistence": 1.3,
                "access": 1.2,
                "configuration": 0.8,
                "default": 1.0,
            },
            "rule_specific_weights": {},
            "confidence_settings": {
                "min_confidence": 0,
                "max_confidence": 100,
                "weight_factor": 0.01,
            },
            "scoring_formula": {"base_score": 10, "max_score": 100, "min_score": 1},
        }
    
    def calculate_finding_score(self, finding: Any) -> int:
        """
        개별 Finding의 점수 계산
        
        Args:
            finding: Finding 객체 또는 딕셔너리
            
        Returns:
            계산된 점수 (음수, 감점형)
        """
        # Finding 정보 추출
        if isinstance(finding, dict):
            severity = finding.get("severity", "info")
            category = finding.get("category", "configuration")
            rule_id = finding.get("rule_id", "")
            confidence = finding.get("confidence", 50)
        else:
            # Finding 객체
            severity = finding.severity
            category = finding.category
            rule_id = finding.rule_id
            confidence = finding.confidence
        
        # 신뢰도 값 정규화 (dict/문자열 대비)
        confidence = self._normalize_confidence(confidence)

        # 기본 점수 및 가중치 로드
        base_score = self.scoring_weights.get("scoring_formula", {}).get("base_score", 10)
        severity_weight = self.scoring_weights.get("severity_weights", {}).get(severity, 1.0)
        category_weight = self.scoring_weights.get("category_weights", {}).get(
            category,
            self.scoring_weights.get("category_weights", {}).get("default", 1.0),
        )

        # 룰별 가중치 적용
        rule_weight = self.scoring_weights.get("rule_specific_weights", {}).get(rule_id, 1.0)
        
        # 신뢰도 조정
        confidence_factor = self._calculate_confidence_adjustment(confidence)

        # 최종 점수 계산
        final_score = base_score * severity_weight * category_weight * rule_weight * confidence_factor
        
        return int(final_score)
    
    # def _calculate_confidence_adjustment(self, confidence: int) -> float:
    def _calculate_confidence_adjustment(self, confidence: Any) -> float:
        """신뢰도 기반 점수 조정"""
        confidence = self._normalize_confidence(confidence)  
        settings = self.scoring_weights.get("confidence_settings", {})
        min_conf = settings.get("min_confidence", 0)
        max_conf = settings.get("max_confidence", 100)
        factor = settings.get("weight_factor", 0.01)

        clamped = max(min_conf, min(max_conf, confidence))
        adjustment = 1 + (clamped - min_conf) * factor
        
        return adjustment
    
    # 신뢰도 값 정규화 추가 
    def _normalize_confidence(self, confidence: Any) -> float:
        """신뢰도 값을 숫자로 정규화"""
        if isinstance(confidence, dict):
            # 일반적으로 {'value': 85} 형태를 예상
            if 'value' in confidence:
                confidence = confidence.get('value')
            else:
                # 첫 번째 숫자형 값을 선택
                for v in confidence.values():
                    if isinstance(v, (int, float)):
                        confidence = v
                        break
                else:
                    confidence = 0
        try:
            return float(confidence)
        except (TypeError, ValueError):
            return 0.0
        
    def calculate_total_score(self, findings: List[Any]) -> Dict[str, Any]:
        """
        전체 Finding들의 종합 점수 계산
        
        Args:
            findings: Finding 객체들 또는 딕셔너리들의 리스트
            
        Returns:
            종합 점수 및 세부 정보
        """
        if not findings:
            return {
                "total_score": 100,
                "grade": "양호",
                "finding_count": 0,
                "category_breakdown": {},
                "severity_breakdown": {},
                "deduction_total": 0
            }
        
        total_deduction = 0
        category_scores = {}
        severity_counts = {}
        
        for finding in findings:
            # 개별 점수 계산
            finding_score = self.calculate_finding_score(finding)
            total_deduction += abs(finding_score)
            
            # 카테고리별 집계
            if isinstance(finding, dict):
                category = finding.get("category", "configuration")
                severity = finding.get("severity", "info")
            else:
                category = finding.category
                severity = finding.severity
            
            category_scores[category] = category_scores.get(category, 0) + abs(finding_score)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # 최종 점수 계산 (100점에서 감점)
        # 최종 점수 계산 (100점에서 감점, 감점 상한선 적용)
        # 너무 많은 medium 등급 발견사항으로 인한 과도한 감점 방지  
        max_deduction = 80  # 최대 80점까지만 감점 (최소 20점 보장)
        adjusted_deduction = min(total_deduction, max_deduction)
        final_score = max(20, 100 - adjusted_deduction)
        
        # 등급 결정
        grade = self._determine_grade(final_score)
        
        return {
            "total_score": final_score,
            "grade": grade,
            "finding_count": len(findings),
            "category_breakdown": category_scores,
            "severity_breakdown": severity_counts,
            "deduction_total": adjusted_deduction
        }
    
    def _determine_grade(self, score: int) -> str:
        """점수에 따른 등급 결정"""
        if score >= 90:
            return "양호"
        elif score >= 70:
            return "주의"
        elif score >= 50:
            return "경고"
        else:
            return "위험"
    
    def get_category_analysis(self, findings: List[Any]) -> Dict[str, Any]:
        """카테고리별 상세 분석"""
        category_analysis = {}
        
        for finding in findings:
            if isinstance(finding, dict):
                category = finding.get("category", "configuration")
                severity = finding.get("severity", "info")
                rule_id = finding.get("rule_id", "")
            else:
                category = finding.category
                severity = finding.severity
                rule_id = finding.rule_id
            
            if category not in category_analysis:
                category_analysis[category] = {
                    "count": 0,
                    "total_score": 0,
                    "severities": {},
                    "rules": {}
                }
            
            # 통계 업데이트
            category_analysis[category]["count"] += 1
            category_analysis[category]["total_score"] += abs(self.calculate_finding_score(finding))
            category_analysis[category]["severities"][severity] = \
                category_analysis[category]["severities"].get(severity, 0) + 1
            category_analysis[category]["rules"][rule_id] = \
                category_analysis[category]["rules"].get(rule_id, 0) + 1
        
        return category_analysis
    
    def get_scoring_statistics(self) -> Dict[str, Any]:
        """점수화 엔진 통계 정보"""
        return {
            "severity_scores": self.scoring_weights.get("severity_weights", {}),
            "category_multipliers": self.scoring_weights.get("category_weights", {}),
            "rule_count": len(self.scoring_weights.get("rule_specific_weights", {})),
            "confidence_enabled": True,
        }
    
    def update_rule_weight(self, rule_id: str, weight: float) -> bool:
        """특정 룰의 가중치 업데이트"""
        try:
            self.scoring_weights.setdefault("rule_specific_weights", {})[rule_id] = weight
            self._save_scoring_weights()
            logger.info(f"룰 가중치 업데이트: {rule_id} = {weight}")
            return True
        except Exception as e:
            logger.error(f"룰 가중치 업데이트 실패: {e}")
            return False
    
    def _save_scoring_weights(self) -> bool:
        """점수 가중치 설정 저장"""
        weights_file = os.path.join(self.rules_dir, "scoring_weights.json")
        
        try:
            with open(weights_file, 'w', encoding='utf-8') as f:
                json.dump(self.scoring_weights, f, indent=2, ensure_ascii=False)
                logger.info(f"점수 가중치 저장 완료: {weights_file}")
                return True
        except Exception as e:
            logger.error(f"점수 가중치 저장 실패: {e}")
            return False
    
    def reload_weights(self) -> bool:
        """점수 가중치 다시 로드"""
        try:
            self.scoring_weights = self._load_scoring_weights()
            logger.info("점수 가중치 다시 로드 완료")
            return True
        except Exception as e:
            logger.error(f"점수 가중치 다시 로드 실패: {e}")
            return False

# 전역 점수화 엔진 인스턴스
_global_scoring_engine = None

def get_scoring_engine() -> ScoringEngine:
    """전역 점수화 엔진 인스턴스 반환"""
    global _global_scoring_engine
    if _global_scoring_engine is None:
        _global_scoring_engine = ScoringEngine()
    return _global_scoring_engine

# 기존 호환성을 위한 전역 함수들
def calculate_total_score(findings: List[Any]) -> Dict[str, Any]:
    """전역 함수로 총 점수 계산 (기존 호환성 유지)"""
    engine = get_scoring_engine()
    return engine.calculate_total_score(findings)

def calculate_finding_score(finding: Any) -> int:
    """전역 함수로 개별 Finding 점수 계산"""
    engine = get_scoring_engine()
    return engine.calculate_finding_score(finding)

def get_category_analysis(findings: List[Any]) -> Dict[str, Any]:
    """전역 함수로 카테고리 분석"""
    engine = get_scoring_engine()
    return engine.get_category_analysis(findings)

def determine_risk_level(score: int) -> str:
    """점수를 기반으로 위험도 수준 결정"""
    from .data_structures import calculate_risk_level
    return calculate_risk_level(score)

def generate_score_summary(findings: List[Any]) -> Dict[str, Any]:
    """Finding 목록에 대한 종합 점수 요약 생성"""
    engine = get_scoring_engine()
    total = engine.calculate_total_score(findings)
    risk_level = determine_risk_level(total["total_score"])
    return {
        "total_score": total["total_score"],
        "risk_level": risk_level,
        "total_findings": total["finding_count"],
        "findings_by_severity": total["severity_breakdown"],
        "findings_by_category": total["category_breakdown"],
    }


# 기존 호환성
scoring_engine = get_scoring_engine()
