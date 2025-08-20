"""
utils/scoring_engine.py
EDR 스캔 결과 점수화 엔진 (100점 만점 감점형)
"""

from typing import List, Dict, Any
from .data_structures import Finding, Severity

class ScoringEngine:
    """EDR 스캔 결과 점수화 엔진"""
    
    def __init__(self):
        # 심각도별 기본 점수
        self.severity_scores = {
            "critical": -20,
            "high": -15,
            "medium": -10,
            "low": -5,
            "info": -1
        }
        
        # 카테고리별 가중치 (곱셈 계수)
        self.category_weights = {
            "execution": 1.5,        # 실행 관련 (LOLBin 등)
            "persistence": 1.3,      # 지속성 (서비스, 자동실행)
            "remote_access": 1.2,    # 원격 접근 (RDP 등)
            "account_logon": 1.1,    # 계정/로그온
            "security_settings": 1.0  # 보안 설정
        }
        
        # 특정 룰 ID에 대한 추가 가중치
        self.rule_weights = {
            "R_LOLBIN_RUNDLL32": 1.3,
            "R_LOLBIN_REGSVR32": 1.3,
            "R_LOLBIN_MSHTA": 1.3,
            "R_POWERSHELL_ENCODED": 1.2,
            "R_SERVICE_TEMP_PATH": 1.1,
            "R_RDP_NONBUSINESS_HOURS": 1.1
        }
    
    def calculate_finding_score(self, finding: Finding) -> int:
        """개별 Finding의 점수 계산"""
        if isinstance(finding, dict):
            # dict 형태로 전달된 경우
            severity = finding.get("severity", "info")
            category = finding.get("category", "security_settings") 
            rule_id = finding.get("rule_id", "")
            confidence = finding.get("confidence", 50)
        else:
            # Finding 객체로 전달된 경우
            severity = finding.severity
            category = finding.category
            rule_id = finding.rule_id
            confidence = finding.confidence
        
        # 기본 점수 (음수)
        base_score = self.severity_scores.get(severity, -5)
        
        # 카테고리 가중치 적용
        category_weight = self.category_weights.get(category, 1.0)
        
        # 룰별 가중치 적용
        rule_weight = self.rule_weights.get(rule_id, 1.0)
        
        # 신뢰도 보정 (신뢰도가 낮으면 점수 영향 감소)
        confidence_factor = confidence / 100.0
        
        # 최종 점수 계산
        final_score = int(base_score * category_weight * rule_weight * confidence_factor)
        
        return final_score
    
    def calculate_total_score(self, findings: List[Dict[str, Any]]) -> int:
        """전체 Finding 목록의 총점 계산"""
        base_score = 100
        total_deduction = 0
        
        for finding in findings:
            deduction = abs(self.calculate_finding_score(finding))
            total_deduction += deduction
        
        # 최종 점수 (0점 미만으로 내려가지 않음)
        final_score = max(0, base_score - total_deduction)
        
        return final_score
    
    def calculate_category_scores(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """카테고리별 점수 및 통계 계산"""
        category_stats = {}
        
        for finding in findings:
            category = finding.get("category", "security_settings")
            
            if category not in category_stats:
                category_stats[category] = {
                    "count": 0,
                    "total_deduction": 0,
                    "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                }
            
            category_stats[category]["count"] += 1
            category_stats[category]["total_deduction"] += abs(self.calculate_finding_score(finding))
            
            severity = finding.get("severity", "info")
            if severity in category_stats[category]["severities"]:
                category_stats[category]["severities"][severity] += 1
        
        return category_stats
    
    def get_risk_level(self, score: int) -> str:
        """점수를 기반으로 위험도 반환"""
        if score >= 90:
            return "양호"
        elif score >= 70:
            return "주의"
        else:
            return "경고"
    
    def get_risk_color(self, score: int) -> str:
        """점수를 기반으로 색상 코드 반환 (UI용)"""
        if score >= 90:
            return "#28a745"  # 녹색
        elif score >= 70:
            return "#ffc107"  # 노랑
        else:
            return "#dc3545"  # 빨강
    
    def generate_score_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """점수 요약 정보 생성"""
        total_score = self.calculate_total_score(findings)
        risk_level = self.get_risk_level(total_score)
        category_stats = self.calculate_category_scores(findings)
        
        # 심각도별 통계
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # 상위 3개 위험 항목
        top_risks = sorted(findings, 
                          key=lambda x: abs(self.calculate_finding_score(x)), 
                          reverse=True)[:3]
        
        return {
            "total_score": total_score,
            "risk_level": risk_level,
            "risk_color": self.get_risk_color(total_score),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "findings_by_category": {cat: stats["count"] for cat, stats in category_stats.items()},
            "category_details": category_stats,
            "top_risks": [
                {
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", ""),
                    "score_impact": self.calculate_finding_score(finding)
                }
                for finding in top_risks
            ]
        }

# 전역 스코어링 엔진 인스턴스
scoring_engine = ScoringEngine()

def calculate_total_score(findings: List[Dict[str, Any]]) -> int:
    """전역 함수로 총점 계산"""
    return scoring_engine.calculate_total_score(findings)

def determine_risk_level(score: int) -> str:
    """전역 함수로 위험도 결정"""
    return scoring_engine.get_risk_level(score)

def generate_score_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """전역 함수로 점수 요약 생성"""
    return scoring_engine.generate_score_summary(findings)
