"""
LLM 모듈 공통 데이터 모델
EDR 프로젝트의 Finding 구조와 연동되는 AI 특화 모델들
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from utils.data_structures import Finding

@dataclass
class SecurityIssue:
    """AI가 탐지한 보안 이슈 데이터 구조"""
    issue_id: str
    title: str
    severity: str
    category: str
    description: str
    confidence: float
    evidence: Dict = None
    detected_at: str = None
    rule_name: str = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_finding(cls, finding: Finding) -> 'SecurityIssue':
        """Finding 객체로부터 SecurityIssue 생성"""
        return cls(
            issue_id=finding.finding_id,
            title=finding.title,
            severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            category=finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
            description=finding.description,
            confidence=finding.confidence,
            evidence=finding.evidence[0].data if finding.evidence else {},
            detected_at=finding.timestamp,
            rule_name=finding.rule_id
        )

@dataclass
class RemediationScript:
    """조치 스크립트 데이터 구조"""
    issue_id: str
    rule_name: str
    severity: str
    fix_command: str
    validation_command: str
    rollback_command: str
    description: str
    confidence: float
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class AnalysisResult:
    """전체 분석 결과 데이터 구조"""
    timestamp: str
    detected_issues: List[SecurityIssue]
    ai_remediation: List[RemediationScript]
    total_issues: int
    statistics: Dict
    executive_summary: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "detected_issues": [issue.to_dict() for issue in self.detected_issues],
            "ai_remediation": [script.to_dict() for script in self.ai_remediation],
            "total_issues": self.total_issues,
            "statistics": self.statistics,
            "executive_summary": self.executive_summary
        }
