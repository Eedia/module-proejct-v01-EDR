"""
AI 모듈 공통 데이터 모델
dataclass 기반 표준화된 데이터 구조
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Union

@dataclass
class SecurityIssue:
    """보안 이슈 데이터 구조"""
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
    hostname: str
    detected_issues: List[Union[SecurityIssue, Dict]]
    ai_remediation: List[Union[RemediationScript, Dict]]
    total_issues: int
    statistics: Dict
    executive_summary: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "detected_issues": [
                issue.to_dict() if hasattr(issue, "to_dict") else issue
                for issue in self.detected_issues
            ],
            "ai_remediation": [
                script.to_dict() if hasattr(script, "to_dict") else script
                for script in self.ai_remediation
            ],
            "total_issues": self.total_issues,
            "statistics": self.statistics,
            "executive_summary": self.executive_summary,
        }

@dataclass 
class QueryResponse:
    """자연어 질의 응답 데이터 구조"""
    answer: str
    confidence: float
    source: str
    query: str
    error: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)
