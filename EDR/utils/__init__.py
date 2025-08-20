"""
utils/__init__.py
유틸리티 모듈 초기화
"""

from .data_structures import (
    Finding, Evidence, EventLogEvidence, RegistryEvidence, FileEvidence,
    MitreAttack, AIAnalysis, ScanMetadata, ScanSummary, SystemInfo, ScanResults,
    Severity, Category, EvidenceSource,
    generate_finding_id, generate_scan_id, calculate_risk_level,
    get_current_timestamp, format_timestamp, serialize_to_json
)

from .scoring_engine import (
    ScoringEngine, scoring_engine,
    calculate_total_score, determine_risk_level, generate_score_summary
)

from .file_handler import (
    FileHandler, file_handler,
    save_findings_json, load_findings_json, generate_html_report
)

__all__ = [
    # Data structures
    'Finding', 'Evidence', 'EventLogEvidence', 'RegistryEvidence', 'FileEvidence',
    'MitreAttack', 'AIAnalysis', 'ScanMetadata', 'ScanSummary', 'SystemInfo', 'ScanResults',
    'Severity', 'Category', 'EvidenceSource',
    
    # Utility functions
    'generate_finding_id', 'generate_scan_id', 'calculate_risk_level',
    'get_current_timestamp', 'format_timestamp', 'serialize_to_json',
    
    # Scoring engine
    'ScoringEngine', 'scoring_engine',
    'calculate_total_score', 'determine_risk_level', 'generate_score_summary',
    
    # File handler
    'FileHandler', 'file_handler',
    'save_findings_json', 'load_findings_json', 'generate_html_report'
]
