"""
utils/data_structures.py
findings.json 표준 포맷을 위한 데이터 구조 정의
모든 모듈에서 공통으로 사용할 클래스들
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum
import json
import uuid

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Category(Enum):
    ACCOUNT_LOGON = "account_logon"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    REMOTE_ACCESS = "remote_access"
    SECURITY_SETTINGS = "security_settings"

class EvidenceSource(Enum):
    EVENT_LOG = "event_log"
    REGISTRY = "registry"
    FILE_SYSTEM = "file_system"

@dataclass
class Evidence:
    """기본 증거 데이터 구조"""
    source: str
    timestamp: str
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EventLogEvidence(Evidence):
    """이벤트 로그 증거"""
    channel: str = ""
    event_id: int = 0
    computer: str = ""
    
    def __post_init__(self):
        self.source = EvidenceSource.EVENT_LOG.value

@dataclass
class RegistryEvidence(Evidence):
    """레지스트리 증거"""
    key: str = ""
    value: str = ""
    registry_data: str = ""
    
    def __post_init__(self):
        self.source = EvidenceSource.REGISTRY.value

@dataclass
class FileEvidence(Evidence):
    """파일 시스템 증거"""
    path: str = ""
    size: int = 0
    created: str = ""
    modified: str = ""
    hash: Optional[str] = None
    
    def __post_init__(self):
        self.source = EvidenceSource.FILE_SYSTEM.value

@dataclass
class MitreAttack:
    """MITRE ATT&CK 매핑"""
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)

@dataclass
class AIAnalysis:
    """AI 분석 결과"""
    summary: str = ""
    risk_assessment: str = ""
    recommended_actions: List[str] = field(default_factory=list)

@dataclass
class Finding:
    """개별 탐지 결과"""
    finding_id: str
    rule_id: str
    severity: str
    score_impact: int
    category: str
    title: str
    description: str
    timestamp : str = ""
    status: str = "active"
    confidence: int = 50
    
    # 증거 데이터
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # 분석 결과
    mitre_attack: Optional[Dict[str, List[str]]] = None
    ai_analysis: Optional[Dict[str, Any]] = None

@dataclass
class ScanMetadata:
    """스캔 메타데이터"""
    scan_id: str
    timestamp: str
    hostname: str
    scan_duration_seconds: float
    scanner_version: str = "1.0.0"
    scan_scope: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanSummary:
    """스캔 요약"""
    total_score: int
    risk_level: str
    total_findings: int
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)

@dataclass
class SystemInfo:
    """시스템 정보"""
    operating_system: str = ""
    version: str = ""
    architecture: str = ""
    total_memory_gb: int = 0
    antivirus: Dict[str, Any] = field(default_factory=dict)
    windows_update: Dict[str, Any] = field(default_factory=dict)
    security_settings: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResults:
    """전체 스캔 결과 구조"""
    scan_metadata: ScanMetadata
    scan_summary: ScanSummary
    findings: List[Finding]
    system_info: SystemInfo
    statistics: Dict[str, Any] = field(default_factory=dict)
    ai_recommendations: Dict[str, List[str]] = field(default_factory=dict)
    schema_version: str = "1.0"
    generated_by: str = "EDR-Scanner v1.0.0"

# =============================================================================
# 유틸리티 함수들
# =============================================================================

def generate_finding_id() -> str:
    """고유한 Finding ID 생성"""
    return f"F{str(uuid.uuid4())[:8].upper()}"

def generate_scan_id() -> str:
    """고유한 Scan ID 생성"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{timestamp}"

def calculate_risk_level(score: int) -> str:
    """점수를 기반으로 위험도 계산"""
    if score >= 90:
        return "양호"
    elif score >= 70:
        return "주의"
    else:
        return "경고"

def serialize_to_json(scan_results: ScanResults) -> Dict[str, Any]:
    """ScanResults 객체를 JSON 직렬화 가능한 dict로 변환"""
    return asdict(scan_results)

def deserialize_from_json(json_data: Dict[str, Any]) -> ScanResults:
    """JSON dict를 ScanResults 객체로 변환"""
    # 복잡한 역직렬화는 필요시 구현
    pass

def get_current_timestamp() -> str:
    """현재 시간을 ISO 8601 형식으로 반환"""
    return datetime.now().isoformat() + "Z"

def format_timestamp(dt: datetime) -> str:
    """datetime 객체를 ISO 8601 형식으로 변환"""
    return dt.isoformat() + "Z"
