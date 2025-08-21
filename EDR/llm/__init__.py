"""
AI Security Analysis Module Package - Upgraded Version

주요 모듈:
- issue_detector: 보안 이슈 탐지 AI
- remediation: 해결책 생성 AI
- summarizer: 보안 이슈 요약 AI
- query_handler: 자연어 질문 처리 AI
- security_analyzer: 통합 분석 AI
- validators: 스크립트 검증기
- utils: 데이터 변환 유틸리티
"""

__version__ = "2.0.0"
__author__ = "EDR Team"

# 새로운 업그레이드된 모듈들 import
from .api_client import GeminiClient
from .base import AIBaseModule
from .models import SecurityIssue, RemediationScript, AnalysisResult, QueryResponse
from .json_utils import JSONCleaner
from .issue_detector import AIIssueDetector
from .remediation import RemediationEngine
from .summarizer import SecuritySummarizer
from .query_handler import QueryHandler
from .validators import ScriptValidator
from .security_analyzer import AISecurityAnalyzer
from .utils import normalize_findings_data, convert_to_alerts_format, create_test_data

# 쉬운 사용을 위한 함수들
def create_analyzer(config: dict = None) -> AISecurityAnalyzer:
    """통합 AI 보안 분석기 생성"""
    return AISecurityAnalyzer(config)

def quick_analysis(raw_data: dict) -> dict:
    """빠른 보안 분석 실행"""
    analyzer = AISecurityAnalyzer()
    result = analyzer.analyze_raw_data(raw_data)
    return result.to_dict()

def ask_question(query: str, analysis_result: dict) -> dict:
    """분석 결과에 대한 자연어 질문"""
    analyzer = AISecurityAnalyzer()
    return analyzer.process_user_query(query, analysis_result)

__all__ = [
    # 핵심 클래스들
    'GeminiClient',
    'AIBaseModule', 
    'AISecurityAnalyzer',
    
    # 개별 AI 모듈들
    'AIIssueDetector',
    'RemediationEngine', 
    'SecuritySummarizer',
    'QueryHandler',
    'ScriptValidator',
    
    # 데이터 모델들
    'SecurityIssue',
    'RemediationScript', 
    'AnalysisResult',
    'QueryResponse',
    
    # 유틸리티들
    'JSONCleaner',
    'normalize_findings_data',
    'convert_to_alerts_format',
    'create_test_data',
    
    # 편의 함수들
    'create_analyzer',
    'quick_analysis', 
    'ask_question'
]
