"""
AI Security Analysis Module Package - Upgraded Version

주요 모듈:
- issue_detector_new: 보안 이슈 탐지 AI (강화됨)
- remediation_new: 해결책 생성 AI (템플릿 시스템 추가)
- summarizer_new: 보안 이슈 요약 AI (신규)
- query_handler_new: 자연어 질문 처리 AI (강화됨)
- security_analyzer_new: 통합 분석 AI (신규)
- validators_new: 스크립트 검증기 (신규)
- utils_new: 데이터 변환 유틸리티 (신규)
"""

__version__ = "2.0.0"
__author__ = "EDR Team"

# 새로운 업그레이드된 모듈들 import
from .api_client_new import GeminiClient
from .base_new import AIBaseModule
from .models_new import SecurityIssue, RemediationScript, AnalysisResult, QueryResponse
from .json_utils_new import JSONCleaner
from .issue_detector_new import AIIssueDetector
from .remediation_new import RemediationEngine
from .summarizer_new import SecuritySummarizer
from .query_handler_new import QueryHandler
from .validators_new import ScriptValidator
from .security_analyzer_new import AISecurityAnalyzer
from .utils_new import normalize_findings_data, convert_to_alerts_format, create_test_data

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
