"""
LLM (AI) 모듈 패키지
EDR 탐지 결과에 대한 AI 기반 분석 및 해결책 제공

주요 모듈:
- ai_remediator: AI 기반 조치 스크립트 생성기
- ask_your_scan: 자연어 질의응답 시스템
- base: 공통 기반 클래스
- models: AI 특화 데이터 모델
- json_utils: JSON 처리 유틸리티
- api_client: Gemini API 클라이언트
"""

__version__ = "2.0.0"
__author__ = "EDR Team"

# 핵심 모듈들만 import (깔끔하게 정리)
from .api_client import GeminiClient
from .ai_remediator_new import AIRemediator
from .ask_your_scan_upgraded import AskYourScanUpgraded
from .models import SecurityIssue, RemediationScript, AnalysisResult
from .base import LLMBaseModule
from .json_utils import JSONCleaner

__all__ = [
    'GeminiClient',
    'AIRemediator',
    'AskYourScanUpgraded', 
    'SecurityIssue',
    'RemediationScript',
    'AnalysisResult',
    'LLMBaseModule',
    'JSONCleaner'
]
