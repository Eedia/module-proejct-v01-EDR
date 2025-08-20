"""
LLM 모듈 공통 기반 클래스
기존 AI 모듈을 EDR 프로젝트 구조에 맞게 업그레이드
"""
import logging
from typing import Dict, Any
from .api_client import GeminiClient
from .json_utils import JSONCleaner

class LLMBaseModule:
    """모든 LLM 모듈의 기반 클래스"""
    
    def __init__(self, module_name: str = None):
        # 공통 컴포넌트 초기화
        self.api_client = GeminiClient()
        self.json_cleaner = JSONCleaner()
        
        # 로깅 설정
        if module_name:
            self.logger = logging.getLogger(f"llm.{module_name}")
        else:
            self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"{self.__class__.__name__} 초기화 완료")
    
    def _safe_api_call(self, prompt: str, call_type: str = "general") -> str:
        """안전한 API 호출 (공통 오류 처리)"""
        try:
            if call_type == "security":
                return self.api_client.generate_security_analysis(prompt)
            elif call_type == "summary":
                return self.api_client.generate_summary(prompt)
            elif call_type == "remediation":
                return self.api_client.generate_remediation(prompt)
            else:
                return self.api_client.chat_completion(prompt)
        except Exception as e:
            self.logger.error(f"API 호출 실패 ({call_type}): {e}")
            return None
    
    def _clean_and_parse_json(self, content: str, fallback_type: str = "object") -> Dict:
        """JSON 정리 및 파싱 (공통 처리)"""
        if not content:
            return {} if fallback_type == "object" else []
        
        cleaned_content = self.json_cleaner.clean_ai_response(content, fallback_type)
        return self.json_cleaner.safe_json_loads(cleaned_content, {} if fallback_type == "object" else [])
