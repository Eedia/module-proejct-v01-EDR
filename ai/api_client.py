# """
# OpenAI API 공통 클라이언트
# """
# from openai import OpenAI
# import os
# import logging
# from typing import Optional
# from dotenv import load_dotenv

# load_dotenv()

# class OpenAIClient:
#     """OpenAI API 호출을 위한 공통 클라이언트"""
    
#     def __init__(self):
#         api_key = os.getenv('OPENAI_API_KEY')
#         if not api_key:
#             raise ValueError("OPENAI_API_KEY 환경변수가 설정되지 않음")
        
#         self.client = OpenAI(api_key=api_key)
#         self.logger = logging.getLogger(__name__)
    
#     def chat_completion(self, 
#                        prompt: str, 
#                        model: str = "gpt-4",
#                        max_tokens: int = 800,
#                        temperature: float = 0.1) -> Optional[str]:
#         """채팅 완료 API 호출"""
#         try:
#             response = self.client.chat.completions.create(
#                 model=model,
#                 messages=[{"role": "user", "content": prompt}],
#                 max_tokens=max_tokens,
#                 temperature=temperature
#             )
#             return response.choices[0].message.content
#         except Exception as e:
#             self.logger.error(f"OpenAI API 호출 실패: {e}")
#             return None
    
#     def generate_security_analysis(self, prompt: str) -> Optional[str]:
#         """보안 분석용 최적화된 호출"""
#         return self.chat_completion(prompt, model="gpt-4", max_tokens=1000, temperature=0.1)
    
#     def generate_summary(self, prompt: str) -> Optional[str]:
#         """요약용 최적화된 호출"""
#         return self.chat_completion(prompt, model="gpt-3.5-turbo", max_tokens=500, temperature=0.1)
    
#     def generate_remediation(self, prompt: str) -> Optional[str]:
#         """해결책 생성용 최적화된 호출"""
#         return self.chat_completion(prompt, model="gpt-4", max_tokens=800, temperature=0.1)

"""
Google Gemini API 공통 클라이언트
"""
import google.generativeai as genai
import os
import logging
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class GeminiClient:
    """Google Gemini API 호출을 위한 공통 클라이언트"""
    
    def __init__(self):
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않음")
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        self.logger = logging.getLogger(__name__)
    
    def chat_completion(self, 
                       prompt: str, 
                       model: str = "gemini-1.5-flash",
                       max_tokens: int = 800,
                       temperature: float = 0.1) -> Optional[str]:
        """채팅 완료 API 호출"""
        try:
            # Gemini 설정
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )
            
            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )
            
            return response.text
        except Exception as e:
            self.logger.error(f"Gemini API 호출 실패: {e}")
            return None
    
    def generate_security_analysis(self, prompt: str) -> Optional[str]:
        """보안 분석용 최적화된 호출"""
        return self.chat_completion(prompt, max_tokens=1000, temperature=0.1)
    
    def generate_summary(self, prompt: str) -> Optional[str]:
        """요약용 최적화된 호출"""
        return self.chat_completion(prompt, max_tokens=500, temperature=0.1)
    
    def generate_remediation(self, prompt: str) -> Optional[str]:
        """해결책 생성용 최적화된 호출"""
        return self.chat_completion(prompt, max_tokens=800, temperature=0.1)
