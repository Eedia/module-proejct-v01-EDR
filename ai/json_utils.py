"""
AI 응답 JSON 처리 유틸리티
"""
import re
import json
import logging
from typing import Dict, List, Union

logger = logging.getLogger(__name__)

class JSONCleaner:
    """AI 응답에서 JSON을 안전하게 추출하고 정리하는 유틸리티"""
    
    @staticmethod
    def clean_ai_response(content: str, fallback_type: str = "object") -> str:
        """AI 응답에서 JSON 부분만 추출하고 정리 (강화된 버전)"""
        if not content:
            return JSONCleaner._get_fallback_json(fallback_type)
        
        content = content.strip()
        
        # 마크다운 제거
        content = content.replace('``````', '').strip()
        
        # JSON 추출 (배열 또는 객체)
        if fallback_type == "array":
            start_char, end_char = "[", "]"
            start_idx = content.find("[")
            end_idx = content.rfind("]")
        else:
            start_char, end_char = "{", "}"
            start_idx = content.find("{")
            end_idx = content.rfind("}")
        
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            if fallback_type == "array":
                return "[]"
            else:
                fallback = {
                    "fix_command": "수동 조치 필요",
                    "validation_command": "수동 확인", 
                    "rollback_command": "수동 되돌리기",
                    "description": "JSON 형식 오류",
                    "confidence": 0.3,
                    "warnings": ["JSON 파싱 실패"]
                }
                return json.dumps(fallback)
        
        json_str = content[start_idx:end_idx+1]
        
        # 🔧 강력한 역슬래시 문제 해결
        try:
            # 1. 모든 Windows 경로 패턴을 슬래시로 변경
            json_str = re.sub(r'HKLM:\\', 'HKLM:/', json_str)
            json_str = re.sub(r'HKCU:\\', 'HKCU:/', json_str)
            json_str = re.sub(r'\\SOFTWARE', '/SOFTWARE', json_str)
            json_str = re.sub(r'\\Microsoft', '/Microsoft', json_str)
            json_str = re.sub(r'\\Windows', '/Windows', json_str)
            json_str = re.sub(r'\\System32', '/System32', json_str)
            
            # 2. PowerShell 변수는 건드리지 않고 나머지 역슬래시 이중화
            json_str = re.sub(r'\\(?!["\\/bfnrtu$])', r'\\\\', json_str)
            
            # 3. 쉼표 문제 해결
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)
            
            # 4. 유효성 검사
            json.loads(json_str)  # 파싱 테스트
            return json_str.strip()
            
        except Exception as e:
            logger.warning(f"JSON 정리 실패: {e}, 폴백 사용")
            return JSONCleaner._get_fallback_json(fallback_type)
    
    @staticmethod
    def _fix_backslash_issues(json_str: str) -> str:
        """역슬래시 이스케이프 문제 해결 (기존 메서드는 유지)"""
        # Windows 경로를 슬래시로 변경
        json_str = re.sub(r'HKLM:\\', 'HKLM:/', json_str)
        json_str = re.sub(r'HKCU:\\', 'HKCU:/', json_str)
        json_str = re.sub(r'\\SOFTWARE', '/SOFTWARE', json_str)
        json_str = re.sub(r'\\Microsoft', '/Microsoft', json_str)
        json_str = re.sub(r'\\Windows', '/Windows', json_str)
        json_str = re.sub(r'\\System32', '/System32', json_str)
        
        # 기타 역슬래시 이중화
        json_str = re.sub(r'\\(?!["\\/bfnrtu$])', r'\\\\', json_str)
        
        # 쉼표 문제 해결
        json_str = re.sub(r',\s*}', '}', json_str)
        json_str = re.sub(r',\s*]', ']', json_str)
        
        return json_str
    
    @staticmethod
    def _get_fallback_json(fallback_type: str) -> str:
        """폴백 JSON 반환"""
        if fallback_type == "array":
            return "[]"
        else:
            return json.dumps({
                "fix_command": "수동 조치 필요",
                "validation_command": "수동 확인",
                "rollback_command": "수동 되돌리기",
                "description": "AI 파싱 실패",
                "confidence": 0.3,
                "warnings": ["수동 검토 필요"]
            })
    
    @staticmethod
    def safe_json_loads(content: str, fallback: Union[Dict, List] = None) -> Union[Dict, List]:
        """안전한 JSON 로드"""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"JSON 로드 실패: {e}")
            return fallback if fallback is not None else {}
