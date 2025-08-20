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
        """AI 응답에서 JSON 부분만 추출하고 정리 (최강화 버전 - Gemini 대응)"""
        if not content:
            return JSONCleaner._get_fallback_json(fallback_type)
        
        content = content.strip()
        
        # 🔧 ANSI 이스케이프 코드 제거 (Gemini가 색상코드 포함할 수 있음)
        content = re.sub(r'\x1b\[[0-9;]*m', '', content)
        
        # 마크다운 제거
        content = content.replace('``````', '').strip()
        
        # JSON 추출
        if fallback_type == "array":
            start_idx = content.find("[")
            end_idx = content.rfind("]")
        else:
            start_idx = content.find("{")
            end_idx = content.rfind("}")
        
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            return JSONCleaner._get_fallback_json(fallback_type)
        
        json_str = content[start_idx:end_idx+1]
        
        try:
            # 임시 플레이스홀더로 유효한 이스케이프 보호
            json_str = json_str.replace('\\\\', '<!DOUBLE_BACKSLASH!>')
            json_str = json_str.replace('\\"', '<!ESCAPED_QUOTE!>')
            json_str = json_str.replace('\\/', '<!ESCAPED_SLASH!>')
            json_str = json_str.replace('\\n', '<!NEWLINE!>')
            json_str = json_str.replace('\\r', '<!CARRIAGE_RETURN!>')
            json_str = json_str.replace('\\t', '<!TAB!>')
            
            # Windows 경로 패턴을 슬래시로 변경
            json_str = re.sub(r'HKLM:\\?', 'HKLM:/', json_str)
            json_str = re.sub(r'HKCU:\\?', 'HKCU:/', json_str)  
            json_str = re.sub(r'\\SOFTWARE', '/SOFTWARE', json_str)
            json_str = re.sub(r'\\Microsoft', '/Microsoft', json_str)
            json_str = re.sub(r'\\Windows', '/Windows', json_str)
            json_str = re.sub(r'\\System32', '/System32', json_str)
            json_str = re.sub(r'\\CurrentVersion', '/CurrentVersion', json_str)
            json_str = re.sub(r'\\Run', '/Run', json_str)
            
            # C:\ 드라이브 경로 처리
            json_str = re.sub(r'C:\\([^"]*)', r'C:/\1', json_str)
            json_str = re.sub(r'\\Users', '/Users', json_str)
            json_str = re.sub(r'\\Program Files', '/Program Files', json_str)
            json_str = re.sub(r'\\Public', '/Public', json_str)
            json_str = re.sub(r'\\Downloads', '/Downloads', json_str)
            json_str = re.sub(r'\\AppData', '/AppData', json_str)
            
            # PowerShell 변수는 보호하고 나머지는 슬래시로
            json_str = re.sub(r'\\(?!\$)', '/', json_str)
            
            # 플레이스홀더 복원
            json_str = json_str.replace('<!DOUBLE_BACKSLASH!>', '\\\\')
            json_str = json_str.replace('<!ESCAPED_QUOTE!>', '\\"')
            json_str = json_str.replace('<!ESCAPED_SLASH!>', '\\/')
            json_str = json_str.replace('<!NEWLINE!>', '\\n')
            json_str = json_str.replace('<!CARRIAGE_RETURN!>', '\\r')
            json_str = json_str.replace('<!TAB!>', '\\t')
            
            # 쉼표 문제 해결
            json_str = re.sub(r',\s*}', '}', json_str)
            json_str = re.sub(r',\s*]', ']', json_str)
            
            # 유효성 검사
            json.loads(json_str)
            return json_str.strip()
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON 파싱 실패 (위치: {e.pos}): {e}")
            
            # 모든 역슬래시를 슬래시로 교체
            try:
                safe_json_str = re.sub(r'\\(?!["\\/bfnrtu])', '/', json_str)
                json.loads(safe_json_str)
                logger.info("역슬래시 전체 교체로 파싱 성공")
                return safe_json_str.strip()
            except Exception:
                logger.error("최종 파싱도 실패, 폴백 사용")
                return JSONCleaner._get_fallback_json(fallback_type)
                
        except Exception as e:
            logger.error(f"JSON 전처리 실패: {e}")
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
