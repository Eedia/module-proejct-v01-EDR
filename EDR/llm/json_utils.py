"""
AI 응답 JSON 처리 유틸리티
json-repair 라이브러리 활용한 강화된 JSON 처리
"""
import json
import re
import logging
from pathlib import Path
from typing import Dict, Any

# json-repair 라이브러리가 없다면 기본 처리 사용
try:
    from json_repair import repair_json
    HAS_JSON_REPAIR = True
except ImportError:
    HAS_JSON_REPAIR = False
    logging.warning("json-repair 라이브러리가 없습니다. 기본 JSON 처리를 사용합니다.")

logger = logging.getLogger(__name__)

class JSONCleaner:
    @staticmethod
    def clean_ai_response(content: str, fallback_type: str = "object") -> str:
        """AI 응답에서 JSON 부분만 추출하고 정리"""
        if not content:
            return JSONCleaner._get_fallback_json(fallback_type)
        
        content = content.strip()
        logger.info(f"AI 응답 길이: {len(content)} 문자")
        
        # ANSI 이스케이프 코드 제거
        content = re.sub(r'\x1b\[[0-9;]*m', '', content)
        
        # 마크다운 제거
        content = content.replace('```json', '').replace('```', '').strip()
        
        # JSON 추출
        if fallback_type == "array":
            start_idx = content.find("[")
            end_idx = content.rfind("]")
        else:
            start_idx = content.find("{")
            end_idx = content.rfind("}")
        
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            logger.warning("JSON 구조를 찾을 수 없음")
            return JSONCleaner._get_fallback_json(fallback_type)
        
        json_str = content[start_idx:end_idx+1]
        
        if HAS_JSON_REPAIR:
            try:
                # 1단계: json-repair로 자동 수정 시도
                repaired_json = repair_json(json_str)
                logger.info("json-repair로 JSON 자동 수정 완료")
                
                # 2단계: Windows 경로 정리
                repaired_json = JSONCleaner._normalize_paths(repaired_json)
                
                # 3단계: 최종 검증
                json.loads(repaired_json)
                logger.info(f"JSON 파싱 성공: {len(repaired_json)} 문자")
                return repaired_json.strip()
                
            except Exception as e:
                logger.error(f"json-repair 실패: {e}, 수동 수정 시도")
        
        # 수동 수정 시도
        try:
            fixed_json = JSONCleaner._fix_json_syntax(json_str)
            fixed_json = JSONCleaner._normalize_paths(fixed_json)
            json.loads(fixed_json)
            logger.info("수동 JSON 수정 성공")
            return fixed_json.strip()
        except Exception as e2:
            logger.error(f"수동 수정도 실패: {e2}")
            return JSONCleaner._get_fallback_json(fallback_type)
    
    @staticmethod
    def _normalize_paths(json_str: str) -> str:
        """Windows 경로 정리"""
        # 백슬래시를 슬래시로 변경
        json_str = json_str.replace('\\\\', '/')
        json_str = re.sub(r'HKLM:\\?', 'HKLM:/', json_str)
        json_str = re.sub(r'HKCU:\\?', 'HKCU:/', json_str)
        json_str = re.sub(r'C:\\([^"]*)', r'C:/\1', json_str)
        return json_str
    
    @staticmethod
    def _fix_json_syntax(json_str: str) -> str:
        """수동 JSON 구문 수정"""
        # 객체 간 쉼표 누락 수정
        json_str = re.sub(r'}\s*{', '}, {', json_str)
        # 배열-객체 간 쉼표 누락
        json_str = re.sub(r']\s*{', '], {', json_str)
        # 문자열-객체 간 쉼표 누락
        json_str = re.sub(r'"\s*{', '", {', json_str)
        # 숫자-객체 간 쉼표 누락
        json_str = re.sub(r'([0-9.]+)\s*{', r'\1, {', json_str)
        # 중복 쉼표 제거
        json_str = re.sub(r',\s*,', ',', json_str)
        # 마지막 쉼표 제거
        json_str = re.sub(r',\s*}', '}', json_str)
        json_str = re.sub(r',\s*]', ']', json_str)
        return json_str
    
    @staticmethod
    def _get_fallback_json(fallback_type: str) -> str:
        """폴백 JSON 반환"""
        return "[]" if fallback_type == "array" else "{}"
    
    @staticmethod
    def safe_json_loads(json_str: str, fallback_value=None):
        """안전한 JSON 로드"""
        try:
            return json.loads(json_str)
        except:
            return fallback_value if fallback_value is not None else {}

# Load all JSON files in a directory        
def load_all_json_files(directory: str) -> Dict[str, Any]:
    """지정된 디렉토리 내 모든 JSON 파일 로드"""
    results: Dict[str, Any] = {}
    dir_path = Path(directory)
    if not dir_path.exists():
        logger.warning(f"JSON 디렉토리를 찾을 수 없습니다: {directory}")
        return results

    for path in dir_path.rglob("*.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                results[path.name] = json.load(f)
        except Exception as e:
            logger.warning(f"JSON 파일 로드 실패: {path} - {e}")
    return results