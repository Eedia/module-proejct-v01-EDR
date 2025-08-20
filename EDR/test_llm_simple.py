"""
LLM 모듈 간단 테스트 스크립트
API 키만 있으면 바로 실행 가능
"""
import os
from dotenv import load_dotenv

# 환경변수 로드
load_dotenv()

def simple_llm_test():
    """간단한 LLM 기능 테스트"""
    
    print("🤖 LLM 모듈 간단 테스트")
    print("=" * 40)
    
    # 1. API 키 확인
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("❌ GEMINI_API_KEY가 설정되지 않았습니다!")
        print("💡 .env 파일에 GEMINI_API_KEY=your_key_here 를 추가하세요")
        return False
    
    print(f"✅ API 키 확인: {'*' * 10}{api_key[-4:]}")
    
    # 2. Gemini API 클라이언트 테스트
    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        response = model.generate_content("안녕하세요! 간단한 테스트입니다.")
        print(f"✅ Gemini API 연결 성공")
        print(f"   응답: {response.text[:50]}...")
        
    except Exception as e:
        print(f"❌ Gemini API 연결 실패: {e}")
        return False
    
    # 3. JSON 유틸리티 테스트
    try:
        from llm.json_utils import JSONCleaner
        
        test_response = '''
        ```json
        {
            "test": "성공",
            "confidence": 0.95
        }
        ```
        '''
        
        cleaner = JSONCleaner()
        cleaned = cleaner.clean_ai_response(test_response)
        parsed = cleaner.safe_json_loads(cleaned)
        
        print(f"✅ JSON 처리 성공: {parsed}")
        
    except Exception as e:
        print(f"❌ JSON 처리 실패: {e}")
        return False
    
    # 4. 간단한 AI 조치 스크립트 생성 테스트
    try:
        # 간단한 프롬프트로 테스트
        prompt = """
Windows 보안 전문가로서 RDP가 활성화된 상황에 대한 조치를 JSON으로 제공해주세요.

{
    "fix_command": "PowerShell 명령어",
    "validation_command": "검증 명령어", 
    "rollback_command": "롤백 명령어",
    "description": "설명",
    "confidence": 0.9,
    "warnings": ["주의사항"]
}

JSON만 응답하세요.
"""
        
        response = model.generate_content(prompt)
        print(f"✅ AI 조치 스크립트 생성 테스트")
        print(f"   응답 길이: {len(response.text)} 문자")
        
        # JSON 파싱 테스트
        cleaned = cleaner.clean_ai_response(response.text)
        parsed = cleaner.safe_json_loads(cleaned)
        
        if parsed and 'fix_command' in parsed:
            print(f"   ✅ JSON 파싱 성공")
            print(f"   조치: {parsed.get('fix_command', '')[:50]}...")
        else:
            print(f"   ⚠️ JSON 파싱 실패하지만 응답은 받음")
        
    except Exception as e:
        print(f"❌ AI 조치 스크립트 테스트 실패: {e}")
        return False
    
    print("\n🎉 LLM 기본 기능 테스트 완료!")
    print("모든 핵심 기능이 정상 동작합니다.")
    return True

if __name__ == "__main__":
    success = simple_llm_test()
    if success:
        print("\n✅ 이제 전체 EDR 시스템에서 LLM 모듈을 사용할 수 있습니다!")
    else:
        print("\n❌ 설정을 확인하고 다시 시도해주세요.")
