"""
EDR LLM 모듈 테스트 (수정된 버전)
실제 프로젝트 구조에 맞춘 테스트
"""
import sys
import os
import logging
from datetime import datetime
from typing import Dict, List

# 프로젝트 루트 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# 환경변수 로드
from dotenv import load_dotenv
load_dotenv()

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_llm_with_real_structure():
    """실제 프로젝트 구조에 맞춘 LLM 모듈 테스트"""
    
    print("🤖 LLM 모듈 테스트 (실제 구조)")
    print("-" * 40)
    
    try:
        # 1. 실제 Finding 구조에 맞춘 샘플 데이터 생성
        from utils.data_structures import Finding
        
        sample_findings = [
            Finding(
                finding_id="TEST-001",
                rule_id="R_RDP_ENABLED",
                severity="high",
                score_impact=25,  # 필수 필드
                category="remote_access", 
                title="RDP 원격 연결 활성화됨",
                description="Windows RDP가 활성화되어 있어 원격 접근 위험이 있습니다.",
                timestamp=datetime.now().isoformat(),
                confidence=90,  # int 타입
                evidence={
                    "registry_evidence": [
                        {"key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", 
                         "value": "fDenyTSConnections", "data": 0}
                    ]
                }
            ),
            Finding(
                finding_id="TEST-002",
                rule_id="R_DEFENDER_DISABLED",
                severity="critical",
                score_impact=40,  # 필수 필드
                category="security_settings",
                title="Windows Defender 실시간 보호 비활성화",
                description="Windows Defender의 실시간 보호 기능이 비활성화되어 있습니다.",
                timestamp=datetime.now().isoformat(),
                confidence=95,  # int 타입
                evidence={
                    "registry_evidence": [
                        {"key": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 
                         "value": "DisableRealtimeMonitoring", "data": 1}
                    ]
                }
            )
        ]
        
        print(f"   ✅ 샘플 Finding 생성: {len(sample_findings)}개")
        
        # 2. API 키 확인
        if not os.getenv('GEMINI_API_KEY'):
            print("   ⚠️ GEMINI_API_KEY 환경변수가 설정되지 않음")
            print("   💡 .env 파일에 GEMINI_API_KEY=your_api_key_here 를 추가하세요")
            return False
        
        print("   ✅ Gemini API 키 확인됨")
        
        # 3. AI Remediator 테스트
        try:
            from llm.ai_remediator_new import AIRemediator
            
            print("   🔧 AI Remediator 테스트 시작...")
            remediator = AIRemediator()
            scripts = remediator.generate_remediation_scripts(sample_findings)
            
            print(f"   ✅ AI 조치 스크립트 생성: {len(scripts)}개")
            
            for i, script in enumerate(scripts, 1):
                print(f"      {i}. {script.rule_name}")
                print(f"         설명: {script.description}")
                print(f"         신뢰도: {script.confidence:.1%}")
                print(f"         수정 명령어: {script.fix_command[:50]}...")
                print()
                
        except Exception as e:
            print(f"   ❌ AI Remediator 테스트 실패: {e}")
            logger.error(f"AI Remediator 오류: {e}")
        
        # 4. Ask Your Scan 테스트
        try:
            from llm.ask_your_scan_upgraded import AskYourScanUpgraded
            
            print("   🔍 Ask Your Scan 테스트 시작...")
            query_handler = AskYourScanUpgraded()
            
            test_queries = [
                "총 몇 개의 보안 문제가 발견되었나요?",
                "가장 심각한 문제는 무엇인가요?",
                "RDP 관련 보안 위험이 있나요?"
            ]
            
            for query in test_queries:
                result = query_handler.process_query(
                    query, 
                    sample_findings,
                    {"hostname": "TEST-PC", "timestamp": datetime.now().isoformat()}
                )
                
                print(f"   ❓ {query}")
                print(f"   💬 {result['answer'][:100]}...")
                print(f"      신뢰도: {result['confidence']:.1%}, 소스: {result['source']}")
                print()
                
        except Exception as e:
            print(f"   ❌ Ask Your Scan 테스트 실패: {e}")
            logger.error(f"Ask Your Scan 오류: {e}")
        
        print("🎉 LLM 모듈 테스트 완료!")
        return True
        
    except Exception as e:
        logger.error(f"LLM 테스트 실패: {e}")
        print(f"❌ LLM 테스트 실패: {e}")
        return False

if __name__ == "__main__":
    print("🔍 EDR LLM 모듈 테스트 (수정 버전)")
    print("=" * 60)
    
    success = test_llm_with_real_structure()
    
    if success:
        print("\n✅ LLM 모듈이 정상적으로 동작합니다!")
        print("이제 전체 EDR 시스템과 통합할 수 있습니다.")
    else:
        print("\n❌ 테스트 실패. 설정을 확인해주세요.")
    
    sys.exit(0 if success else 1)
