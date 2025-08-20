"""
main_integrated.py
완전히 통합된 EDR 시스템 - 기존 룰 기반 + AI 분석
"""

import sys
import os
import logging
from datetime import datetime

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.integrated_analyzer import IntegratedEDRAnalyzer, run_integrated_scan, ask_about_scan

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """메인 실행 함수"""
    
    print("🛡️ 통합 EDR 시스템 v2.0")
    print("=" * 50)
    print("기존 룰 기반 탐지 + AI 분석 통합 시스템")
    print("=" * 50)
    
    try:
        # 1. 통합 분석 실행
        print("\n🚀 통합 EDR 분석 시작...")
        results = run_integrated_scan()
        
        # 2. 결과 요약 출력
        print("\n📊 분석 결과 요약:")
        print("-" * 30)
        
        rule_analysis = results['rule_based_analysis']
        ai_analysis = results['ai_analysis']
        metadata = results['integration_metadata']
        
        print(f"🏠 호스트명: {metadata['hostname']}")
        print(f"⏱️ 분석 시간: {metadata['analysis_duration_seconds']:.1f}초")
        print(f"🔍 룰 기반 탐지: {metadata['total_rule_findings']}개 발견사항")
        print(f"🤖 AI 탐지: {metadata['total_ai_issues']}개 보안 이슈")
        print(f"📝 AI 요약: {ai_analysis['executive_summary']}")
        
        # 3. 주요 발견사항 출력
        if rule_analysis['findings']:
            print(f"\n🔴 주요 룰 기반 발견사항 (상위 3개):")
            for i, finding in enumerate(rule_analysis['findings'][:3], 1):
                severity = finding.get('severity', 'unknown').upper()
                desc = finding.get('description', '설명 없음')
                print(f"  {i}. [{severity}] {desc}")
        
        if ai_analysis['detected_issues']:
            print(f"\n🤖 주요 AI 탐지 이슈 (상위 3개):")
            for i, issue in enumerate(ai_analysis['detected_issues'][:3], 1):
                severity = issue.get('severity', 'unknown').upper()
                title = issue.get('title', '제목 없음')
                confidence = issue.get('confidence', 0) * 100
                print(f"  {i}. [{severity}] {title} (신뢰도: {confidence:.0f}%)")
        
        # 4. AI 해결책 출력
        if ai_analysis['ai_remediation']:
            print(f"\n🛠️ AI 추천 해결책 (상위 2개):")
            for i, script in enumerate(ai_analysis['ai_remediation'][:2], 1):
                desc = script.get('description', '해결책')
                fix_cmd = script.get('fix_command', '명령어 없음')
                confidence = script.get('confidence', 0) * 100
                print(f"  {i}. {desc} (신뢰도: {confidence:.0f}%)")
                print(f"     명령어: {fix_cmd}")
        
        # 5. 대화형 질의응답
        print(f"\n💬 분석 결과에 대해 질문하세요 (종료: 'quit'):")
        print("예시: '몇 개의 문제가 발견되었나요?', '가장 위험한 문제는 무엇인가요?'")
        
        while True:
            try:
                question = input("\n❓ 질문: ").strip()
                
                if question.lower() in ['quit', 'exit', '종료', 'q']:
                    break
                
                if not question:
                    continue
                
                # AI 질의응답
                answer = ask_about_scan(question, results)
                print(f"🤖 답변: {answer}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ 질문 처리 실패: {e}")
        
        print("\n✅ 통합 EDR 분석 완료!")
        print(f"📁 결과는 output/ 폴더에 저장되었습니다.")
        
    except KeyboardInterrupt:
        print("\n⏹️ 사용자에 의해 중단되었습니다.")
    except Exception as e:
        logger.error(f"시스템 오류: {e}")
        print(f"\n❌ 시스템 오류: {e}")
        print("자세한 내용은 로그를 확인하세요.")

if __name__ == "__main__":
    main()
