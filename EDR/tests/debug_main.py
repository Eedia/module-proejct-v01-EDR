"""
디버그용 메인 스크립트 - 상세한 오류 정보 출력
"""
import sys
import os
import logging
import traceback
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
    
    print("🛡️ 통합 EDR 시스템 v2.0 (디버그 모드)")
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
        
        print("\n✅ 통합 EDR 분석 완료!")
        
    except Exception as e:
        logger.error(f"시스템 오류: {e}")
        print(f"\n❌ 시스템 오류: {e}")
        print(f"\n🔍 상세 스택 트레이스:")
        traceback.print_exc()

if __name__ == "__main__":
    main()
