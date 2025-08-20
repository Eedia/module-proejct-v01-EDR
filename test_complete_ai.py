"""
AI 모듈 완전 테스트 스크립트 - 통합 버전
"""
import sys
import os
import json
from datetime import datetime
from typing import Dict, List

# PYTHONPATH 설정
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = current_dir
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_complete_ai_workflow():
    """AI 모듈 통합 워크플로우 테스트"""
    
    print("🤖 EDR AI 모듈 통합 테스트 시작!")
    print("=" * 60)
    print(f"⏰ 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 설정 로드
    try:
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
        print("✅ config.json 로드 성공")
    except FileNotFoundError:
        print("⚠️  config.json 없음 - 기본 설정 사용")
        config = {"ai": {"provider": "gemini", "model": "gemini-1.5-flash"}}
    
    # EDR 스캔 데이터 로드
    try:
        with open('findings.json', 'r', encoding='utf-8') as f:
            raw_scan_data = json.load(f)
        
        print("✅ EDR 스캔 데이터 로드 성공")
        
        # 스캔 결과 요약
        summary = raw_scan_data.get('scan_summary', {})
        metadata = raw_scan_data.get('scan_metadata', {})
        
        print(f"   🖥️  호스트명: {metadata.get('hostname', 'N/A')}")
        print(f"   📅 스캔 시간: {metadata.get('timestamp', 'N/A')}")
        print(f"   ⚖️  위험 수준: {summary.get('risk_level', 'N/A')}")
        print(f"   📊 총 발견: {summary.get('total_findings', 0)}개")
        
        # AI 모듈 호환 형식으로 변환
        from ai.utils import normalize_findings_data
        findings_data = normalize_findings_data(raw_scan_data)
        
        print(f"   🔄 AI 분석용 변환 완료:")
        print(f"      📊 이벤트로그: {len(findings_data['event_logs'])}개")
        print(f"      📊 레지스트리: {len(findings_data['registry_data'])}개")
        
    except FileNotFoundError:
        print("❌ test_findings.json 파일이 없습니다!")
        return False
    except Exception as e:
        print(f"❌ 데이터 로드 오류: {e}")
        return False
    
    print()
    
    # ===== AI 통합 분석 =====
    print("🧠 AI 통합 분석")
    print("-" * 60)
    
    try:
        from ai.security_analyzer import AISecurityAnalyzer
        
        analyzer = AISecurityAnalyzer(config)
        print("   ✅ AI Security Analyzer 초기화 성공")
        
        # 🔥 한 번에 모든 분석 수행
        final_results = analyzer.analyze_raw_data(findings_data)
        
        print(f"   🎉 통합 분석 완료!")
        print(f"      • 탐지된 이슈: {final_results.get('total_issues', 0)}개")
        print(f"      • 생성된 해결책: {len(final_results.get('ai_remediation', []))}개")
        print(f"      • AI 통계: 평균 신뢰도 {final_results.get('statistics', {}).get('avg_confidence', 0):.1%}")
        
        # 상세 결과 출력
        detected_issues = final_results.get('detected_issues', [])
        ai_remediation = final_results.get('ai_remediation', [])
        
        print("\n   📊 탐지된 주요 이슈:")
        for i, issue in enumerate(detected_issues[:3], 1):
            severity = issue.get('severity', '').upper()
            title = issue.get('title', 'Unknown')
            confidence = issue.get('confidence', 0) * 100
            print(f"      {i}. [{severity}] {title} (신뢰도: {confidence:.0f}%)")
        
        print("\n   💊 생성된 해결책:")
        for i, script in enumerate(ai_remediation[:3], 1):
            rule_name = script.get('rule_name', 'Unknown')
            confidence = script.get('confidence', 0) * 100
            print(f"      {i}. {rule_name} (신뢰도: {confidence:.0f}%)")
        
        # 경영진 요약
        executive_summary = final_results.get('executive_summary', '')
        if executive_summary:
            print(f"\n   📋 경영진 요약: {executive_summary[:100]}...")
        
    except Exception as e:
        print(f"   ❌ AI 분석 실패: {e}")
        return False
    
    print()
    
    # ===== 질문 답변 테스트 =====
    print("💬 자연어 질문 답변 테스트")
    print("-" * 30)
    
    try:
        test_questions = [
            "안녕하세요?",
            "총 몇 개의 보안 문제가 발견되었나요?",
            "가장 위험한 문제는 무엇인가요?",
            "persistence 관련 이슈가 있나요?",
            "호스트명을 알 수 있나요?"
        ]
        
        # 컨텍스트 데이터 구성
        context_data = {
            'detected_issues': detected_issues,
            'ai_remediation': ai_remediation,
            'hostname': metadata.get('hostname', findings_data.get('hostname', 'Unknown')),
            'total_issues': len(detected_issues),
            'scan_summary': summary,
            'scan_metadata': metadata
        }
        
        for question in test_questions:
            answer_result = analyzer.process_user_query(question, context_data)
            print(f"   ❓ {question}")
            print(f"   💬 {answer_result['answer'][:80]}...")
            print(f"      신뢰도: {answer_result['confidence']:.1%}")
            print()
        
    except Exception as e:
        print(f"   ❌ 질문 답변 실패: {e}")
        return False
    
    # ===== 결과 파일 확인 =====
    print("💾 생성된 파일 확인")
    print("-" * 30)
    
    output_files = [
        'output/ai_analysis.json',
        'output/ai_remediation.json'
    ]
    
    for file_path in output_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"   ✅ {file_path} ({file_size} bytes)")
        else:
            print(f"   ⚠️  {file_path} 생성되지 않음")
    
    print()
    print("🎉 AI 통합 분석 완료!")
    print("=" * 60)
    print(f"⏰ 완료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("📋 최종 결과:")
    print(f"   📊 원본 EDR 발견사항: {summary.get('total_findings', 0)}개")
    print(f"   🤖 AI 분석 결과: {len(detected_issues)}개 이슈")
    print(f"   💡 AI 해결책: {len(ai_remediation)}개")
  
    
    return True

if __name__ == "__main__":
    success = test_complete_ai_workflow()
    
    
    sys.exit(0 if success else 1)
