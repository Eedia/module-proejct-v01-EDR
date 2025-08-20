"""
AI 모듈 완전 테스트 스크립트
"""
import sys
import os
import json
from datetime import datetime

# 🔧 PYTHONPATH 설정 (프로젝트 루트 추가)
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = current_dir
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_complete_ai_workflow():
    """AI 모듈 전체 워크플로우 테스트"""
    
    print("🤖 EDR AI 모듈 완전 테스트 시작!")
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
        config = {"ai": {"provider": "openai", "model": "gpt-4"}}
    
    # 테스트 데이터 로드
    try:
        with open('test_findings.json', 'r', encoding='utf-8') as f:
            findings_data = json.load(f)
        print("✅ test_findings.json 로드 성공")
        print(f"   📊 이벤트로그: {len(findings_data['event_logs'])}개")
        print(f"   📊 레지스트리 키: {len(findings_data['registry_data'])}개")
    except FileNotFoundError:
        print("❌ test_findings.json 파일이 없습니다!")
        print("   위의 가이드대로 test_findings.json 파일을 만들어주세요.")
        return False
    
    print()
    
    # ===== 1단계: 이슈 탐지 테스트 =====
    print("🔍 1단계: AI 이슈 탐지 테스트")
    print("-" * 30)
    
    try:
        from ai.issue_detector import AIIssueDetector
        
        detector = AIIssueDetector(config)
        print("   ✅ Issue Detector 초기화 성공")
        
        detected_issues = detector.analyze_findings(findings_data)
        print(f"   🎯 AI가 {len(detected_issues)}개 보안 이슈 탐지!")
        
        for i, issue in enumerate(detected_issues, 1):
            print(f"      {i}. [{issue.severity.upper()}] {issue.title}")
            print(f"         신뢰도: {issue.confidence:.1%}")
        
    except Exception as e:
        print(f"   ❌ 이슈 탐지 실패: {e}")
        return False
    
    print()
    
    # ===== 2단계: 해결책 생성 테스트 =====
    print("💊 2단계: AI 해결책 생성 테스트") 
    print("-" * 30)
    
    try:
        from ai.remediation import RemediationEngine
        
        remediation_engine = RemediationEngine(config)
        print("   ✅ Remediation Engine 초기화 성공")
        
        remediation_scripts = remediation_engine.generate_remediation_scripts(detected_issues)
        print(f"   🔧 AI가 {len(remediation_scripts)}개 해결책 생성!")
        
        for i, script in enumerate(remediation_scripts, 1):
            print(f"      {i}. {script.rule_name}")
            print(f"         조치: {script.fix_command[:50]}...")
            print(f"         신뢰도: {script.confidence:.1%}")
            if script.warnings:
                print(f"         ⚠️  주의: {script.warnings[0]}")
        
    except Exception as e:
        print(f"   ❌ 해결책 생성 실패: {e}")
        return False
    
    print()
    
    # ===== 3단계: 요약 생성 테스트 =====
    print("📝 3단계: AI 요약 생성 테스트")
    print("-" * 30)

    try:
        from ai.summarizer import SecuritySummarizer
        
        summarizer = SecuritySummarizer(config)
        print("   ✅ Summarizer 초기화 성공")
        
        # 임시 AI 결과 데이터
        if remediation_scripts:
            avg_confidence = sum(s.confidence for s in remediation_scripts) / len(remediation_scripts)
        else:
            avg_confidence = 0.0
        
        temp_ai_results = {
            "ai_remediation": [script.to_dict() for script in remediation_scripts],
            "statistics": {"avg_confidence": avg_confidence}
        }
        
        summary_findings = {"alerts": [issue.to_dict() for issue in detected_issues]}
        
        executive_summary = summarizer.generate_executive_summary(summary_findings, temp_ai_results)
        print(f"   📋 경영진 요약: {executive_summary}")
        
        detailed_summary = summarizer.generate_detailed_summary(summary_findings, temp_ai_results)
        print(f"   📊 상세 요약: 총 {detailed_summary['total_issues']}개 이슈")
        
        ai_insight = summarizer.generate_ai_insight(summary_findings, temp_ai_results)
        print(f"   🧠 AI 인사이트: {ai_insight[:100]}...")
        
    except Exception as e:
        print(f"   ❌ 요약 생성 실패: {e}")
        return False
    
    print()
    
    # ===== 4단계: 통합 분석 테스트 =====
    print("🧠 4단계: AI 통합 분석 테스트")
    print("-" * 30)

    try:
        from ai.security_analyzer import AISecurityAnalyzer
        
        analyzer = AISecurityAnalyzer(config) 
        print("   ✅ Security Analyzer 초기화 성공")
        
        # analyze_raw_data로 수정 (findings.json 형태로 전달)
        final_results = analyzer.analyze_raw_data(findings_data)
        
        print(f"   🎉 최종 분석 완료!")
        print(f"      • 탐지된 이슈: {final_results.get('total_issues', 0)}개")
        print(f"      • 생성된 해결책: {len(final_results.get('ai_remediation', []))}개")
        
    except Exception as e:
        print(f"   ❌ 통합 분석 실패: {e}")
        return False
    
    print()
    
    # ===== 5단계: 질문 답변 테스트 =====
    print("💬 5단계: 자연어 질문 답변 테스트")
    print("-" * 30)
    
    try:
        test_questions = [
            "총 몇 개의 보안 문제가 발견되었나요?",
            "Defender 문제가 있나요?", 
            "가장 위험한 문제는 무엇인가요?",
            "RDP 관련 이슈가 있나요?"
        ]
        
        for question in test_questions:
            answer_result = analyzer.process_user_query(question, findings_data)
            print(f"   ❓ {question}")
            print(f"   💬 {answer_result['answer'][:80]}...")
            print(f"      신뢰도: {answer_result['confidence']:.1%}")
            print()
        
    except Exception as e:
        print(f"   ❌ 질문 답변 실패: {e}")
        return False
    
    # ===== 6단계: 결과 파일 확인 =====
    print("💾 6단계: 생성된 파일 확인")
    print("-" * 30)
    
    output_files = [
        'output/ai_remediation.json',
        'output/ai_analysis.json'
    ]
    
    for file_path in output_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"   ✅ {file_path} ({file_size} bytes)")
        else:
            print(f"   ⚠️  {file_path} 생성되지 않음")
    
    print()
    print("🎉 AI 모듈 완전 테스트 성공!")
    print("=" * 60)
    print(f"⏰ 완료 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("📋 다음 단계:")
    print("   1. output/ai_remediation.json → UI팀이 사용")
    print("   2. output/ai_analysis.json → 리포트팀이 사용")
    print("   3. 다른 팀원들에게 'AI 모듈 완성!' 보고")
    
    return True  # 🔧 성공 시 True 반환


if __name__ == "__main__":
    success = test_complete_ai_workflow()


    # 테스트 완료 후 종료
    import sys
    sys.exit(0 if success else 1)
