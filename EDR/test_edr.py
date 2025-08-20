"""
test_edr.py
EDR Scanner 기본 테스트 스크립트
"""

import sys
import os
import logging

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_utils():
    """utils 모듈 테스트"""
    print("=== Utils 모듈 테스트 ===")
    
    try:
        from utils import generate_finding_id, generate_scan_id, calculate_risk_level
        
        # ID 생성 테스트
        finding_id = generate_finding_id()
        scan_id = generate_scan_id()
        
        print(f"Finding ID: {finding_id}")
        print(f"Scan ID: {scan_id}")
        
        # 위험도 계산 테스트
        risk_levels = [
            (95, "양호"),
            (75, "주의"), 
            (55, "경고")
        ]
        
        for score, expected in risk_levels:
            result = calculate_risk_level(score)
            print(f"점수 {score} -> 위험도: {result} (예상: {expected})")
            assert result == expected, f"Expected {expected}, got {result}"
        
        print("✓ Utils 모듈 테스트 통과")
        
    except Exception as e:
        print(f"✗ Utils 모듈 테스트 실패: {e}")
        return False
    
    return True

def test_scoring_engine():
    """점수화 엔진 테스트"""
    print("\n=== 점수화 엔진 테스트 ===")
    
    try:
        from utils import generate_score_summary
        
        # 테스트 Finding 데이터
        test_findings = [
            {
                "finding_id": "F001",
                "rule_id": "R_LOLBIN_RUNDLL32",
                "severity": "high",
                "score_impact": -15,
                "category": "execution",
                "confidence": 85
            },
            {
                "finding_id": "F002", 
                "rule_id": "R_SERVICE_TEMP_PATH",
                "severity": "medium",
                "score_impact": -10,
                "category": "persistence",
                "confidence": 80
            }
        ]
        
        # 점수 계산
        summary = generate_score_summary(test_findings)
        
        print(f"총점: {summary['total_score']}")
        print(f"위험도: {summary['risk_level']}")
        print(f"총 탐지 항목: {summary['total_findings']}")
        
        print("✓ 점수화 엔진 테스트 통과")
        
    except Exception as e:
        print(f"✗ 점수화 엔진 테스트 실패: {e}")
        return False
    
    return True

def test_evtx_collector():
    """이벤트 로그 수집기 테스트"""
    print("\n=== 이벤트 로그 수집기 테스트 ===")
    
    try:
        from evtx import EventLogCollector
        
        # 짧은 시간 범위로 테스트
        collector = EventLogCollector(time_range_hours=1)
        
        print(f"수집 시간 범위: {collector.time_range_hours}시간")
        print(f"대상 채널 수: {len(collector.target_channels)}")
        
        # 통계 정보 확인
        stats = collector.get_collection_statistics()
        print(f"통계 정보: {stats}")
        
        print("✓ 이벤트 로그 수집기 테스트 통과")
        
    except Exception as e:
        print(f"✗ 이벤트 로그 수집기 테스트 실패: {e}")
        return False
    
    return True

def test_event_analyzer():
    """이벤트 분석기 테스트"""
    print("\n=== 이벤트 분석기 테스트 ===")
    
    try:
        from evtx import EventAnalyzer
        
        analyzer = EventAnalyzer()
        
        # 테스트 이벤트 데이터
        test_events = [
            {
                "channel": "Security",
                "event_id": 4688,
                "timestamp": "2025-08-20T14:25:30Z",
                "computer": "TEST-PC",
                "process_name": "C:\\Windows\\System32\\rundll32.exe",
                "command_line": 'rundll32.exe javascript:"test"',
                "parent_process": "C:\\Windows\\System32\\cmd.exe",
                "user": "TEST\\user01"
            }
        ]
        
        # 분석 실행
        findings = analyzer.analyze_events(test_events)
        
        print(f"분석된 Finding 수: {len(findings)}")
        
        for finding in findings:
            print(f"- {finding['title']} ({finding['severity']})")
        
        print("✓ 이벤트 분석기 테스트 통과")
        
    except Exception as e:
        print(f"✗ 이벤트 분석기 테스트 실패: {e}")
        return False
    
    return True

def test_file_handler():
    """파일 핸들러 테스트"""
    print("\n=== 파일 핸들러 테스트 ===")
    
    try:
        from utils import FileHandler
        
        # 테스트용 출력 디렉토리
        test_output_dir = "test_output"
        file_handler = FileHandler(test_output_dir)
        
        # 테스트 데이터
        test_scan_results = {
            "scan_metadata": {
                "scan_id": "test_scan_001",
                "timestamp": "2025-08-20T15:30:00Z",
                "hostname": "TEST-PC"
            },
            "scan_summary": {
                "total_score": 75,
                "risk_level": "주의",
                "total_findings": 1
            },
            "findings": [
                {
                    "finding_id": "F001",
                    "title": "테스트 탐지 항목",
                    "severity": "medium"
                }
            ],
            "system_info": {},
            "statistics": {}
        }
        
        # JSON 저장 테스트
        json_path = file_handler.save_findings_json(test_scan_results, "test_scan_001")
        print(f"JSON 저장 경로: {json_path}")
        
        # HTML 리포트 생성 테스트
        html_path = file_handler.generate_html_report(test_scan_results)
        print(f"HTML 리포트 경로: {html_path}")
        
        # 파일 존재 확인
        if os.path.exists(json_path) and os.path.exists(html_path):
            print("✓ 파일 핸들러 테스트 통과")
            
            # 테스트 파일 정리
            import shutil
            if os.path.exists(test_output_dir):
                shutil.rmtree(test_output_dir)
            
            return True
        else:
            print("✗ 생성된 파일을 찾을 수 없습니다.")
            return False
        
    except Exception as e:
        print(f"✗ 파일 핸들러 테스트 실패: {e}")
        return False

def test_integration():
    """통합 테스트"""
    print("\n=== 통합 테스트 ===")
    
    try:
        # 메인 모듈 임포트 테스트
        from main import generate_ai_recommendations, get_system_info
        
        # 시스템 정보 수집 테스트
        system_info = get_system_info()
        print(f"운영체제: {system_info.get('operating_system')}")
        print(f"호스트명: {system_info.get('hostname')}")
        
        # AI 추천사항 생성 테스트
        test_findings = [
            {
                "rule_id": "R_LOLBIN_RUNDLL32",
                "severity": "high",
                "title": "rundll32.exe JavaScript 실행"
            }
        ]
        
        recommendations = generate_ai_recommendations(test_findings, 65)
        
        print(f"즉시 조치사항: {len(recommendations['immediate_actions'])}개")
        print(f"단기 조치사항: {len(recommendations['short_term_actions'])}개") 
        print(f"장기 조치사항: {len(recommendations['long_term_actions'])}개")
        
        print("✓ 통합 테스트 통과")
        
    except Exception as e:
        print(f"✗ 통합 테스트 실패: {e}")
        return False
    
    return True

def main():
    """메인 테스트 함수"""
    print("EDR Scanner 모듈 테스트 시작\n")
    
    test_results = []
    
    # 각 테스트 실행
    test_functions = [
        ("Utils 모듈", test_utils),
        ("점수화 엔진", test_scoring_engine), 
        ("이벤트 로그 수집기", test_evtx_collector),
        ("이벤트 분석기", test_event_analyzer),
        ("파일 핸들러", test_file_handler),
        ("통합 테스트", test_integration)
    ]
    
    for test_name, test_func in test_functions:
        try:
            result = test_func()
            test_results.append((test_name, result))
        except Exception as e:
            print(f"✗ {test_name} 테스트 중 예외 발생: {e}")
            test_results.append((test_name, False))
    
    # 결과 요약
    print("\n" + "="*50)
    print("테스트 결과 요약")
    print("="*50)
    
    passed = 0
    failed = 0
    
    for test_name, result in test_results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name:<20}: {status}")
        
        if result:
            passed += 1
        else:
            failed += 1
    
    print("-"*50)
    print(f"통과: {passed}개, 실패: {failed}개")
    
    if failed == 0:
        print("🎉 모든 테스트가 통과했습니다!")
        return 0
    else:
        print(f"⚠️  {failed}개의 테스트가 실패했습니다.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
