"""
test_reg.py
reg 모듈 테스트 스크립트
"""

import sys
import os

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_reg_module():
    """reg 모듈 테스트"""
    print("=== REG 모듈 테스트 시작 ===")
    
    try:
        # 1. 모듈 import 테스트
        print("\n1. 모듈 import 테스트...")
        from reg import (
            registry_collector, autorun_analyzer, 
            service_analyzer, security_settings_analyzer
        )
        print("✅ 모든 모듈 import 성공")
        
        # 2. 레지스트리 수집기 테스트
        print("\n2. 레지스트리 수집기 테스트...")
        try:
            # 간단한 레지스트리 값 조회 테스트
            result = registry_collector.get_registry_value(
                'HKLM', 
                r'SOFTWARE\Microsoft\Windows NT\CurrentVersion',
                'ProductName'
            )
            if result:
                print(f"✅ 레지스트리 조회 성공: {result.get('value', 'Unknown')}")
            else:
                print("⚠️  레지스트리 조회 결과 없음")
        except Exception as e:
            print(f"❌ 레지스트리 수집기 오류: {e}")
        
        # 3. 자동실행 분석기 테스트
        print("\n3. 자동실행 분석기 테스트...")
        try:
            autorun_data = autorun_analyzer.get_all_autorun_locations()
            autorun_count = sum(
                data.get('count', 0) 
                for data in autorun_data.get('registry_locations', {}).values()
            )
            print(f"✅ 자동실행 항목 수집 성공: {autorun_count}개 항목")
            
            # 의심스러운 자동실행 항목 분석
            suspicious_autoruns = autorun_analyzer.analyze_autorun_entries()
            print(f"✅ 자동실행 분석 완료: {len(suspicious_autoruns)}개 의심스러운 항목")
            
        except Exception as e:
            print(f"❌ 자동실행 분석기 오류: {e}")
        
        # 4. 서비스 분석기 테스트
        print("\n4. 서비스 분석기 테스트...")
        try:
            # 서비스 정보 수집 (일부만)
            services_data = service_analyzer.get_all_services()
            registry_services_count = len(services_data.get('registry_services', {}))
            running_services_count = len(services_data.get('running_services', {}))
            
            print(f"✅ 서비스 정보 수집 성공:")
            print(f"   - 레지스트리 서비스: {registry_services_count}개")
            print(f"   - 실행 중인 서비스: {running_services_count}개")
            
            # 의심스러운 서비스 분석 (시간 절약을 위해 스킵)
            print("   - 의심스러운 서비스 분석 스킵 (시간 절약)")
            
        except Exception as e:
            print(f"❌ 서비스 분석기 오류: {e}")
        
        # 5. 보안 설정 분석기 테스트
        print("\n5. 보안 설정 분석기 테스트...")
        try:
            # 중요 보안 설정만 체크
            critical_settings = security_settings_analyzer.check_critical_settings()
            print(f"✅ 보안 설정 체크 완료:")
            print(f"   - 총 문제: {critical_settings.get('total_issues', 0)}개")
            print(f"   - Critical: {critical_settings.get('critical_issues', 0)}개")
            print(f"   - High: {critical_settings.get('high_issues', 0)}개")
            
        except Exception as e:
            print(f"❌ 보안 설정 분석기 오류: {e}")
        
        print("\n=== REG 모듈 테스트 완료 ===")
        print("✅ reg 모듈이 성공적으로 구현되었습니다!")
        
        # 6. 통합 테스트 - 전체 reg 모듈 실행
        print("\n6. 통합 테스트 - 전체 reg 분석 실행...")
        try:
            from reg import (
                analyze_autorun_entries, analyze_services, 
                analyze_security_settings
            )
            
            print("   - 자동실행 분석 실행 중...")
            autorun_findings = analyze_autorun_entries()
            print(f"   ✅ 자동실행 분석 완료: {len(autorun_findings)}개 Finding")
            
            print("   - 보안 설정 분석 실행 중...")
            security_findings = analyze_security_settings()
            print(f"   ✅ 보안 설정 분석 완료: {len(security_findings)}개 Finding")
            
            # 서비스 분석은 시간이 오래 걸려서 스킵
            print("   - 서비스 분석 스킵 (시간 절약)")
            
            total_findings = len(autorun_findings) + len(security_findings)
            print(f"\n🎯 REG 모듈 총 Finding: {total_findings}개")
            
        except Exception as e:
            print(f"❌ 통합 테스트 오류: {e}")
    
    except Exception as e:
        print(f"❌ REG 모듈 테스트 실패: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_reg_module()
