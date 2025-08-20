"""
main.py
EDR Scanner 메인 진입점
"""

import sys
import os
import time
import logging
from datetime import datetime
from pathlib import Path

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from evtx.collector import collect_all_target_events
from evtx.analyzer import analyze_events
from utils.scoring_engine import (
    calculate_total_score, determine_risk_level, generate_score_summary,
)
from utils.data_structures import ( 
    generate_scan_id, get_current_timestamp
)
from utils.file_handler import (
    save_findings_json, generate_html_report
)



# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_system_info():
    """시스템 정보 수집"""
    import platform
    try:
        import psutil
        memory_gb = round(psutil.virtual_memory().total / (1024**3), 1)
    except ImportError:
        memory_gb = 0
    
    return {
        "operating_system": f"{platform.system()} {platform.release()}",
        "version": platform.version(),
        "architecture": platform.machine(),
        "total_memory_gb": memory_gb,
        "hostname": platform.node(),
        "antivirus": {
            "product": "Windows Defender",
            "enabled": True,
            "real_time_protection": True,
            "signature_version": "Unknown",
            "last_update": "Unknown"
        },
        "windows_update": {
            "auto_update_enabled": True,
            "last_update_installed": "Unknown",
            "pending_updates": 0
        },
        "security_settings": {
            "uac_enabled": True,
            "rdp_enabled": False,
            "firewall_enabled": True,
            "smb_signing": False
        }
    }

def run_full_scan(time_range_hours: int = 24) -> dict:
    """전체 EDR 스캔 실행"""
    logger.info("=== EDR Scanner 시작 ===")
    start_time = time.time()
    
    # 1. 스캔 메타데이터 생성
    scan_id = generate_scan_id()
    timestamp = get_current_timestamp()
    hostname = os.environ.get('COMPUTERNAME', 'Unknown')
    
    logger.info(f"스캔 ID: {scan_id}")
    logger.info(f"호스트명: {hostname}")
    logger.info(f"수집 범위: 최근 {time_range_hours}시간")
    
    try:
        # 2. 이벤트 로그 수집
        logger.info("이벤트 로그 수집 중...")
        events = collect_all_target_events(time_range_hours)
        logger.info(f"수집된 이벤트: {len(events)}개")
        
        if not events:
            logger.warning("수집된 이벤트가 없습니다.")
        
        # 3. 이벤트 분석
        logger.info("이벤트 분석 중...")
        findings = analyze_events(events)
        logger.info(f"생성된 탐지 항목: {len(findings)}개")
        
        # 4. 점수 계산
        logger.info("점수 계산 중...")
        score_summary = generate_score_summary(findings)
        total_score = score_summary['total_score']
        risk_level = score_summary['risk_level']
        
        logger.info(f"최종 점수: {total_score}점 ({risk_level})")
        
        # 5. 시스템 정보 수집
        logger.info("시스템 정보 수집 중...")
        system_info = get_system_info()
        
        # 6. 스캔 완료 시간 계산
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # 7. 최종 결과 구성
        scan_results = {
            "scan_metadata": {
                "scan_id": scan_id,
                "timestamp": timestamp,
                "hostname": hostname,
                "scan_duration_seconds": round(scan_duration, 2),
                "scanner_version": "1.0.0",
                "scan_scope": {
                    "event_logs": {
                        "enabled": True,
                        "time_range_hours": time_range_hours,
                        "channels": [
                            "Security", "System", 
                            "Microsoft-Windows-PowerShell/Operational",
                            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
                        ]
                    },
                    "registry": {
                        "enabled": False
                    },
                    "system_info": {
                        "enabled": True
                    }
                }
            },
            "scan_summary": {
                "total_score": total_score,
                "risk_level": risk_level,
                "total_findings": len(findings),
                "findings_by_severity": score_summary['findings_by_severity'],
                "findings_by_category": score_summary['findings_by_category']
            },
            "findings": findings,
            "system_info": system_info,
            "statistics": {
                "events_processed": {
                    "total": len(events),
                    "security": len([e for e in events if e.get('channel') == 'Security']),
                    "system": len([e for e in events if e.get('channel') == 'System']),
                    "powershell": len([e for e in events if 'PowerShell' in e.get('channel', '')]),
                    "rdp": len([e for e in events if 'TerminalServices' in e.get('channel', '')])
                },
                "processing_time": {
                    "total": round(scan_duration, 2),
                    "event_collection": round(scan_duration * 0.6, 2),
                    "analysis": round(scan_duration * 0.3, 2),
                    "reporting": round(scan_duration * 0.1, 2)
                }
            },
            "ai_recommendations": generate_ai_recommendations(findings, total_score),
            "schema_version": "1.0",
            "generated_by": "EDR-Scanner v1.0.0"
        }
        
        # 8. 결과 저장
        logger.info("결과 저장 중...")
        json_path = save_findings_json(scan_results, scan_id)
        html_path = generate_html_report(scan_results)
        
        logger.info(f"JSON 리포트: {json_path}")
        logger.info(f"HTML 리포트: {html_path}")
        
        logger.info("=== EDR Scanner 완료 ===")
        return scan_results
        
    except Exception as e:
        logger.error(f"스캔 중 오류 발생: {e}")
        raise

def generate_ai_recommendations(findings: list, total_score: int) -> dict:
    """AI 추천사항 생성 (간단한 룰 기반)"""
    recommendations = {
        "immediate_actions": [],
        "short_term_actions": [],
        "long_term_actions": []
    }
    
    # 즉시 조치 필요 항목
    critical_high_findings = [f for f in findings if f.get('severity') in ['critical', 'high']]
    
    for finding in critical_high_findings[:3]:
        rule_id = finding.get('rule_id', '')
        title = finding.get('title', '')
        
        if 'LOLBIN' in rule_id:
            recommendations["immediate_actions"].append(f"의심스러운 프로세스 종료 검토: {title}")
        elif 'SERVICE' in rule_id:
            recommendations["immediate_actions"].append(f"의심스러운 서비스 중지 검토: {title}")
        elif 'POWERSHELL' in rule_id:
            recommendations["immediate_actions"].append(f"PowerShell 활동 조사: {title}")
    
    # 단기 조치사항
    if any('RDP' in f.get('rule_id', '') for f in findings):
        recommendations["short_term_actions"].append("RDP 접근 정책 검토 및 강화")
    
    if any('LOGON' in f.get('rule_id', '') for f in findings):
        recommendations["short_term_actions"].append("계정 보안 정책 점검")
    
    if total_score < 70:
        recommendations["short_term_actions"].append("보안 솔루션 업그레이드 검토")
    
    # 장기 조치사항
    recommendations["long_term_actions"].extend([
        "정기적인 보안 교육 실시",
        "엔드포인트 보안 솔루션 도입 검토",
        "보안 모니터링 체계 구축"
    ])
    
    return recommendations

def main():
    """메인 함수"""
    try:
        # 관리자 권한 확인 (Windows)
        if os.name == 'nt':
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    logger.warning("관리자 권한이 필요합니다. 일부 기능이 제한될 수 있습니다.")
            except Exception:
                logger.warning("권한 확인 중 오류가 발생했습니다.")
        
        # 스캔 실행
        results = run_full_scan()
        
        # 요약 출력
        summary = results.get('scan_summary', {})
        print(f"\n=== 스캔 완료 ===")
        print(f"최종 점수: {summary.get('total_score', 0)}점")
        print(f"위험도: {summary.get('risk_level', '알 수 없음')}")
        print(f"탐지 항목: {summary.get('total_findings', 0)}개")
        print(f"리포트 위치: output/reports/")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("사용자에 의해 중단되었습니다.")
        return 1
    except Exception as e:
        logger.error(f"실행 중 오류: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
