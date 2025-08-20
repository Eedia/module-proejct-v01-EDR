"""
통합 EDR 분석 엔진
evtx + reg + rules + llm을 완전히 통합한 메인 분석기
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# 기존 EDR 모듈들
from evtx.collector import collect_all_target_events
from evtx.analyzer import analyze_events
from reg.autorun_analyzer import analyze_autorun_entries
from reg.service_analyzer import analyze_services
from reg.security_settings import analyze_security_settings
from rules.rule_engine import RuleEngine
from utils.scoring_engine import calculate_total_score, determine_risk_level
from utils.data_structures import generate_scan_id, get_current_timestamp
from utils.file_handler import save_findings_json, generate_html_report

# 새로운 통합 LLM
from llm.security_analyzer import AISecurityAnalyzer
from llm.utils import normalize_findings_data, convert_to_alerts_format

logger = logging.getLogger(__name__)

class IntegratedEDRAnalyzer:
    """통합 EDR 분석 엔진"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.ai_analyzer = AISecurityAnalyzer(config)
        self.rule_engine = RuleEngine()
        
    def run_complete_analysis(self) -> Dict:
        """완전한 EDR 분석 실행 (기존 + AI)"""
        
        analysis_start = datetime.now()
        scan_id = generate_scan_id()
        
        logger.info(f"🚀 통합 EDR 분석 시작 (ID: {scan_id})")
        
        # 1단계: 기존 EDR 데이터 수집
        logger.info("1. 이벤트 로그 및 레지스트리 데이터 수집...")
        raw_edr_data = self._collect_edr_data()
        
        # 2단계: 기존 룰 기반 분석
        logger.info("2. 룰 기반 탐지 및 점수 계산...")
        rule_based_results = self._run_rule_based_analysis(raw_edr_data)
        
        # 3단계: AI 분석을 위한 데이터 변환
        logger.info("3. AI 분석용 데이터 변환...")
        ai_compatible_data = self._prepare_ai_data(raw_edr_data, rule_based_results)
        
        # 4단계: AI 통합 분석
        logger.info("4. AI 통합 분석 실행...")
        ai_results = self._run_ai_analysis(ai_compatible_data)
        
        # 5단계: 결과 통합
        logger.info("5. 분석 결과 통합...")
        integrated_results = self._merge_results(rule_based_results, ai_results, analysis_start)
        
        # 6단계: 결과 저장
        logger.info("6. 결과 저장...")
        self._save_integrated_results(integrated_results, scan_id)
        
        logger.info("통합 EDR 분석 완료")
        return integrated_results
    
    def _collect_edr_data(self) -> Dict:
        """기존 EDR 데이터 수집"""
        return {
            # 이벤트 로그 수집
            'events': collect_all_target_events(),
            
            # 레지스트리 분석
            'autorun_entries': analyze_autorun_entries(),
            'services': analyze_services(), 
            'security_settings': analyze_security_settings(),
            
            # 메타데이터
            'scan_metadata': {
                'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
                'timestamp': get_current_timestamp(),
                'collector_version': '2.0.0'
            }
        }
    
    def _run_rule_based_analysis(self, raw_data: Dict) -> Dict:
        """기존 룰 기반 분석"""
        
        # 이벤트 분석
        event_findings = analyze_events(raw_data['events'])
        
        # 모든 발견사항 통합
        all_findings = []
        all_findings.extend(event_findings)
        all_findings.extend(raw_data['autorun_entries'])
        all_findings.extend(raw_data['services'])
        all_findings.extend(raw_data['security_settings'])
        
        # 점수 계산
        total_score_result = calculate_total_score(all_findings)
        actual_score = total_score_result.get('total_score', 0) if isinstance(total_score_result, dict) else total_score_result
        risk_level = determine_risk_level(actual_score)
        
        return {
            'findings': all_findings,
            'total_score': total_score_result,
            'risk_level': risk_level,
            'scan_summary': {
                'total_findings': len(all_findings),
                'findings_by_severity': self._count_by_severity(all_findings)
            },
            'scan_metadata': raw_data['scan_metadata']
        }
    
    def _prepare_ai_data(self, raw_data: Dict, rule_results: Dict) -> Dict:
        """AI 분석용 데이터 준비"""
        
        # 기존 룰 결과를 AI 호환 형식으로 변환
        structured_data = {
            'scan_metadata': rule_results['scan_metadata'],
            'scan_summary': rule_results['scan_summary'],
            'findings': rule_results['findings']
        }
        
        # AI 모듈이 이해할 수 있는 형식으로 정규화
        return normalize_findings_data(structured_data)
    
    def _run_ai_analysis(self, ai_data: Dict) -> Dict:
        """AI 통합 분석 실행"""
        try:
            ai_result = self.ai_analyzer.analyze_raw_data(ai_data)
            return ai_result.to_dict()
        except Exception as e:
            logger.error(f"AI 분석 실패: {e}")
            return {
                'detected_issues': [],
                'ai_remediation': [],
                'executive_summary': 'AI 분석을 수행할 수 없습니다.',
                'total_issues': 0,
                'statistics': {}
            }
    
    def _merge_results(self, rule_results: Dict, ai_results: Dict, start_time: datetime) -> Dict:
        """룰 기반 + AI 결과 통합"""
        
        analysis_duration = (datetime.now() - start_time).total_seconds()
        
        return {
            # 기존 룰 기반 결과
            'rule_based_analysis': {
                'findings': rule_results['findings'],
                'total_score': rule_results['total_score'],
                'risk_level': rule_results['risk_level'],
                'scan_summary': rule_results['scan_summary']
            },
            
            # AI 분석 결과
            'ai_analysis': {
                'detected_issues': ai_results['detected_issues'],
                'ai_remediation': ai_results['ai_remediation'],
                'executive_summary': ai_results['executive_summary'],
                'ai_statistics': ai_results['statistics']
            },
            
            # 통합 메타데이터
            'integration_metadata': {
                'scan_id': generate_scan_id(),
                'timestamp': get_current_timestamp(),
                'analysis_duration_seconds': analysis_duration,
                'total_rule_findings': len(rule_results['findings']),
                'total_ai_issues': ai_results['total_issues'],
                'hostname': rule_results['scan_metadata']['hostname']
            }
        }
    
    def _save_integrated_results(self, results: Dict, scan_id: str):
        """통합 결과 저장"""
        
        # 1. 기존 형식으로 저장 (호환성)
        save_findings_json(results['rule_based_analysis'], scan_id)
        
        # 2. 통합 결과 저장
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 통합 JSON 저장
        import json
        with open(output_dir / f'integrated_analysis_{timestamp}.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        # HTML 리포트 생성 (AI 결과 포함)
        self._generate_enhanced_html_report(results, output_dir / f'integrated_report_{timestamp}.html')
        
        logger.info(f"📁 통합 결과 저장 완료: output/integrated_*_{timestamp}.*")
    
    def _generate_enhanced_html_report(self, results: Dict, output_path: Path):
        """AI 결과가 포함된 강화된 HTML 리포트"""
        
        rule_analysis = results['rule_based_analysis']
        ai_analysis = results['ai_analysis']
        metadata = results['integration_metadata']
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>통합 EDR 분석 리포트</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .ai-section {{ background: #f8f9fa; }}
        .high {{ color: #e74c3c; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        .remediation {{ background: #e8f5e8; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .code {{ background: #f4f4f4; padding: 5px; font-family: monospace; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 통합 EDR 분석 리포트</h1>
        <p>스캔 ID: {metadata['scan_id']} | 호스트: {metadata['hostname']} | 분석 시간: {metadata['analysis_duration_seconds']:.1f}초</p>
    </div>
    
    <div class="section">
        <h2>📊 전체 요약</h2>
        <p><strong>룰 기반 탐지:</strong> {metadata['total_rule_findings']}개 발견사항</p>
        <p><strong>AI 탐지:</strong> {metadata['total_ai_issues']}개 보안 이슈</p>
        <p><strong>AI 요약:</strong> {ai_analysis['executive_summary']}</p>
    </div>
    
    <div class="section">
        <h2>🔍 룰 기반 분석 결과</h2>
        <p><strong>보안 점수:</strong> {rule_analysis['total_score']}/100 ({rule_analysis['risk_level']})</p>
        <h3>발견사항 목록:</h3>
        <ul>
"""
        
        # 룰 기반 발견사항 추가
        for finding in rule_analysis['findings'][:10]:  # 상위 10개만
            severity_class = finding.get('severity', 'medium').lower()
            html_content += f'<li class="{severity_class}">[{finding.get("severity", "UNKNOWN").upper()}] {finding.get("description", "설명 없음")}</li>\n'
        
        html_content += """
        </ul>
    </div>
    
    <div class="section ai-section">
        <h2>🤖 AI 분석 결과</h2>
        <h3>탐지된 보안 이슈:</h3>
        <ul>
"""
        
        # AI 탐지 이슈 추가
        for issue in ai_analysis['detected_issues']:
            severity_class = issue.get('severity', 'medium').lower()
            html_content += f'<li class="{severity_class}">[{issue.get("severity", "UNKNOWN").upper()}] {issue.get("title", "제목 없음")} (신뢰도: {issue.get("confidence", 0)*100:.0f}%)</li>\n'
        
        html_content += """
        </ul>
        
        <h3>🛠️ AI 해결책:</h3>
"""
        
        # AI 해결책 추가
        for script in ai_analysis['ai_remediation'][:5]:  # 상위 5개만
            html_content += f"""
        <div class="remediation">
            <h4>{script.get('description', '해결책')}</h4>
            <p><strong>수정 명령어:</strong></p>
            <div class="code">{script.get('fix_command', '명령어 없음')}</div>
            <p><strong>검증 명령어:</strong></p>
            <div class="code">{script.get('validation_command', '검증 없음')}</div>
            <p><strong>신뢰도:</strong> {script.get('confidence', 0)*100:.0f}%</p>
        </div>
"""
        
        html_content += f"""
    </div>
    
    <div class="section">
        <h2>📈 통계 정보</h2>
        <p>생성 시간: {metadata['timestamp']}</p>
        <p>AI 분석 통계: {ai_analysis.get('ai_statistics', {})}</p>
    </div>
    
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _count_by_severity(self, findings: List) -> Dict:
        """심각도별 개수 계산"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def ask_question(self, query: str, analysis_results: Dict) -> str:
        """분석 결과에 대한 자연어 질문"""
        try:
            response = self.ai_analyzer.process_user_query(query, analysis_results)
            return response.get('answer', '답변을 생성할 수 없습니다.')
        except Exception as e:
            logger.error(f"질문 처리 실패: {e}")
            return f"질문 처리 중 오류가 발생했습니다: {str(e)}"

# 편의 함수들
def run_integrated_scan() -> Dict:
    """통합 스캔 실행"""
    analyzer = IntegratedEDRAnalyzer()
    return analyzer.run_complete_analysis()

def ask_about_scan(question: str, scan_results: Dict) -> str:
    """스캔 결과에 대한 질문"""
    analyzer = IntegratedEDRAnalyzer()
    return analyzer.ask_question(question, scan_results)
