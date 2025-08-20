"""
AI Security Analyzer - 통합 보안 분석 엔진
이슈 탐지부터 해결책까지 통합 처리
"""
import os
import json
from typing import Dict, List
import logging
from datetime import datetime

from .issue_detector import AIIssueDetector
from .remediation import RemediationEngine
from .summarizer import SecuritySummarizer
from .query_handler import QueryHandler
from .validators import ScriptValidator
from .api_client import GeminiClient
from .models import AnalysisResult

class AISecurityAnalyzer:
    """통합 AI 보안 분석기"""
    
    def __init__(self, config: Dict = None):
        # 각 AI 모듈 초기화
        self.issue_detector = AIIssueDetector(config or {})
        self.remediation_engine = RemediationEngine(config or {})
        self.summarizer = SecuritySummarizer(config or {})
        self.query_handler = QueryHandler(config or {})
        self.script_validator = ScriptValidator()
        
        # API 클라이언트 초기화
        self.api_client = GeminiClient()
        
        # 로깅 설정
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def analyze_raw_data(self, raw_data: Dict) -> AnalysisResult:
        """원시 EDR 데이터를 받아서 완전한 보안 분석 수행"""
        
        self.logger.info("🔍 AI 통합 보안 분석 시작")
        
        # 1단계: AI 이슈 탐지
        self.logger.info("1️⃣ AI 이슈 탐지 실행...")
        detected_issues = self.issue_detector.analyze_findings(raw_data)
        
        # 2단계: AI 해결책 생성
        self.logger.info("2️⃣ AI 해결책 생성 실행...")
        remediation_scripts = self.remediation_engine.generate_remediation_scripts(detected_issues)
        
        # 3단계: 스크립트 검증
        self.logger.info("3️⃣ 스크립트 안전성 검증...")
        validated_scripts = self._validate_remediation_scripts(remediation_scripts)
        
        # 4단계: 분석 결과 구조화
        analysis_result = AnalysisResult(
            timestamp=datetime.now().isoformat(),
            hostname=raw_data.get('hostname', 'Unknown'),
            detected_issues=detected_issues,
            ai_remediation=validated_scripts,
            total_issues=len(detected_issues),
            statistics=self._calculate_statistics(detected_issues, validated_scripts)
        )
        
        # 5단계: AI 요약 생성
        self.logger.info("4️⃣ AI 요약 생성 실행...")
        summary_findings = {"alerts": [issue.to_dict() for issue in detected_issues]}
        analysis_result.executive_summary = self.summarizer.generate_executive_summary(
            summary_findings, analysis_result.to_dict()
        )
        
        # 6단계: 결과 저장
        self._save_complete_results(analysis_result)
        
        self.logger.info(f"✅ AI 분석 완료: {len(detected_issues)}개 이슈, {len(validated_scripts)}개 해결책")
        return analysis_result
    
    def process_user_query(self, query: str, context_data: Dict) -> Dict:
        """사용자 자연어 질문 처리"""
        
        self.logger.info(f"💬 사용자 질문 처리: {query}")
        
        # 컨텍스트 데이터 변환
        if isinstance(context_data, AnalysisResult):
            detected_issues = [issue.to_dict() for issue in context_data.detected_issues]
            hostname = context_data.hostname
        else:
            detected_issues = context_data.get('detected_issues', [])
            hostname = context_data.get('hostname', 'Unknown')
        
        # QueryHandler가 기대하는 형식으로 변환
        findings_data = {
            'alerts': detected_issues,
            'collection_period': '스캔 완료',
            'hostname': hostname,
            'total_issues': len(detected_issues),
            'ai_remediation': context_data.get('ai_remediation', [])
        }
        
        try:
            result = self.query_handler.process_natural_language_query(query, findings_data)
            return result.to_dict()
            
        except Exception as e:
            self.logger.error(f"질문 처리 실패: {e}")
            return {
                'answer': f"질문 처리 중 오류가 발생했습니다: {str(e)}",
                'confidence': 0.0,
                'source': 'error',
                'query': query,
                'error': True
            }
    
    def get_detailed_analysis(self, analysis_result: AnalysisResult) -> Dict:
        """상세 분석 정보 제공"""
        
        findings_data = {"alerts": [issue.to_dict() for issue in analysis_result.detected_issues]}
        ai_results = analysis_result.to_dict()
        
        return self.summarizer.generate_technical_report(findings_data, ai_results)
    
    def _validate_remediation_scripts(self, scripts: List) -> List:
        """생성된 해결책 스크립트들의 안전성 검증"""
        validated_scripts = []
        
        for script in scripts:
            # 스크립트 검증
            validation_result = self.script_validator.validate_script(script.fix_command)
            
            # 검증 결과를 스크립트에 추가
            script_dict = script.to_dict()
            script_dict['validation'] = validation_result
            script_dict['recommendation'] = self.script_validator.get_recommendation(validation_result)
            
            # 위험한 스크립트는 경고 표시
            if validation_result['risk_level'] == 'dangerous':
                script_dict['warnings'].append("⚠️ 위험한 명령어가 포함되어 있습니다.")
                self.logger.warning(f"위험한 스크립트 탐지: {script.issue_id}")
            
            validated_scripts.append(script_dict)
        
        return validated_scripts
    
    def _calculate_statistics(self, issues: List, scripts: List) -> Dict:
        """AI 통계 계산"""
        if not scripts:
            return {"total_scripts": 0, "avg_confidence": 0, "validation_stats": {}}
        
        total = len(scripts)
        avg_conf = sum(s.confidence if hasattr(s, 'confidence') else s.get('confidence', 0) for s in scripts) / total
        
        # 검증 통계
        safe_scripts = sum(1 for s in scripts if s.get('validation', {}).get('risk_level') == 'safe')
        caution_scripts = sum(1 for s in scripts if s.get('validation', {}).get('risk_level') == 'caution')
        dangerous_scripts = sum(1 for s in scripts if s.get('validation', {}).get('risk_level') == 'dangerous')
        
        return {
            "total_scripts": total,
            "avg_confidence": avg_conf,
            "high_confidence": len([s for s in scripts if (s.confidence if hasattr(s, 'confidence') else s.get('confidence', 0)) >= 0.8]),
            "validation_stats": {
                "safe": safe_scripts,
                "caution": caution_scripts,
                "dangerous": dangerous_scripts
            }
        }
    
    def _save_complete_results(self, analysis_result: AnalysisResult) -> None:
        """결과 저장"""
        os.makedirs('output', exist_ok=True)
        
        # 1. 전체 분석 결과 저장
        with open('output/ai_analysis_complete.json', 'w', encoding='utf-8') as f:
            json.dump(analysis_result.to_dict(), f, ensure_ascii=False, indent=2)
        
        # 2. AI 해결책만 별도 저장
        remediation_data = [script for script in analysis_result.ai_remediation]
        with open('output/ai_remediation_validated.json', 'w', encoding='utf-8') as f:
            json.dump(remediation_data, f, ensure_ascii=False, indent=2)
        
        # 3. 요약 보고서 저장
        summary_report = {
            "timestamp": analysis_result.timestamp,
            "hostname": analysis_result.hostname,
            "executive_summary": analysis_result.executive_summary,
            "statistics": analysis_result.statistics,
            "total_issues": analysis_result.total_issues
        }
        
        with open('output/executive_summary.json', 'w', encoding='utf-8') as f:
            json.dump(summary_report, f, ensure_ascii=False, indent=2)
        
        self.logger.info("📁 분석 결과가 output/ 폴더에 저장되었습니다.")
