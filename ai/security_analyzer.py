"""
AI Security Analyzer - 이슈 탐지부터 해결책까지 통합
"""
import os
import json
from typing import Dict, List
import logging

from ai.issue_detector import AIIssueDetector
from ai.remediation import RemediationEngine
from ai.summarizer import SecuritySummarizer
from ai.query_handler import QueryHandler
from ai.api_client import GeminiClient  # API 클라이언트 추가

class AISecurityAnalyzer:
    def __init__(self, config: Dict):
        self.issue_detector = AIIssueDetector(config)
        self.remediation_engine = RemediationEngine(config)
        self.summarizer = SecuritySummarizer(config)
        self.query_handler = QueryHandler(config)
        
        # API 클라이언트 초기화
        self.api_client = GeminiClient()
        
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _safe_api_call(self, prompt: str, call_type: str = "general") -> str:
        """안전한 API 호출 (누락된 메서드 추가)"""
        try:
            if call_type == "general":
                response = self.api_client.generate_response(prompt)
            else:
                response = self.api_client.generate_security_analysis(prompt)
            
            return response
        except Exception as e:
            self.logger.error(f"API 호출 실패 ({call_type}): {e}")
            return None
    
    def analyze_raw_data(self, raw_data: Dict) -> Dict:
        """원시 데이터를 받아서 완전한 보안 분석 수행"""
        
        # 1단계: AI가 이슈 탐지 (SecurityIssue 객체 리스트 반환)
        detected_issues = self.issue_detector.analyze_findings(raw_data)
        
        # 2단계: 각 이슈에 대한 해결책 생성 (RemediationScript 객체 리스트 반환)
        remediation_scripts = self.remediation_engine.generate_remediation_scripts(detected_issues)
        
        # 3단계: 객체들을 딕셔너리로 변환
        detected_issues_dicts = [issue.to_dict() for issue in detected_issues]
        remediation_scripts_dicts = [script.to_dict() for script in remediation_scripts]
        
        # 4단계: 결과 통합
        analysis_result = {
            "timestamp": raw_data.get('collection_timestamp'),
            "detected_issues": detected_issues_dicts,
            "ai_remediation": remediation_scripts_dicts,
            "total_issues": len(detected_issues),
            "statistics": self._calculate_statistics(detected_issues, remediation_scripts)
        }
        
        # 5단계: AI 요약 생성
        summary_findings = {"alerts": detected_issues_dicts}
        analysis_result["executive_summary"] = self.summarizer.generate_executive_summary(
            summary_findings, analysis_result
        )
        
        # 결과 저장
        self._save_complete_results(analysis_result)
        
        return analysis_result
    
    def process_user_query(self, query: str, context_data: Dict) -> Dict:
        """사용자 질문 처리 (QueryHandler 활용)"""
        
        # 컨텍스트 데이터를 QueryHandler가 이해할 수 있는 형식으로 변환
        detected_issues = context_data.get('detected_issues', [])
        
        # detected_issues가 비어있으면 다른 키에서 찾기
        if not detected_issues:
            for key in context_data.keys():
                value = context_data[key]
                if isinstance(value, list) and value:
                    if isinstance(value[0], dict) and 'title' in value:
                        detected_issues = value
                        break
        
        # QueryHandler가 기대하는 형식으로 데이터 변환
        findings_data = {
            'alerts': detected_issues,  # QueryHandler는 'alerts' 키를 사용
            'collection_period': '스캔 완료',
            'hostname': context_data.get('hostname', 'Unknown'),
            'total_issues': len(detected_issues),
            'ai_remediation': context_data.get('ai_remediation', [])
        }
        
        try:
            # QueryHandler 사용
            result = self.query_handler.process_natural_language_query(query, findings_data)
            
            return {
                'answer': result.get('answer', '답변을 생성할 수 없습니다.'),
                'confidence': result.get('confidence', 0.5),
                'source': result.get('source', 'query_handler')
            }
            
        except Exception as e:
            self.logger.error(f"QueryHandler 처리 실패: {e}")
            return {
                'answer': f"질문 처리 중 오류가 발생했습니다: {str(e)}",
                'confidence': 0.0,
                'source': 'error'
            }
    
    def _calculate_statistics(self, issues: List, scripts: List) -> Dict:
        """AI 통계 계산"""
        if not scripts:
            return {"total_scripts": 0, "avg_confidence": 0}
        
        total = len(scripts)
        avg_conf = sum(s.confidence for s in scripts) / total
        
        return {
            "total_scripts": total,
            "avg_confidence": avg_conf,
            "high_confidence": len([s for s in scripts if s.confidence >= 0.8])
        }
    
    def _save_complete_results(self, analysis_result: Dict) -> None:
        """결과 저장"""
        os.makedirs('output', exist_ok=True)
        
        # 1. 전체 분석 결과 저장
        with open('output/ai_analysis.json', 'w', encoding='utf-8') as f:
            json.dump(analysis_result, f, ensure_ascii=False, indent=2)
        
        # 2. AI 해결책만 별도 저장
        remediation_data = analysis_result.get('ai_remediation', [])
        with open('output/ai_remediation.json', 'w', encoding='utf-8') as f:
            json.dump(remediation_data, f, ensure_ascii=False, indent=2)
    
    def _summarize_raw_data(self, raw_data: Dict) -> Dict:
        """원시 데이터 요약"""
        return {
            "event_logs_count": len(raw_data.get('event_logs', [])),
            "registry_keys_count": len(raw_data.get('registry_data', {})),
            "collection_time": raw_data.get('collection_timestamp'),
            "system": raw_data.get('system_info', {}).get('os_version', 'Unknown')
        }
