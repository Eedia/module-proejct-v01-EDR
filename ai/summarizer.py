"""
AI Security Summarizer - 보안 이슈 요약 생성기
"""
from typing import Dict, List
from ai.base import AIBaseModule

class SecuritySummarizer(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "summarizer")
    
    def generate_executive_summary(self, findings_data: Dict, ai_results: Dict) -> str:
        """경영진용 한 줄 요약"""
        alerts = findings_data.get('alerts', [])
        total_issues = len(alerts)
        high_severity = len([a for a in alerts if a.get('severity') == 'high'])
        ai_solutions = len(ai_results.get('ai_remediation', []))
        
        prompt = f"총 {total_issues}개 보안 이슈 발견, 고위험 {high_severity}개, AI 해결방법 {ai_solutions}개 제공된 상황을 경영진이 이해하기 쉽게 한 문장으로 요약해주세요."
        
        # 🔧 공통 API 호출 사용
        response = self._safe_api_call(prompt, "summary")
        
        if response:
            return response.strip()
        else:
            return f"총 {total_issues}개 보안 이슈 발견, 고위험 {high_severity}개, AI 해결방법 {ai_solutions}개 제공"
    
    def generate_detailed_summary(self, findings_data: Dict, ai_results: Dict) -> Dict:
        """상세 요약 정보"""
        alerts = findings_data.get('alerts', [])
        
        severity_count = {
            'high': len([a for a in alerts if a.get('severity') == 'high']),
            'medium': len([a for a in alerts if a.get('severity') == 'medium']),
            'low': len([a for a in alerts if a.get('severity') == 'low'])
        }
        
        return {
            "total_issues": len(alerts),
            "severity_breakdown": severity_count,
            "scan_timestamp": findings_data.get('timestamp'),
            "ai_statistics": ai_results.get('statistics', {})
        }
    
    def generate_ai_insight(self, findings_data: Dict, ai_results: Dict) -> str:
        """AI 기반 인사이트 생성"""
        alerts = findings_data.get('alerts', [])
        prompt = f"다음 보안 이슈들을 분석해서 핵심 인사이트를 2-3줄로 제공해주세요: {[a.get('title', '') for a in alerts[:3]]}"
        
        # 🔧 공통 API 호출 사용
        response = self._safe_api_call(prompt, "summary")
        
        if response:
            return response.strip()
        else:
            return "AI 인사이트 생성 중 오류가 발생했습니다."
