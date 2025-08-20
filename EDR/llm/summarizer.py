"""
AI Security Summarizer - 보안 이슈 요약 생성기
경영진용 요약, 기술적 분석, AI 인사이트 제공
"""
from typing import Dict, List
from .base import AIBaseModule

class SecuritySummarizer(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "summarizer")
    
    def generate_executive_summary(self, findings_data: Dict, ai_results: Dict) -> str:
        """경영진용 한 줄 요약"""
        alerts = findings_data.get('alerts', [])
        total_issues = len(alerts)
        high_severity = len([a for a in alerts if a.get('severity') == 'high'])
        ai_solutions = len(ai_results.get('ai_remediation', []))
        
        prompt = f"""
다음 보안 스캔 결과를 경영진이 이해하기 쉽게 한국어로 한 문장으로 요약해주세요:

- 총 발견된 보안 이슈: {total_issues}개
- 고위험(High) 이슈: {high_severity}개  
- AI가 제공한 해결방법: {ai_solutions}개

비즈니스 관점에서 핵심만 간결하게 요약해주세요.
"""
        
        # 공통 API 호출 사용
        response = self._safe_api_call(prompt, "summary")
        
        if response:
            return response.strip()
        else:
            return f"총 {total_issues}개 보안 이슈 발견 (고위험 {high_severity}개), AI 해결방법 {ai_solutions}개 제공"
    
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
            "ai_statistics": ai_results.get('statistics', {}),
            "hostname": findings_data.get('hostname', 'Unknown')
        }
    
    def generate_ai_insight(self, findings_data: Dict, ai_results: Dict) -> str:
        """AI 기반 인사이트 생성"""
        alerts = findings_data.get('alerts', [])
        
        if not alerts:
            return "보안 스캔 결과 문제가 발견되지 않았습니다. 시스템이 양호한 상태입니다."
        
        # 상위 3개 이슈 추출
        top_issues = [a.get('title', '') for a in alerts[:3]]
        severity_info = self.generate_detailed_summary(findings_data, ai_results)["severity_breakdown"]
        
        prompt = f"""
다음 보안 이슈들을 분석해서 핵심 인사이트를 2-3문장으로 제공해주세요:

주요 발견사항:
{', '.join(top_issues)}

심각도 분포:
- 고위험: {severity_info['high']}개
- 중위험: {severity_info['medium']}개  
- 저위험: {severity_info['low']}개

보안 전문가 관점에서 이 시스템의 주요 위험요소와 우선 조치사항을 한국어로 설명해주세요.
"""
        
        # 공통 API 호출 사용
        response = self._safe_api_call(prompt, "summary")
        
        if response:
            return response.strip()
        else:
            return f"주요 보안 위험: {top_issues[0] if top_issues else '없음'}. 총 {len(alerts)}개 이슈 중 고위험 {severity_info['high']}개에 우선 대응 필요."
    
    def generate_technical_report(self, findings_data: Dict, ai_results: Dict) -> Dict:
        """기술진용 상세 리포트"""
        alerts = findings_data.get('alerts', [])
        remediation_scripts = ai_results.get('ai_remediation', [])
        
        # 카테고리별 분석
        categories = {}
        for alert in alerts:
            category = alert.get('category', 'unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(alert)
        
        # AI 해결책 통계
        confidences = [self._extract_confidence(s) for s in remediation_scripts]
        script_stats = {
            'total_scripts': len(remediation_scripts),
            'high_confidence': len([c for c in confidences if c >= 0.8]),
            'avg_confidence': sum(confidences) / len(confidences) if confidences else 0
        }
        
        return {
            "summary": self.generate_detailed_summary(findings_data, ai_results),
            "category_breakdown": {cat: len(issues) for cat, issues in categories.items()},
            "remediation_statistics": script_stats,
            "ai_insight": self.generate_ai_insight(findings_data, ai_results),
            "recommendations": self._generate_recommendations(categories)
        }
    
    def _extract_confidence(self, script) -> float:
        """스크립트에서 신뢰도 값을 안전하게 추출"""
        if isinstance(script, dict):
            confidence = script.get('confidence', 0)
        else:
            confidence = getattr(script, 'confidence', 0)

        if isinstance(confidence, dict):
            confidence = confidence.get('value', 0)

        try:
            return float(confidence)
        except (TypeError, ValueError):
            return 0.0
        
    def _generate_recommendations(self, categories: Dict) -> List[str]:
        """카테고리별 권장사항 생성"""
        recommendations = []
        
        if 'antivirus' in categories:
            recommendations.append("Windows Defender 설정을 점검하고 실시간 보호를 활성화하세요.")
        
        if 'persistence' in categories:
            recommendations.append("자동실행 레지스트리 키를 정기적으로 점검하세요.")
        
        if 'suspicious_activity' in categories:
            recommendations.append("의심스러운 프로세스 활동을 모니터링하고 PowerShell 실행 로그를 검토하세요.")
        
        if 'network' in categories:
            recommendations.append("네트워크 보안 설정을 강화하고 불필요한 원격 연결을 차단하세요.")
        
        if not recommendations:
            recommendations.append("현재 발견된 이슈 유형에 대한 구체적인 권장사항을 확인하려면 개별 이슈를 검토하세요.")
        
        return recommendations
