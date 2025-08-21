"""
Ask your Scan - 자연어 질문 처리기
실제 스캔 결과를 기반으로 한 지능형 질의응답
"""
import json
from typing import Dict, List
from .base import AIBaseModule
from .models import QueryResponse

class QueryHandler(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "query_handler")
    
    def process_natural_language_query(self, query: str, findings_data: Dict) -> QueryResponse:
        """자연어 질의를 분석해서 관련 보안 이벤트 찾기"""
        try:
            # 데이터 요약
            summary = self._create_findings_summary(findings_data)
            
            # 🔧 강제 데이터 검증 및 수정
            alerts = findings_data.get('detected_issues', findings_data.get('alerts', []))  # 키 이름 변경 대응
            total_real_issues = len(alerts)
            hostname = findings_data.get('hostname', 'Unknown')

            # 조치 스크립트 매핑
            remediation_map = {}
            for script in findings_data.get('ai_remediation', []):
                issue_id = script.get('issue_id')
                if issue_id:
                    remediation_map[issue_id] = script          
            
            # 실제 이슈 목록 생성
            issue_details = ""
            if alerts:
                issue_details = "실제 탐지된 보안 이슈들:\n"
                for i, alert in enumerate(alerts, 1):
                    title = alert.get('title', 'Unknown issue')
                    severity = alert.get('severity', 'unknown').upper()
                    confidence = alert.get('confidence', 0) * 100
                    issue_id = alert.get('issue_id') or alert.get('finding_id')
                    issue_details += f"{i}. [{severity}] {title} (신뢰도: {confidence:.0f}%)\n"

                    script = remediation_map.get(issue_id)
                    if script:
                        fix_cmd = script.get('fix_command', 'N/A')
                        risk = script.get('validation', {}).get('risk_level', 'unknown')
                        warnings = ', '.join(script.get('warnings', []))
                        issue_details += f"   - 권장 조치: {fix_cmd}\n"
                        issue_details += f"   - 명령어 위험도: {risk}\n"
                        if warnings:
                            issue_details += f"   - 주의사항: {warnings}\n"
            
            # 🔧 강력한 프롬프트 (데이터 강제 주입)
            prompt = f"""
당신은 보안 분석 전문가입니다. 반드시 아래 실제 데이터를 정확히 참조하여 답변하세요.

=== 절대 무시하지 말 것: 실제 스캔 결과 ===
호스트명: {hostname}
실제 탐지된 보안 이슈: {total_real_issues}개

{issue_details}

=== 사용자 질문 ===
"{query}"

=== 중요한 지시사항 ===
1. 위에 명시된 {total_real_issues}개가 정확한 탐지 이슈 수입니다
2. 실제 이슈 제목을 구체적으로 언급하세요
3. 만약 데이터가 {total_real_issues}개를 보여 준다면 반드시 이 숫자를 사용하세요
4. 한국어로 전문적이고 정확하게 답변하세요
5. 사용자가 구체적으로 묻지 않았다면 모든 이슈를 나열하지 마세요

위의 실제 데이터에 기반하여 정확한 답변을 해 주세요.
"""
            
            # API 호출
            response = self._safe_api_call(prompt, "general")
            
            if response:
                return QueryResponse(
                    answer=response,
                    confidence=0.9,
                    source="gemini_api",
                    query=query
                )
            else:
                # 🔧 API 실패 시 컨텍스트 기반 직접 답변
                return self._generate_fallback_response(query, alerts, total_real_issues)
                
        except Exception as e:
            self.logger.error(f"질의 처리 실패: {e}")
            return QueryResponse(
                answer=f"'{query}' 질문을 처리하는 중 오류가 발생했습니다.",
                confidence=0.0,
                source="error",
                query=query,
                error=True
            )
    
    def _generate_fallback_response(self, query: str, alerts: List, total_real_issues: int) -> QueryResponse:
        """API 실패 시 직접 답변 생성"""
        
        if "몇 개" in query or "개수" in query:
            if total_real_issues > 0:
                severity_counts = self._count_by_severity(alerts)
                answer = f"총 {total_real_issues}개의 보안 문제가 탐지되었습니다. "
                answer += f"심각도별로는 HIGH: {severity_counts['high']}개, "
                answer += f"MEDIUM: {severity_counts['medium']}개, LOW: {severity_counts['low']}개입니다."
            else:
                answer = "탐지된 보안 문제가 없습니다."
                
            return QueryResponse(
                answer=answer,
                confidence=0.85,
                source="fallback_direct",
                query=query
            )
        
        elif "위험한" in query or "심각한" in query:
            high_issues = [a for a in alerts if a.get('severity') == 'high']
            if high_issues:
                answer = f"가장 위험한 문제는 '{high_issues[0]['title']}' 입니다. HIGH 심각도로 분류됩니다."
            else:
                medium_issues = [a for a in alerts if a.get('severity') == 'medium']
                if medium_issues:
                    answer = f"가장 주목할 문제는 '{medium_issues[0]['title']}' 입니다. MEDIUM 심각도입니다."
                else:
                    answer = "현재 HIGH나 MEDIUM 심각도의 문제는 발견되지 않았습니다."
                    
            return QueryResponse(
                answer=answer,
                confidence=0.85,
                source="fallback_direct",
                query=query
            )
        
        elif "요약" in query or "정리" in query:
            if total_real_issues > 0:
                top_issue = alerts[0]['title'] if alerts else "알 수 없는 문제"
                answer = f"스캔 결과 총 {total_real_issues}개의 보안 문제를 발견했습니다. "
                answer += f"가장 주요한 문제는 '{top_issue}'입니다."
            else:
                answer = "스캔 결과 보안 문제가 발견되지 않았습니다. 시스템이 안전한 상태입니다."
                
            return QueryResponse(
                answer=answer,
                confidence=0.8,
                source="fallback_direct",
                query=query
            )
        
        # 기본 응답
        return QueryResponse(
            answer=f"'{query}' 질문에 대한 구체적인 답변을 생성할 수 없습니다. 다른 방식으로 질문해보세요.",
            confidence=0.3,
            source="fallback_default",
            query=query
        )
    
    def _create_findings_summary(self, findings_data: Dict) -> Dict:
        """스캔 결과 요약"""
        alerts = findings_data.get('alerts', [])
        
        return {
            "total_alerts": len(alerts),
            "timeframe": findings_data.get('collection_period', '24시간'),
            "severity_breakdown": self._count_by_severity(alerts),
            "top_issues": [alert.get('description', '') for alert in alerts[:5]]
        }
    
    def _count_by_severity(self, alerts: List) -> Dict:
        """심각도별 통계"""
        severity_count = {'high': 0, 'medium': 0, 'low': 0}
        for alert in alerts:
            severity = alert.get('severity', 'medium')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        return severity_count
