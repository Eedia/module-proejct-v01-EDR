"""
Ask your Scan - 자연어 질문 처리기
"""
import json
from typing import Dict, List
from ai.base import AIBaseModule

class QueryHandler(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "query_handler")
    
    def process_natural_language_query(self, query: str, findings_data: Dict) -> Dict:
        """자연어 질의를 분석해서 관련 보안 이벤트 찾기"""
        try:
            # 데이터 요약
            summary = self._create_findings_summary(findings_data)
            
            # AI 요청 생성
            prompt = f"""
사용자 질문: {query}

스캔 결과 요약:
{json.dumps(summary, ensure_ascii=False, indent=2)}

이 질문에 대해 스캔 결과를 바탕으로 정확하고 도움이 되는 답변을 해 주세요.
답변은 한국어로 작성해 주세요.
"""

            # 🔧 공통 API 호출 사용
            response = self._safe_api_call(prompt, "summary")
            
            if response:
                return {
                    "answer": response,
                    "confidence": 0.8,
                    "source": "openai",
                    "query": query
                }
            else:
                return self._get_fallback_response(query)
            
        except Exception as e:
            self.logger.error(f"질의 처리 실패: {e}")
            return self._get_fallback_response(query)
    
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
    
    def _get_fallback_response(self, query: str) -> Dict:
        """AI 처리 실패 시 기본 응답"""
        return {
            "answer": f"'{query}' 질문을 처리하는 중 오류가 발생했습니다.",
            "confidence": 0.0,
            "source": "fallback",
            "query": query,
            "error": True
        }
