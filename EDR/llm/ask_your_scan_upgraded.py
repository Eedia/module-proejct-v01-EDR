"""
Ask Your Scan - 자연어 질문 처리기 (업그레이드됨)
EDR 스캔 결과에 대한 자연어 질의응답 시스템
"""

import json
import logging
from typing import Dict, List, Any
from .base import LLMBaseModule
from utils.data_structures import Finding

class AskYourScanUpgraded(LLMBaseModule):
    """자연어 질의응답 처리기"""
    
    def __init__(self):
        super().__init__("ask_your_scan")
    
    def process_query(self, query: str, findings: List[Finding], scan_metadata: Dict = None) -> Dict[str, Any]:
        """자연어 질문을 처리하여 EDR 스캔 결과에서 답변 생성"""
        
        try:
            # 스캔 결과 요약 생성
            summary = self._create_findings_summary(findings)
            metadata = scan_metadata or {}
            
            # 프롬프트 생성
            prompt = self._build_query_prompt(query, summary, metadata)
            
            # AI API 호출
            response = self._safe_api_call(prompt, "general")
            
            if response:
                return {
                    "answer": response,
                    "confidence": 0.9,
                    "source": "ai_analysis",
                    "query": query,
                    "context_used": summary
                }
            else:
                # AI 실패 시 폴백 응답
                return self._get_fallback_response(query, findings, summary)
                
        except Exception as e:
            self.logger.error(f"질의 처리 실패: {e}")
            return {
                "answer": f"질문 처리 중 오류가 발생했습니다: {str(e)}",
                "confidence": 0.0,
                "source": "error",
                "query": query
            }
    
    def _create_findings_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Finding 리스트를 요약 정보로 변환"""
        
        if not findings:
            return {
                "total_findings": 0,
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "category_breakdown": {},
                "top_issues": []
            }
        
        # 심각도별 통계
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = str(finding.severity).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # 카테고리별 통계  
        category_counts = {}
        for finding in findings:
            category = str(finding.category)
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # 상위 이슈들
        top_issues = [
            {
                "title": finding.title,
                "severity": str(finding.severity),
                "category": str(finding.category),
                "confidence": finding.confidence,
                "rule_id": finding.rule_id
            }
            for finding in sorted(findings, key=lambda x: x.confidence, reverse=True)[:5]
        ]
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "top_issues": top_issues
        }
    
    def _build_query_prompt(self, query: str, summary: Dict, metadata: Dict) -> str:
        """질의응답용 프롬프트 생성"""
        
        hostname = metadata.get('hostname', 'Unknown')
        scan_time = metadata.get('timestamp', 'Unknown')
        
        return f"""
당신은 Windows EDR 시스템의 전문 분석가입니다.
사용자의 질문에 대해 스캔 결과를 바탕으로 정확하고 전문적인 답변을 제공해주세요.

=== EDR 스캔 결과 요약 ===
호스트명: {hostname}
스캔 시간: {scan_time}
총 발견사항: {summary['total_findings']}개

심각도별 분포:
- Critical: {summary['severity_breakdown']['critical']}개
- High: {summary['severity_breakdown']['high']}개  
- Medium: {summary['severity_breakdown']['medium']}개
- Low: {summary['severity_breakdown']['low']}개
- Info: {summary['severity_breakdown']['info']}개

주요 발견사항:
{json.dumps(summary['top_issues'][:3], ensure_ascii=False, indent=2)}

=== 사용자 질문 ===
"{query}"

=== 답변 지침 ===
1. 스캔 결과 데이터를 정확히 반영하여 답변하세요
2. 구체적인 수치와 증거를 포함하세요
3. 보안 전문가 관점에서 명확하고 이해하기 쉽게 설명하세요
4. 추가 조치가 필요하다면 구체적인 권장사항을 제시하세요
5. 한국어로 답변하세요

위 스캔 결과를 바탕으로 사용자 질문에 정확히 답변해주세요.
"""
    
    def _get_fallback_response(self, query: str, findings: List[Finding], summary: Dict) -> Dict[str, Any]:
        """AI 실패 시 규칙 기반 폴백 응답"""
        
        query_lower = query.lower()
        total_findings = len(findings)
        high_severity = summary['severity_breakdown']['high'] + summary['severity_breakdown']['critical']
        
        # 개수 관련 질문
        if any(keyword in query_lower for keyword in ['몇 개', '개수', '얼마나', 'how many']):
            answer = f"총 {total_findings}개의 보안 이슈가 발견되었습니다."
            if high_severity > 0:
                answer += f" 이 중 {high_severity}개는 높은 심각도(High/Critical)입니다."
            
            return {
                "answer": answer,
                "confidence": 0.8,
                "source": "rule_based",
                "query": query
            }
        
        # 위험도 관련 질문
        elif any(keyword in query_lower for keyword in ['위험', '심각', '위협', 'risk', 'critical']):
            if high_severity > 0:
                top_critical = [f for f in findings if str(f.severity).lower() in ['high', 'critical']]
                answer = f"{high_severity}개의 높은 위험도 이슈가 발견되었습니다."
                if top_critical:
                    answer += f" 가장 심각한 문제는 '{top_critical[0].title}' 입니다."
            else:
                answer = "높은 위험도의 보안 이슈는 발견되지 않았습니다."
            
            return {
                "answer": answer,
                "confidence": 0.7,
                "source": "rule_based", 
                "query": query
            }
        
        # 기본 응답
        else:
            return {
                "answer": f"스캔 결과 총 {total_findings}개의 이슈가 발견되었습니다. 더 구체적인 질문을 해주시면 자세한 분석을 제공해드릴 수 있습니다.",
                "confidence": 0.5,
                "source": "fallback",
                "query": query
            }
    
    def get_suggested_queries(self, findings: List[Finding]) -> List[str]:
        """Finding 기반 추천 질문 생성"""
        suggestions = [
            "전체적인 보안 상태는 어떤가요?",
            "가장 위험한 탐지 항목은 무엇인가요?",
            "즉시 조치가 필요한 항목이 있나요?"
        ]
        
        # 카테고리별 질문 추가
        categories = set(str(f.category) for f in findings)
        for category in categories:
            if 'persistence' in category.lower():
                suggestions.append("지속성 공격 흔적이 있나요?")
            elif 'execution' in category.lower():
                suggestions.append("의심스러운 실행 활동이 있나요?")
            elif 'remote_access' in category.lower():
                suggestions.append("원격 접근 시도가 있었나요?")
        
        return suggestions[:6]  # 최대 6개 반환
