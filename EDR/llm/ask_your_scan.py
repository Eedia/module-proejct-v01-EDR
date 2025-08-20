"""
Ask your Scan - 자연어 질의 처리기
스캔 결과에 대한 자연어 질문을 처리하고 답변 제공
"""

import json
import logging
from typing import Dict, List, Any, Optional

from .api_client import GeminiClient
from .prompt_templates import PromptTemplates

class AskYourScan:
    """자연어 질의 처리 클래스"""
    
    def __init__(self):
        self.client = GeminiClient()
        self.logger = logging.getLogger(__name__)
    
    def process_query(self, query: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """자연어 질의를 분석해서 스캔 결과 기반 답변 생성"""
        try:
            self.logger.info(f"자연어 질의 처리 시작: {query}")
            
            # 스캔 결과 요약 생성
            findings_summary = self._create_findings_summary(scan_results)
            
            # 프롬프트 생성
            prompt = PromptTemplates.get_query_prompt(query, findings_summary)
            
            # AI API 호출
            response = self.client.generate_summary(prompt)
            
            if response:
                return {
                    "query": query,
                    "answer": response,
                    "confidence": 0.8,
                    "source": "ai_analysis",
                    "related_findings": self._find_related_findings(query, scan_results.get('findings', [])),
                    "timestamp": scan_results.get('scan_metadata', {}).get('timestamp', '')
                }
            else:
                return self._get_fallback_response(query)
                
        except Exception as e:
            self.logger.error(f"질의 처리 실패: {e}")
            return self._get_fallback_response(query)
    
    def _create_findings_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """스캔 결과 요약 생성"""
        findings = scan_results.get('findings', [])
        scan_summary = scan_results.get('scan_summary', {})
        
        # 심각도별 분류
        severity_counts = {}
        category_counts = {}
        rule_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            category = finding.get('category', 'unknown')
            rule_id = finding.get('rule_id', 'unknown')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        # 최근 탐지 항목 (상위 10개)
        recent_findings = findings[:10] if findings else []
        
        summary = {
            "scan_overview": {
                "total_score": scan_summary.get('total_score', 0),
                "risk_level": scan_summary.get('risk_level', 'unknown'),
                "total_findings": len(findings),
                "scan_duration": scan_results.get('scan_metadata', {}).get('scan_duration_seconds', 0)
            },
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "top_rules": dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            "recent_findings": [
                {
                    "rule_id": f.get('rule_id', ''),
                    "title": f.get('title', ''),
                    "severity": f.get('severity', ''),
                    "timestamp": f.get('timestamp', ''),
                    "description": f.get('description', '')[:100] + "..." if len(f.get('description', '')) > 100 else f.get('description', '')
                }
                for f in recent_findings
            ]
        }
        
        return summary
    
    def _find_related_findings(self, query: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """질의와 관련된 Finding 찾기"""
        query_lower = query.lower()
        related = []
        
        # 키워드 기반 매칭
        keywords = {
            'rdp': ['rdp', '원격', 'remote', '터미널'],
            'powershell': ['powershell', 'ps1', '파워셸', '스크립트'],
            'service': ['서비스', 'service', '프로세스'],
            'autorun': ['자동실행', 'autorun', '시작프로그램'],
            'lolbin': ['rundll32', 'regsvr32', 'mshta', 'certutil'],
            'logon': ['로그온', 'logon', '로그인', 'login'],
            'security': ['보안', 'security', '방화벽', 'defender']
        }
        
        for finding in findings:
            finding_text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('rule_id', '')}".lower()
            
            # 키워드 매칭
            for category, terms in keywords.items():
                if any(term in query_lower for term in terms) and any(term in finding_text for term in terms):
                    related.append({
                        "finding_id": finding.get('finding_id', ''),
                        "rule_id": finding.get('rule_id', ''),
                        "title": finding.get('title', ''),
                        "severity": finding.get('severity', ''),
                        "match_reason": f"키워드 매칭: {category}"
                    })
                    break
        
        # 중복 제거 및 상위 5개만 반환
        unique_related = []
        seen_ids = set()
        for item in related:
            if item['finding_id'] not in seen_ids:
                unique_related.append(item)
                seen_ids.add(item['finding_id'])
                if len(unique_related) >= 5:
                    break
        
        return unique_related
    
    def _get_fallback_response(self, query: str) -> Dict[str, Any]:
        """폴백 응답 생성"""
        return {
            "query": query,
            "answer": "죄송합니다. 현재 이 질문에 대한 답변을 생성할 수 없습니다. 스캔 결과를 직접 확인하시거나 다른 방식으로 질문해 주세요.",
            "confidence": 0.1,
            "source": "fallback",
            "related_findings": [],
            "timestamp": ""
        }
    
    def get_suggested_queries(self, scan_results: Dict[str, Any]) -> List[str]:
        """스캔 결과 기반 추천 질문 생성"""
        findings = scan_results.get('findings', [])
        scan_summary = scan_results.get('scan_summary', {})
        
        suggestions = []
        
        # 기본 질문들
        suggestions.extend([
            "전체적인 보안 상태는 어떤가요?",
            "가장 위험한 탐지 항목은 무엇인가요?",
            "즉시 조치가 필요한 항목이 있나요?"
        ])
        
        # 탐지된 항목 기반 질문 생성
        rule_counts = {}
        for finding in findings:
            rule_id = finding.get('rule_id', '')
            if rule_id:
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        
        # 많이 탐지된 룰 기반 질문
        if rule_counts:
            top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            
            for rule_id, count in top_rules:
                if 'RDP' in rule_id:
                    suggestions.append("RDP 관련 보안 위험이 있나요?")
                elif 'POWERSHELL' in rule_id:
                    suggestions.append("PowerShell 관련 의심스러운 활동이 있나요?")
                elif 'SERVICE' in rule_id:
                    suggestions.append("의심스러운 서비스가 설치되어 있나요?")
                elif 'AUTORUN' in rule_id:
                    suggestions.append("자동실행 프로그램에 문제가 있나요?")
        
        # 중복 제거 및 최대 6개 반환
        unique_suggestions = list(dict.fromkeys(suggestions))[:6]
        
        return unique_suggestions
