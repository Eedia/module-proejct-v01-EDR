"""
AI Issue Detector - 기존 탐지 이슈 분석 전용 (새로운 이슈 생성 금지)
EDR 데이터를 기반으로 기존 이슈들의 AI 분석과 해설 제공
"""
import json
from typing import Dict, List
from .base import AIBaseModule
from .models import SecurityIssue

class AIIssueDetector(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "issue_detector")
        
    def analyze_findings(self, findings_data: Dict) -> List[SecurityIssue]:
        """기존 탐지 이슈들을 AI로 분석하여 요약과 해설 생성 (새로운 이슈 생성 금지)"""
        
        existing_findings = findings_data.get('existing_findings', [])
        
        if not existing_findings:
            self.logger.warning("분석할 기존 탐지 이슈가 없습니다.")
            return []
        
        prompt = self._build_analysis_prompt(existing_findings, findings_data)
        
        # 공통 API 호출 사용
        response_content = self._safe_api_call(prompt, "analysis")
        
        if response_content:
            # AI 분석 결과를 파싱하여 기존 이슈에 AI 해설 추가
            analysis_result = self._clean_and_parse_json(response_content, "object")
            
            if isinstance(analysis_result, dict):
                # 기존 이슈들에 AI 분석 결과를 추가
                enhanced_issues = []
                for i, finding in enumerate(existing_findings):
                    enhanced_issue = SecurityIssue(
                        issue_id=finding.get('finding_id', f"existing-{i+1:03d}"),
                        title=finding.get('title', 'Unknown Issue'),
                        severity=finding.get('severity', 'medium'),
                        category=finding.get('category', 'unknown'),
                        description=finding.get('description', ''),
                        confidence=float(finding.get('confidence', 50)) / 100.0,
                        evidence=finding.get('evidence', {}),
                        detected_at=finding.get('timestamp'),
                        rule_name=finding.get('rule_id', ''),
                        ai_analysis=analysis_result.get('ai_insights', {})  # AI 분석 추가
                    )
                    enhanced_issues.append(enhanced_issue)
                
                self.logger.info(f"AI가 {len(enhanced_issues)}개 기존 이슈 분석 완료")
                return enhanced_issues
        
        # AI 분석 실패 시 기존 이슈들을 그대로 반환
        self.logger.warning("AI 분석 실패, 기존 이슈들을 그대로 반환")
        return self._convert_existing_findings(existing_findings)
    
    def _build_analysis_prompt(self, existing_findings: List, findings_data: Dict) -> str:
        """기존 이슈 분석용 프롬프트 생성 (새로운 이슈 탐지 금지)"""
        return f"""
=== 🔍 EDR 스캔 결과 AI 분석 임무 ===

당신은 Windows 보안 전문가입니다. 이미 탐지된 보안 이슈들을 분석하여 
전문적인 해설과 요약을 제공해주세요.

⚠️ 중요: 새로운 이슈를 생성하지 말고, 기존 이슈들만 분석해주세요.

=== 기존 탐지된 보안 이슈들 ===
{json.dumps(existing_findings[:10], ensure_ascii=False, indent=2)}

=== 분석 요구사항 ===
1. **위험도 평가**: 전체 보안 상황 평가
2. **우선순위 분석**: 가장 위험한 이슈부터 순서화
3. **기술적 해설**: 각 이슈의 기술적 의미와 위험성
4. **연관성 분석**: 이슈들 간의 연관관계 파악
5. **대응 우선순위**: 어떤 순서로 대응해야 하는지

=== 응답 형식 ===
{{
  "overall_risk_level": "critical|high|medium|low",
  "priority_issues": ["issue_id1", "issue_id2", ...],
  "technical_analysis": "기술적 분석 내용",
  "correlation_insights": "이슈 간 연관성 분석",
  "response_priority": "대응 우선순위 가이드",
  "ai_insights": {{
    "summary": "전체 요약",
    "risk_factors": ["위험 요소들"],
    "recommendations": ["권장사항들"]
  }}
}}
"""
    
    def _convert_existing_findings(self, existing_findings: List) -> List[SecurityIssue]:
        """기존 findings를 SecurityIssue 객체로 변환"""
        issues = []
        for i, finding in enumerate(existing_findings):
            try:
                issue = SecurityIssue(
                    issue_id=finding.get('finding_id', f"existing-{i+1:03d}"),
                    title=finding.get('title', 'Unknown Issue'),
                    severity=finding.get('severity', 'medium'),
                    category=finding.get('category', 'unknown'),
                    description=finding.get('description', ''),
                    confidence=float(finding.get('confidence', 50)) / 100.0,
                    evidence=finding.get('evidence', {}),
                    detected_at=finding.get('timestamp'),
                    rule_name=finding.get('rule_id', '')
                )
                issues.append(issue)
            except Exception as e:
                self.logger.error(f"SecurityIssue 변환 실패: {e}")
                continue
        
        return issues
