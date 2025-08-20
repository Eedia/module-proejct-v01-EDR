"""
AI Issue Detector - 이벤트로그와 레지스트리 데이터 전문 분석
EDR 데이터를 기반으로 보안 이슈를 AI로 탐지
"""
import json
from typing import Dict, List
from .base import AIBaseModule
from .models import SecurityIssue

class AIIssueDetector(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "issue_detector")
        
    def analyze_findings(self, findings_data: Dict) -> List[SecurityIssue]:
        """이벤트로그와 레지스트리 데이터에서 보안 이슈 탐지"""
        
        event_logs = findings_data.get('event_logs', [])
        registry_data = findings_data.get('registry_data', {})
        
        prompt = self._build_analysis_prompt(event_logs, registry_data)
        
        # 공통 API 호출 사용
        response_content = self._safe_api_call(prompt, "security")
        
        if response_content:
            # 공통 JSON 처리 사용
            detected_issues_data = self._clean_and_parse_json(response_content, "array")
            
            if isinstance(detected_issues_data, list):
                # SecurityIssue 객체로 변환
                issues = []
                for i, issue_data in enumerate(detected_issues_data):
                    issue = self._create_security_issue(issue_data, findings_data, i)
                    if issue:
                        issues.append(issue)
                
                self.logger.info(f"AI가 {len(issues)}개 보안 이슈 탐지")
                return issues
        
        # AI 실패 시 폴백 분석
        self.logger.warning("AI 탐지 실패, 폴백 분석 사용")
        return self._simple_event_registry_analysis(findings_data)
    
    def _build_analysis_prompt(self, event_logs: List, registry_data: Dict) -> str:
        """보안 분석용 프롬프트 생성"""
        return f"""
=== 🚨 EDR 스캔 결과 보안 분석 임무 ===

당신은 Windows 보안 전문가입니다. 수집된 EDR 데이터를 분석하여 
보안 위험과 의심스러운 활동을 탐지해주세요.

=== 이벤트 로그 데이터 ===
{json.dumps(event_logs[:10], ensure_ascii=False, indent=2)}

=== 레지스트리 분석 데이터 ===
{json.dumps(dict(list(registry_data.items())[:5]), ensure_ascii=False, indent=2)}

=== AI 분석 관점 ===
1. **악성 활동 탐지**: 의심스러운 프로세스 실행, 파일 조작
2. **지속성 메커니즘**: 자동실행 레지스트리 키, 서비스 설치
3. **권한 상승**: 관리자 권한 획득 시도
4. **보안 우회**: Windows Defender 비활성화 등
5. **MITRE ATT&CK 매핑**: 공격 기법 분류

=== 응답 규칙 ===
- JSON 배열만 응답 (설명 없이)
- 모든 경로는 슬래시(/) 사용
- 신뢰도는 0.0~1.0 범위

[
  {{
    "issue_id": "ai-detection-001",
    "title": "의심스러운 PowerShell 실행",
    "severity": "high",
    "category": "suspicious_execution", 
    "description": "Base64 인코딩된 PowerShell 명령어 실행 탐지",
    "evidence": {{
      "event_id": 4688,
      "process_name": "powershell.exe",
      "command_line": "powershell -encodedcommand..."
    }},
    "confidence": 0.85
  }}
]
"""
    
    def _create_security_issue(self, issue_data: Dict, findings_data: Dict, index: int) -> SecurityIssue:
        """이슈 데이터를 SecurityIssue 객체로 변환"""
        try:
            return SecurityIssue(
                issue_id=issue_data.get('issue_id', f"ai-{index+1:03d}"),
                title=issue_data.get('title', 'Unknown Issue'),
                severity=issue_data.get('severity', 'medium'),
                category=issue_data.get('category', 'unknown'),
                description=issue_data.get('description', ''),
                confidence=float(issue_data.get('confidence', 0.5)),
                evidence=issue_data.get('evidence', {}),
                detected_at=findings_data.get('collection_timestamp'),
                rule_name=f"ai_detected_{issue_data.get('category', 'unknown')}"
            )
        except Exception as e:
            self.logger.error(f"SecurityIssue 생성 실패: {e}")
            return None
    
    def _simple_event_registry_analysis(self, findings_data: Dict) -> List[SecurityIssue]:
        """AI 실패 시 간단한 이벤트로그/레지스트리 분석"""
        issues = []
        event_logs = findings_data.get('event_logs', [])
        registry_data = findings_data.get('registry_data', {})
        
        self.logger.info("폴백 분석 시작")
        
        # 이벤트로그 분석
        for event in event_logs:
            event_id = event.get('event_id')
            
            # 의심스러운 PowerShell 실행
            if event_id == 4688 and event.get('process_name', '').lower() == 'powershell.exe':
                command_line = event.get('command_line', '')
                if any(suspicious in command_line.lower() for suspicious in 
                      ['-encodedcommand', 'bypass', 'downloadstring', 'invoke-expression']):
                    
                    issues.append(SecurityIssue(
                        issue_id=f"evt-ps-{event.get('process_id', '000')}",
                        title="의심스러운 PowerShell 명령어 실행",
                        severity="high",
                        category="suspicious_activity",
                        description=f"의심스러운 PowerShell 명령어가 실행됨: {command_line[:100]}...",
                        confidence=0.8,
                        evidence={"type": "event_log", "event_id": 4688, "command": command_line}
                    ))
        
        # 레지스트리 분석
        defender_key = registry_data.get('HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection', {})
        if defender_key.get('DisableRealtimeMonitoring') == 1:
            issues.append(SecurityIssue(
                issue_id="reg-defender",
                title="Windows Defender 실시간 보호 비활성화",
                severity="high",
                category="antivirus",
                description="레지스트리에서 Windows Defender 실시간 보호가 비활성화됨",
                confidence=0.95,
                evidence={"type": "registry", "key": "Real-Time Protection", "value": 1}
            ))
        
        self.logger.info(f"폴백 분석 완료: {len(issues)}개 이슈 발견")
        return issues
