"""
AI Remediator - 해결책 생성 AI
보안 이슈에 대한 PowerShell 조치 스크립트 자동 생성
"""
import json
from typing import List, Dict, Optional
from .base import AIBaseModule
from .models import RemediationScript, SecurityIssue


class RemediationEngine(AIBaseModule):
    def __init__(self, config: Dict):
        super().__init__(config, "remediation")
        self.fallback_templates = self._load_fallback_templates()
    
    def generate_remediation_scripts(self, findings: List[SecurityIssue]) -> List[RemediationScript]:
        """여러 보안 이슈들을 한번에 처리"""
        scripts = []
        
        self.logger.info(f"{len(findings)}개 이슈 해결책 생성 시작")
        
        for i, finding in enumerate(findings, 1):
            try:
                self.logger.info(f"  {i}/{len(findings)}: {finding.rule_name}")
                
                # AI로 해결책 생성 시도
                script = self._create_remediation_script(finding)
                
                conf = self._extract_confidence(script)

                if script and conf >= 0.5:
                    script.confidence = conf
                    scripts.append(script)
                    self.logger.info(f"  ✅ AI 해결책 생성 성공 (신뢰도: {conf:.2f})")
                else:
                    fallback_script = self._get_fallback_script(finding)
                    scripts.append(fallback_script)
                    self.logger.warning(f"  ⚠️ 폴백 템플릿 사용")
                    
            except Exception as e:
                self.logger.error(f"  ❌ 해결책 생성 실패: {e}")
                scripts.append(self._get_fallback_script(finding))
        
        self.logger.info(f"총 {len(scripts)}개 해결책 생성 완료")
        return scripts
    
    def _extract_confidence(self, script) -> float:
        """스크립트에서 신뢰도 값을 안전하게 추출"""
        if script is None:
            return 0.0

        if hasattr(script, 'confidence'):
            confidence = script.confidence
        elif isinstance(script, dict):
            confidence = script.get('confidence', 0)
        else:
            confidence = 0

        if isinstance(confidence, dict):
            confidence = confidence.get('value', 0)

        try:
            value = float(confidence)
        except (TypeError, ValueError):
            value = 0.0

        return max(0.0, min(value, 1.0))
    
    def _create_remediation_script(self, finding: SecurityIssue) -> Optional[RemediationScript]:
        """단일 보안 이슈에 대해 AI로 해결책 생성"""
        
        prompt = f"""
당신은 Windows 보안 전문가입니다.
아래 보안 이슈를 해결하는 안전한 PowerShell 명령어를 생성해 주세요.

=== 보안 이슈 정보 ===
ID: {finding.issue_id}
제목: {finding.title}
심각도: {finding.severity}
설명: {finding.description}
증거: {json.dumps(finding.evidence, ensure_ascii=False, indent=2)}

=== 응답 형식 (JSON만) ===
{{
    "fix_command": "문제를 해결하는 PowerShell 명령어",
    "validation_command": "해결 결과를 확인하는 PowerShell 명령어",
    "rollback_command": "원래 상태로 되돌리는 PowerShell 명령어",
    "description": "무엇을 하는지 상세 설명",
    "confidence": 0.95,
    "warnings": ["주의사항 리스트"]
}}

중요한 규칙:
1. 모든 키와 문자열 값은 쌍따옴표로 감싸세요
2. 마지막 항목 뒤에는 쉼표를 붙이지 마세요
3. 레지스트리 경로는 HKLM:/ 형태로 슬래시 사용
4. 파일 경로는 C:/ 형태로 슬래시 사용  
5. JSON 문자열에 역슬래시 절대 금지
6. 다른 텍스트 없이 JSON만 응답하세요
7. confidence는 반드시 0.0부터 1.0 사이의 숫자로만 입력하세요
8. 한국어로 답변하세요

레지스트리 경로 예시:
- "HKLM:/SOFTWARE/Microsoft/Windows" (슬래시 사용)

다른 설명은 하지 말고 위 JSON만 응답하세요.
"""
        
        # 공통 API 호출 사용
        response_content = self._safe_api_call(prompt, "remediation")
        
        if response_content:
            # 공통 JSON 처리 사용
            result = self._clean_and_parse_json(response_content, "object")
            
            if result and all(key in result for key in ['fix_command', 'validation_command', 'rollback_command']):
                return RemediationScript(
                    issue_id=finding.issue_id,
                    rule_name=finding.rule_name,
                    severity=finding.severity,
                    fix_command=result['fix_command'],
                    validation_command=result['validation_command'],
                    rollback_command=result['rollback_command'],
                    description=result['description'],
                    confidence=self._extract_confidence(result),
                    warnings=result.get('warnings', [])
                )
        
        return None
    
    def _load_fallback_templates(self) -> Dict:
        """폴백 템플릿 로드"""
        return {
            'antivirus': {
                'fix': 'Set-MpPreference -DisableRealtimeMonitoring $false',
                'validation': 'Get-MpPreference | Select-Object DisableRealtimeMonitoring',
                'rollback': 'Set-MpPreference -DisableRealtimeMonitoring $true',
                'description': 'Windows Defender 실시간 보호 활성화',
                'warnings': ['관리자 권한 필요']
            },
            'network': {
                'fix': 'Set-ItemProperty -Path "HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server" -Name "fDenyTSConnections" -Value 1',
                'validation': 'Get-ItemProperty -Path "HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server" -Name "fDenyTSConnections"',
                'rollback': 'Set-ItemProperty -Path "HKLM:/SYSTEM/CurrentControlSet/Control/Terminal Server" -Name "fDenyTSConnections" -Value 0',
                'description': 'RDP 원격 연결 비활성화',
                'warnings': ['관리자 권한 필요', '원격 연결이 차단됩니다']
            },
            'persistence': {
                'fix': 'Remove-ItemProperty -Path "HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run" -Name "SuspiciousApp"',
                'validation': 'Get-ItemProperty -Path "HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run" -Name "SuspiciousApp" -ErrorAction SilentlyContinue',
                'rollback': 'Set-ItemProperty -Path "HKLM:/SOFTWARE/Microsoft/Windows/CurrentVersion/Run" -Name "SuspiciousApp" -Value "원래값"',
                'description': '의심스러운 자동실행 항목 제거',
                'warnings': ['관리자 권한 필요', '레지스트리 백업 권장']
            },
            'suspicious_activity': {
                'fix': 'Stop-Process -Name "powershell" -Force',
                'validation': 'Get-Process -Name "powershell" -ErrorAction SilentlyContinue',
                'rollback': 'Write-Host "프로세스 종료는 되돌릴 수 없습니다"',
                'description': '의심스러운 PowerShell 프로세스 종료',
                'warnings': ['관리자 권한 필요', '정상 작업도 종료될 수 있음']
            }
        }
    
    def _get_fallback_script(self, finding: SecurityIssue) -> RemediationScript:
        """AI 실패 시 폴백 스크립트 생성"""
        template_key = finding.category if finding.category in self.fallback_templates else 'persistence'
        template = self.fallback_templates[template_key]
        
        return RemediationScript(
            issue_id=finding.issue_id,
            rule_name=finding.rule_name,
            severity=finding.severity,
            fix_command=template['fix'],
            validation_command=template['validation'],
            rollback_command=template['rollback'],
            description=f"[템플릿] {template['description']}",
            confidence=0.6,
            warnings=template['warnings'] + ['AI 생성 실패로 템플릿 사용']
        )
