"""
AI Remediator - EDR 탐지 항목별 조치 스크립트 생성기 (업그레이드됨)
새로운 EDR 데이터 구조와 연동되는 버전
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from .base import AIBaseModule
from .models import RemediationScript, SecurityIssue
from .prompt_templates import PromptTemplates
from utils.data_structures import Finding

class AIRemediator(AIBaseModule):
    """AI 기반 조치 스크립트 생성기"""
    
    def __init__(self):
        super().__init__("remediator")
        self.prompt_templates = PromptTemplates()
        self.fallback_templates = self._load_fallback_templates()
    
    def generate_remediation_scripts(self, findings: List[Finding]) -> List[RemediationScript]:
        """여러 Finding을 한번에 처리하여 조치 스크립트 생성"""
        scripts = []
        
        self.logger.info(f"{len(findings)}개 Finding 해결책 생성 시작")
        
        for i, finding in enumerate(findings, 1):
            try:
                self.logger.info(f"  {i}/{len(findings)}: {finding.rule_id}")
                
                # AI로 해결책 생성 시도
                script = self._create_remediation_script(finding)
                
                if script and script.confidence >= 0.5:
                    scripts.append(script)
                    self.logger.info(f"  ✅ AI 해결책 생성 성공 (신뢰도: {script.confidence:.2f})")
                else:
                    fallback_script = self._get_fallback_script(finding)
                    scripts.append(fallback_script)
                    self.logger.warning(f"  ⚠️ 폴백 템플릿 사용")
                    
            except Exception as e:
                self.logger.error(f"  ❌ 해결책 생성 실패: {e}")
                scripts.append(self._get_fallback_script(finding))
        
        self.logger.info(f"총 {len(scripts)}개 해결책 생성 완료")
        return scripts
    
    def _create_remediation_script(self, finding: Finding) -> Optional[RemediationScript]:
        """단일 Finding에 대해 AI로 해결책 생성"""
        
        # Finding의 증거 데이터 수집
        evidence_data = {}
        if finding.evidence:
            # Finding.evidence는 dict 형식으로 제공될 수 있음
            if isinstance(finding.evidence, dict):
                for item in finding.evidence.values():
                    # 각 항목은 리스트 또는 단일 dict일 수 있음
                    if isinstance(item, list):
                        for ev in item:
                            if isinstance(ev, dict):
                                evidence_data.update(ev)
                    elif isinstance(item, dict):
                        evidence_data.update(item)
            elif isinstance(finding.evidence, list):
                # 리스트로 전달될 경우 각 증거 객체 처리
                for ev in finding.evidence:
                    if hasattr(ev, "data"):
                        evidence_data.update(getattr(ev, "data", {}))
                    elif isinstance(ev, dict):
                        evidence_data.update(ev)
                        
        prompt = f"""
당신은 Windows 보안 전문가입니다.
아래 보안 이슈를 해결하는 안전한 PowerShell 명령어를 생성해 주세요.

=== 보안 이슈 정보 ===
ID: {finding.finding_id}
룰 ID: {finding.rule_id}
제목: {finding.title}
심각도: {finding.severity}
카테고리: {finding.category}
설명: {finding.description}
신뢰도: {finding.confidence}
증거: {json.dumps(evidence_data, ensure_ascii=False, indent=2)}

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
                    issue_id=finding.finding_id,
                    rule_name=finding.rule_id,
                    severity=str(finding.severity),
                    fix_command=result['fix_command'],
                    validation_command=result['validation_command'],
                    rollback_command=result['rollback_command'],
                    description=result['description'],
                    confidence=float(result.get('confidence', 0.5)),
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
            'execution': {
                'fix': 'Set-ExecutionPolicy -ExecutionPolicy Restricted -Force',
                'validation': 'Get-ExecutionPolicy',
                'rollback': 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force',
                'description': 'PowerShell 실행 정책 강화',
                'warnings': ['관리자 권한 필요', '스크립트 실행이 제한됩니다']
            }
        }
    
    def _get_fallback_script(self, finding: Finding) -> RemediationScript:
        """AI 실패 시 폴백 스크립트 생성"""
        # 카테고리에 따른 템플릿 선택
        category_str = str(finding.category).lower()
        template_key = 'persistence'  # 기본값
        
        for key in self.fallback_templates.keys():
            if key in category_str:
                template_key = key
                break
        
        template = self.fallback_templates[template_key]
        
        return RemediationScript(
            issue_id=finding.finding_id,
            rule_name=finding.rule_id,
            severity=str(finding.severity),
            fix_command=template['fix'],
            validation_command=template['validation'],
            rollback_command=template['rollback'],
            description=f"[템플릿] {template['description']}",
            confidence=0.6,
            warnings=template['warnings'] + ['AI 생성 실패로 템플릿 사용']
        )
    
    def save_scripts_to_file(self, scripts: List[RemediationScript], output_dir: str = "output") -> str:
        """생성된 스크립트를 파일로 저장"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"remediation_scripts_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        scripts_data = [script.to_dict() for script in scripts]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scripts_data, f, ensure_ascii=False, indent=2)
        
        self.logger.info(f"조치 스크립트 저장됨: {filepath}")
        return filepath
