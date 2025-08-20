"""
AI Remediator - EDR 탐지 항목별 조치 스크립트 생성기
"""

import json
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from .api_client import GeminiClient
from .prompt_templates import PromptTemplates

class RemediationScript:
    """조치 스크립트 데이터 구조"""
    
    def __init__(self, finding_id: str, rule_id: str, severity: str,
                 fix_command: str, validation_command: str, rollback_command: str,
                 description: str, confidence: float, warnings: List[str] = None):
        self.finding_id = finding_id
        self.rule_id = rule_id
        self.severity = severity
        self.fix_command = fix_command
        self.validation_command = validation_command
        self.rollback_command = rollback_command
        self.description = description
        self.confidence = confidence
        self.warnings = warnings or []
        self.generated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """딕셔너리로 변환"""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "fix_command": self.fix_command,
            "validation_command": self.validation_command,
            "rollback_command": self.rollback_command,
            "description": self.description,
            "confidence": self.confidence,
            "warnings": self.warnings,
            "generated_at": self.generated_at
        }

class AIRemediator:
    """AI 기반 조치 스크립트 생성기"""
    
    def __init__(self):
        self.client = GeminiClient()
        self.logger = logging.getLogger(__name__)
        self.fallback_templates = self._load_fallback_templates()
    
    def generate_remediation_script(self, finding: Dict[str, Any]) -> Optional[RemediationScript]:
        """단일 Finding에 대한 AI 조치 스크립트 생성"""
        try:
            finding_id = finding.get('finding_id', '')
            rule_id = finding.get('rule_id', '')
            severity = finding.get('severity', 'medium')
            
            self.logger.info(f"AI 조치 스크립트 생성 시작: {rule_id}")
            
            # 프롬프트 생성
            prompt = PromptTemplates.get_remediation_prompt(finding)
            
            # AI API 호출
            response = self.client.generate_remediation(prompt)
            
            if response:
                # JSON 응답 파싱
                script_data = self._parse_ai_response(response)
                
                if script_data:
                    # RemediationScript 객체 생성
                    script = RemediationScript(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        severity=severity,
                        fix_command=script_data.get('fix_command', ''),
                        validation_command=script_data.get('validation_command', ''),
                        rollback_command=script_data.get('rollback_command', ''),
                        description=script_data.get('description', ''),
                        confidence=script_data.get('confidence', 0.7),
                        warnings=script_data.get('warnings', [])
                    )
                    
                    self.logger.info(f"✅ AI 조치 스크립트 생성 성공: {rule_id} (신뢰도: {script.confidence:.2f})")
                    return script
                else:
                    self.logger.warning(f"⚠️ AI 응답 파싱 실패: {rule_id}")
                    return self._get_fallback_script(finding)
            else:
                self.logger.warning(f"⚠️ AI API 호출 실패: {rule_id}")
                return self._get_fallback_script(finding)
                
        except Exception as e:
            self.logger.error(f"❌ 조치 스크립트 생성 실패: {rule_id} - {e}")
            return self._get_fallback_script(finding)
    
    def generate_batch_remediation_scripts(self, findings: List[Dict[str, Any]]) -> List[RemediationScript]:
        """여러 Finding에 대한 배치 조치 스크립트 생성"""
        scripts = []
        
        self.logger.info(f"{len(findings)}개 탐지 항목에 대한 조치 스크립트 생성 시작")
        
        for i, finding in enumerate(findings, 1):
            try:
                rule_id = finding.get('rule_id', 'UNKNOWN')
                self.logger.info(f"  {i}/{len(findings)}: {rule_id}")
                
                script = self.generate_remediation_script(finding)
                if script:
                    scripts.append(script)
                    
            except Exception as e:
                self.logger.error(f"  ❌ {i}/{len(findings)} 처리 실패: {e}")
                fallback_script = self._get_fallback_script(finding)
                if fallback_script:
                    scripts.append(fallback_script)
        
        self.logger.info(f"총 {len(scripts)}개 조치 스크립트 생성 완료")
        return scripts
    
    def _parse_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """AI 응답에서 JSON 추출 및 파싱"""
        try:
            # JSON 블록 찾기
            start_markers = ['```json', '{']
            end_markers = ['```', '}']
            
            json_start = -1
            json_end = -1
            
            # JSON 시작점 찾기
            for marker in start_markers:
                idx = response.find(marker)
                if idx != -1:
                    json_start = idx + len(marker) if marker == '```json' else idx
                    break
            
            if json_start == -1:
                return None
            
            # JSON 끝점 찾기 (가장 마지막 } 찾기)
            brace_count = 0
            in_json = False
            
            for i, char in enumerate(response[json_start:], json_start):
                if char == '{':
                    brace_count += 1
                    in_json = True
                elif char == '}':
                    brace_count -= 1
                    if in_json and brace_count == 0:
                        json_end = i + 1
                        break
            
            if json_end == -1:
                return None
            
            # JSON 추출 및 파싱
            json_text = response[json_start:json_end].strip()
            if json_text.startswith('```json'):
                json_text = json_text[7:].strip()
            if json_text.endswith('```'):
                json_text = json_text[:-3].strip()
            
            parsed = json.loads(json_text)
            
            # 필수 필드 검증
            required_fields = ['fix_command', 'validation_command', 'rollback_command', 'description']
            if all(field in parsed for field in required_fields):
                return parsed
            else:
                self.logger.warning(f"AI 응답에 필수 필드 누락: {required_fields}")
                return None
                
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON 파싱 실패: {e}")
            return None
        except Exception as e:
            self.logger.error(f"AI 응답 파싱 실패: {e}")
            return None
    
    def _get_fallback_script(self, finding: Dict[str, Any]) -> RemediationScript:
        """폴백 조치 스크립트 생성"""
        finding_id = finding.get('finding_id', '')
        rule_id = finding.get('rule_id', '')
        severity = finding.get('severity', 'medium')
        title = finding.get('title', '알 수 없는 보안 이슈')
        
        # 룰별 폴백 템플릿
        fallback_data = self.fallback_templates.get(rule_id, {
            'fix_command': '# 수동 조치 필요\nWrite-Host "이 항목은 수동으로 검토하고 조치해주세요."',
            'validation_command': 'Write-Host "수동 검증이 필요합니다."',
            'rollback_command': 'Write-Host "필요 시 수동으로 롤백해주세요."',
            'description': f'{title}에 대한 수동 조치가 필요합니다.',
            'confidence': 0.3,
            'warnings': ['이 항목은 AI가 자동 생성하지 못했습니다.', '수동 검토 및 조치가 필요합니다.']
        })
        
        return RemediationScript(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            fix_command=fallback_data['fix_command'],
            validation_command=fallback_data['validation_command'],
            rollback_command=fallback_data['rollback_command'],
            description=fallback_data['description'],
            confidence=fallback_data['confidence'],
            warnings=fallback_data['warnings']
        )
    
    def _load_fallback_templates(self) -> Dict[str, Dict[str, Any]]:
        """폴백 템플릿 로드"""
        return {
            # LOLBin 관련 폴백
            "R_LOLBIN_RUNDLL32_JS": {
                'fix_command': '''# rundll32.exe JavaScript 실행 차단
Get-Process -Name "rundll32" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*javascript:*" -or $_.CommandLine -like "*vbscript:*"
} | Stop-Process -Force
Write-Host "의심스러운 rundll32 프로세스를 종료했습니다."''',
                'validation_command': '''# rundll32 프로세스 상태 확인
$suspicious = Get-Process -Name "rundll32" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*javascript:*" -or $_.CommandLine -like "*vbscript:*"
}
if ($suspicious) { Write-Host "여전히 의심스러운 rundll32 프로세스가 실행 중입니다." } 
else { Write-Host "의심스러운 rundll32 프로세스가 발견되지 않습니다." }''',
                'rollback_command': 'Write-Host "rundll32 프로세스 종료는 롤백할 수 없습니다. 필요 시 해당 애플리케이션을 다시 시작하세요."',
                'description': 'rundll32.exe를 통한 JavaScript 실행을 차단합니다.',
                'confidence': 0.8,
                'warnings': ['정상적인 rundll32 프로세스도 영향을 받을 수 있습니다.']
            },
            
            "R_POWERSHELL_ENCODED": {
                'fix_command': '''# PowerShell 실행 정책 강화
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser -Force
Write-Host "PowerShell 실행 정책을 Restricted로 설정했습니다."''',
                'validation_command': '''# PowerShell 실행 정책 확인
$policy = Get-ExecutionPolicy -Scope CurrentUser
Write-Host "현재 PowerShell 실행 정책: $policy"
if ($policy -eq "Restricted") { Write-Host "✅ 실행 정책이 안전하게 설정되었습니다." }
else { Write-Host "⚠️ 실행 정책 설정을 확인해주세요." }''',
                'rollback_command': '''# PowerShell 실행 정책 복원
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Write-Host "PowerShell 실행 정책을 RemoteSigned로 복원했습니다."''',
                'description': 'PowerShell 실행 정책을 제한하여 인코딩된 스크립트 실행을 방지합니다.',
                'confidence': 0.9,
                'warnings': ['일부 PowerShell 스크립트가 실행되지 않을 수 있습니다.']
            }
        }
    
    def save_scripts_to_file(self, scripts: List[RemediationScript], output_dir: str = "output/scripts") -> str:
        """조치 스크립트를 파일로 저장"""
        # 출력 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        
        # 파일명 생성
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"remediation_scripts_{timestamp}.ps1"
        filepath = os.path.join(output_dir, filename)
        
        # PowerShell 스크립트 생성
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# EDR Scanner - AI Generated Remediation Scripts\n")
            f.write(f"# Generated at: {datetime.now().isoformat()}\n")
            f.write("# WARNING: Review all scripts before execution!\n\n")
            
            for i, script in enumerate(scripts, 1):
                f.write(f"# ======== Script {i}: {script.rule_id} ========\n")
                f.write(f"# Severity: {script.severity}\n")
                f.write(f"# Confidence: {script.confidence}\n")
                f.write(f"# Description: {script.description}\n")
                
                if script.warnings:
                    f.write("# Warnings:\n")
                    for warning in script.warnings:
                        f.write(f"#   - {warning}\n")
                
                f.write("\n# Fix Command:\n")
                f.write(f"{script.fix_command}\n\n")
                
                f.write("# Validation Command:\n")
                f.write(f"{script.validation_command}\n\n")
                
                f.write("# Rollback Command:\n")
                f.write(f"{script.rollback_command}\n\n")
                
                f.write("#" + "="*50 + "\n\n")
        
        self.logger.info(f"조치 스크립트 파일 저장: {filepath}")
        return filepath
