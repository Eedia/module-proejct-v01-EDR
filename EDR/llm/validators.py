"""
AI 보안 명령어 검증기
AI가 생성한 명령어의 안전성을 검증
"""
import re
import logging
from typing import List, Dict, Tuple

class ScriptValidator:
    """AI 생성 스크립트 안전성 검증기"""
    
    def __init__(self):
        # 절대 금지된 위험 명령어 패턴
        self.dangerous_patterns = [
            r'Remove-Item.*-Recurse.*-Force',        # 폴더 전체 삭제
            r'Format-Volume',                        # 디스크 포맷
            r'Stop-Process.*explorer',               # 탐색기 종료
            r'Set-ExecutionPolicy.*Unrestricted',   # 보안 정책 해제
            r'Invoke-Expression.*\$\(',              # 동적 코드 실행
            r'reg delete.*HKLM',                     # 시스템 레지스트리 삭제
            r'Remove-WindowsFeature',                # Windows 기능 제거
            r'Disable-WindowsOptionalFeature.*Defender', # Defender 완전 비활성화
        ]
        
        # 허용된 안전한 명령어 패턴 (화이트리스트)
        self.safe_patterns = [
            r'^Get-\w+',                             # 조회 명령어들
            r'^Set-MpPreference',                    # Defender 설정
            r'^Update-MpSignature',                  # Defender 업데이트
            r'^Set-ItemProperty.*HKLM.*CurrentControlSet', # 안전한 레지스트리 수정
            r'^Stop-Service.*-Name.*["\'][\w-]+["\']', # 특정 서비스 중지
            r'^Set-Service.*-StartupType',           # 서비스 시작 타입 변경
            r'^Write-Host',                          # 화면 출력
            r'^Test-\w+',                           # 테스트 명령어들
        ]
        
        # 주의 필요한 명령어 패턴
        self.caution_patterns = [
            r'Stop-Service',                         # 서비스 중지
            r'Set-ItemProperty.*HKLM',              # 레지스트리 수정
            r'Restart-Service',                      # 서비스 재시작
            r'New-NetFirewallRule',                  # 방화벽 규칙 추가
        ]
        
        self.logger = logging.getLogger(__name__)
    
    def validate_script(self, script_content: str) -> Dict:
        """
        스크립트 안전성 검증
        
        반환값:
        {
            "is_safe": True/False,
            "risk_level": "safe/caution/dangerous",
            "warnings": ["경고사항들"],
            "blocked_commands": ["차단된 명령어들"]
        }
        """
        result = {
            "is_safe": True,
            "risk_level": "safe",
            "warnings": [],
            "blocked_commands": []
        }
        
        # 1. 위험한 패턴 검사
        for pattern in self.dangerous_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                result["is_safe"] = False
                result["risk_level"] = "dangerous"
                result["blocked_commands"].append(f"위험한 패턴 감지: {pattern}")
                self.logger.warning(f"위험한 명령어 차단: {pattern}")
        
        # 2. 주의 패턴 검사
        for pattern in self.caution_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                if result["risk_level"] == "safe":
                    result["risk_level"] = "caution"
                result["warnings"].append(f"주의 필요: {pattern}")
        
        # 3. 화이트리스트 검사 (안전한 명령어인지 확인)
        lines = script_content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):  # 빈 줄이나 주석은 스킵
                continue
                
            is_safe_command = any(
                re.match(pattern, line, re.IGNORECASE) 
                for pattern in self.safe_patterns
            )
            
            if not is_safe_command:
                result["warnings"].append(f"검증되지 않은 명령어: {line}")
                if result["risk_level"] == "safe":
                    result["risk_level"] = "caution"
        
        # 4. 추가 보안 검사
        security_checks = self._additional_security_checks(script_content)
        result["warnings"].extend(security_checks)
        
        return result
    
    def _additional_security_checks(self, script: str) -> List[str]:
        """추가 보안 검사"""
        warnings = []
        
        # PowerShell 스크립트 블록 검사
        if '${' in script or '$(' in script:
            warnings.append("동적 변수 사용 감지 - 검토 필요")
        
        # Base64 인코딩 감지
        if re.search(r'-EncodedCommand|FromBase64String', script, re.IGNORECASE):
            warnings.append("Base64 인코딩 사용 감지 - 의심스러운 활동")
        
        # 네트워크 활동 감지
        if re.search(r'Invoke-WebRequest|wget|curl|DownloadString', script, re.IGNORECASE):
            warnings.append("네트워크 다운로드 활동 감지")
        
        # 파일 실행 감지
        if re.search(r'Start-Process.*\.exe|Invoke-Item.*\.exe', script, re.IGNORECASE):
            warnings.append("실행 파일 구동 감지")
        
        return warnings
    
    def get_recommendation(self, validation_result: Dict) -> str:
        """검증 결과에 따른 권장사항 제공"""
        if validation_result["risk_level"] == "dangerous":
            return "🚨 위험! 이 명령어를 실행하지 마세요. 전문가 상담이 필요합니다."
        
        elif validation_result["risk_level"] == "caution":
            return "⚠️ 주의! 이 명령어의 영향을 이해한 후에 실행하세요."
        
        else:
            return "✅ 안전한 명령어입니다. 실행해도 됩니다."

# 테스트용 함수
def test_validator():
    validator = ScriptValidator()
    
    # 테스트 스크립트들
    test_scripts = [
        # 안전한 스크립트
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        
        # 주의 필요한 스크립트  
        "Stop-Service -Name 'Spooler'",
        
        # 위험한 스크립트
        "Remove-Item C:\\Windows -Recurse -Force"
    ]
    
    for script in test_scripts:
        print(f"\n스크립트: {script}")
        result = validator.validate_script(script)
        print(f"안전성: {result['is_safe']}")
        print(f"위험도: {result['risk_level']}")
        print(f"권장사항: {validator.get_recommendation(result)}")
        if result['warnings']:
            print(f"경고: {result['warnings']}")

if __name__ == "__main__":
    test_validator()
