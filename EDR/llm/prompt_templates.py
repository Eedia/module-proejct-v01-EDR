"""
AI 프롬프트 템플릿
각 탐지 룰별 맞춤형 프롬프트 제공
"""

from typing import Dict, Any

class PromptTemplates:
    """AI 프롬프트 템플릿 관리"""
    
    # 기본 시스템 프롬프트
    SYSTEM_PROMPT = """
당신은 Windows 보안 전문가입니다.
EDR 스캔 결과를 기반으로 정확하고 안전한 PowerShell 조치 스크립트를 생성해야 합니다.

**중요한 원칙:**
1. 절대로 시스템을 손상시키지 않는 안전한 명령어만 생성
2. 각 조치에 대해 검증 스크립트와 롤백 스크립트도 함께 제공
3. 명령어 실행 전 반드시 백업이나 확인 절차를 포함
4. 가능한 한 비파괴적인 방법을 우선 사용
5. 모든 스크립트는 PowerShell 5.1+ 호환

**응답 형식:**
반드시 다음 JSON 형식으로 응답해주세요:
```json
{
    "fix_command": "조치 PowerShell 명령어",
    "validation_command": "조치 검증 PowerShell 명령어", 
    "rollback_command": "롤백 PowerShell 명령어",
    "description": "조치 내용 설명",
    "confidence": 0.85,
    "warnings": ["주의사항1", "주의사항2"]
}
```
"""

    # 룰별 특화 템플릿
    RULE_SPECIFIC_TEMPLATES = {
        # LOLBin 관련
        "R_LOLBIN_RUNDLL32_JS": """
rundll32.exe JavaScript 실행이 탐지되었습니다.
이는 악성 페이로드 다운로드나 실행에 사용될 수 있습니다.

탐지 정보:
- 프로세스: {process_name}
- 명령줄: {command_line}
- 시간: {timestamp}

적절한 조치 방법을 제시해주세요:
1. 해당 프로세스 종료
2. 실행된 스크립트나 다운로드된 파일 확인 및 제거
3. 시스템 스캔 권장
""",

        "R_LOLBIN_REGSVR32_URL": """
regsvr32.exe를 통한 외부 URL 호출이 탐지되었습니다.
이는 원격 스크립트 실행에 사용될 수 있습니다.

탐지 정보:
- 프로세스: {process_name}
- 명령줄: {command_line}
- URL: {url}
- 시간: {timestamp}

안전한 조치 방법을 제시해주세요.
""",

        "R_POWERSHELL_ENCODED": """
PowerShell 인코딩된 명령어 실행이 탐지되었습니다.
이는 악성 스크립트 난독화에 사용될 수 있습니다.

탐지 정보:
- 명령줄: {command_line}
- 사용자: {username}
- 시간: {timestamp}

PowerShell 실행 정책 강화 및 모니터링 방법을 제시해주세요.
""",

        "R_POWERSHELL_BYPASS_POLICY": """
PowerShell 실행 정책 우회가 탐지되었습니다.

탐지 정보:
- 명령줄: {command_line}
- 사용자: {username}
- 시간: {timestamp}

실행 정책을 강화하고 우회를 방지하는 방법을 제시해주세요.
""",

        # RDP 관련
        "R_RDP_NONBUSINESS_HOURS": """
비업무시간 RDP 접속이 탐지되었습니다.

탐지 정보:
- 사용자: {username}
- 소스 IP: {source_ip}
- 접속 시간: {timestamp}

RDP 보안을 강화하는 방법을 제시해주세요.
""",

        "R_ADMIN_RDP_LOGON": """
관리자 계정 RDP 로그온이 탐지되었습니다.

탐지 정보:
- 관리자 계정: {username}
- 소스 IP: {source_ip}
- 로그온 시간: {timestamp}

관리자 계정 RDP 접근을 제한하는 방법을 제시해주세요.
""",

        # 서비스 관련
        "R_SERVICE_TEMP_PATH": """
임시 경로에 서비스가 설치되었습니다.

탐지 정보:
- 서비스명: {service_name}
- 이미지 경로: {image_path}
- 설치 시간: {timestamp}

의심스러운 서비스를 안전하게 제거하는 방법을 제시해주세요.
""",

        "R_SERVICE_SUSPICIOUS": """
의심스러운 서비스가 탐지되었습니다.

탐지 정보:
- 서비스명: {service_name}
- 이미지 경로: {image_path}
- 시작 유형: {start_type}

서비스 분석 및 제거 방법을 제시해주세요.
""",

        # 자동실행 관련
        "R_AUTORUN_SUSPICIOUS": """
의심스러운 자동실행 항목이 탐지되었습니다.

탐지 정보:
- 레지스트리 키: {registry_key}
- 값 이름: {value_name}
- 실행 파일: {executable_path}

자동실행 항목을 안전하게 제거하는 방법을 제시해주세요.
""",

        # 보안 설정 관련
        "R_SECURITY_RDP_NON_COMPLIANT": """
RDP 보안 설정이 취약합니다.

탐지 정보:
- RDP 상태: {rdp_enabled}
- 방화벽 허용: {firewall_allowed}
- 네트워크 레벨 인증: {nla_enabled}

RDP 보안을 강화하는 방법을 제시해주세요.
""",

        "R_SECURITY_DEFENDER_NON_COMPLIANT": """
Windows Defender 보안 설정이 취약합니다.

탐지 정보:
- 실시간 보호: {real_time_protection}
- 정의 업데이트: {definitions_updated}
- 스캔 상태: {scan_status}

Windows Defender를 적절히 설정하는 방법을 제시해주세요.
""",
    }

    # 폴백 템플릿 (알 수 없는 룰용)
    FALLBACK_TEMPLATE = """
보안 이슈가 탐지되었습니다.

탐지 정보:
- 룰 ID: {rule_id}
- 제목: {title}
- 심각도: {severity}
- 설명: {description}
- 시간: {timestamp}

이 보안 이슈에 대한 적절한 조치 방법을 제시해주세요.
"""

    @classmethod
    def get_remediation_prompt(cls, finding: Dict[str, Any]) -> str:
        """Finding에 맞는 조치 프롬프트 생성"""
        rule_id = finding.get('rule_id', '')
        
        # 룰별 특화 템플릿 찾기
        template = cls.RULE_SPECIFIC_TEMPLATES.get(rule_id, cls.FALLBACK_TEMPLATE)
        
        # 템플릿에 데이터 삽입
        try:
            # evidence에서 primary_event 추출
            evidence = finding.get('evidence', {})
            primary_event = evidence.get('primary_event', {})
            
            # 템플릿 변수 준비
            template_vars = {
                'rule_id': rule_id,
                'title': finding.get('title', ''),
                'severity': finding.get('severity', ''),
                'description': finding.get('description', ''),
                'timestamp': finding.get('timestamp', ''),
                'process_name': primary_event.get('process_name', ''),
                'command_line': primary_event.get('command_line', ''),
                'username': primary_event.get('username', ''),
                'source_ip': primary_event.get('source_ip', ''),
                'service_name': primary_event.get('service_name', ''),
                'image_path': primary_event.get('image_path', ''),
                'start_type': primary_event.get('start_type', ''),
                'registry_key': '',
                'value_name': '',
                'executable_path': '',
                'url': '',
                'rdp_enabled': '',
                'firewall_allowed': '',
                'nla_enabled': '',
                'real_time_protection': '',
                'definitions_updated': '',
                'scan_status': ''
            }
            
            # 레지스트리 증거가 있는 경우
            registry_evidence = evidence.get('registry_evidence', [])
            if registry_evidence:
                reg_data = registry_evidence[0] if isinstance(registry_evidence, list) else registry_evidence
                template_vars.update({
                    'registry_key': reg_data.get('key', ''),
                    'value_name': reg_data.get('value_name', ''),
                    'executable_path': reg_data.get('value_data', '')
                })
            
            # URL 추출 (명령줄에서)
            command_line = template_vars['command_line']
            if 'http' in command_line.lower():
                import re
                url_match = re.search(r'https?://[^\s]+', command_line)
                if url_match:
                    template_vars['url'] = url_match.group()
            
            formatted_template = template.format(**template_vars)
            
        except Exception as e:
            # 포맷팅 실패 시 폴백
            formatted_template = cls.FALLBACK_TEMPLATE.format(
                rule_id=rule_id,
                title=finding.get('title', ''),
                severity=finding.get('severity', ''),
                description=finding.get('description', ''),
                timestamp=finding.get('timestamp', '')
            )
        
        # 시스템 프롬프트와 결합
        return f"{cls.SYSTEM_PROMPT}\n\n{formatted_template}"

    @classmethod
    def get_summary_prompt(cls, findings: list) -> str:
        """스캔 결과 요약 프롬프트"""
        return f"""
다음은 EDR 스캔 결과입니다. 주요 보안 위험과 권장 조치사항을 요약해주세요.

스캔 결과:
- 총 탐지 항목: {len(findings)}개
- 심각도별 분포:
  * Critical: {len([f for f in findings if f.get('severity') == 'critical'])}개
  * High: {len([f for f in findings if f.get('severity') == 'high'])}개  
  * Medium: {len([f for f in findings if f.get('severity') == 'medium'])}개
  * Low: {len([f for f in findings if f.get('severity') == 'low'])}개

상위 5개 탐지 항목:
{chr(10).join([f"- {f.get('title', 'Unknown')} ({f.get('severity', 'unknown')})" for f in findings[:5]])}

전체적인 보안 상태를 평가하고 우선순위별 조치사항을 제시해주세요.
"""

    @classmethod 
    def get_query_prompt(cls, query: str, findings_summary: dict) -> str:
        """자연어 질의 프롬프트"""
        return f"""
사용자 질문: {query}

스캔 결과 요약:
{findings_summary}

이 질문에 대해 스캔 결과를 바탕으로 정확하고 도움이 되는 답변을 해주세요.
답변은 한국어로 작성해주세요.
"""
