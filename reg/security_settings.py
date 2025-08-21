from typing import Dict, Any
from .reg_comm import get_dword

# 보안 세팅 수집
def collect_security_settings() -> Dict[str, Any]:
    """
    보안 세팅 수집 함수 
    스위치값(0x00, 0x01) => 읽어서 True(0)/False(1)/None으로 반환

    Returns:
        "rdp_enabled": RDP 허용여부
        "firewall_enabled": 방화벽 사용 여부,
        "uac_enabled": UAC 활성화 여부 ,
        "smb_signing": SMB 서명 강제 여부 ,
        "defender_real_time": Defender 실시간 보호 활성화 여부 ,
        "windows_update_auto": widows_update 자동 다운로드 여부,


    """

    # RDP 확인
    v = get_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    rdp_enabled = (v == 0) if v is not None else None

    # 방화벽
    profs = [
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
    ]
    fw_vals = [get_dword("HKLM", p, "EnableFirewall") for p in profs]
    firewall_enabled = None if any(x is None for x in fw_vals) else all(x == 1 for x in fw_vals)

    #UAC
    v = get_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    uac_enabled = (v == 1) if v is not None else None

    # SMB
    v = get_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature")
    smb_signing = (v == 1) if v is not None else None

    # Defender 
    v = get_dword("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")
    defender_real_time = (v == 0) if v is not None else None

    # Windows Update 자동
    v = get_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update", "AUOptions")
    windows_update_auto = (v is not None and v >= 3)

    return {
        "rdp_enabled": rdp_enabled,
        "firewall_enabled": firewall_enabled,
        "uac_enabled": uac_enabled,
        "smb_signing": smb_signing,
        "defender_real_time": defender_real_time,
        "windows_update_auto": windows_update_auto,
    }
