from typing import Dict, Any
from .reg_comm import get_dword

def collect_security_settings() -> Dict[str, Any]:
    v = get_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    rdp_enabled = (v == 0) if v is not None else None

    profs = [
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile",
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
    ]
    fw_vals = [get_dword("HKLM", p, "EnableFirewall") for p in profs]
    firewall_enabled = None if any(x is None for x in fw_vals) else all(x == 1 for x in fw_vals)

    v = get_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    uac_enabled = (v == 1) if v is not None else None

    v = get_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature")
    smb_signing = (v == 1) if v is not None else None

    v = get_dword("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring")
    defender_real_time = (v == 0) if v is not None else None

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
