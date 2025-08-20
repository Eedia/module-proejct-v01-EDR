from typing import List, Dict, Any
import re, os
from .reg_comm import open_reg, lastwrite_iso, type_name, enum_values



def collect_autorun_entries() -> List[Dict[str, Any]]:
    targets = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    out: List[Dict[str, Any]] = []

    for hive, path in targets:
        h = open_reg(hive, path)
        if not h:
            continue
        ts = lastwrite_iso(h)
        for name, data, typ in enum_values(h):
            out.append({
                "key": f"{hive}\\{path}",
                "value": name,
                "data": data, 
                "timestamp": ts,
                "type": type_name(typ),
            })
    return out
