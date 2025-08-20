from typing import List, Dict, Any
from winreg import QueryValueEx
from .reg_comm import open_reg, enum_subkeys, lastwrite_iso, type_name

def collect_service_registry() -> List[Dict[str, Any]]:
    """
    """
    hive = "HKLM"
    base_path = r"SYSTEM\CurrentControlSet\Services"
    out: List[Dict[str, Any]] = []

    root = open_reg(hive, base_path)
    if not root:
        return out

    for svc in enum_subkeys(root):
        svc_path = f"{base_path}\\{svc}"

        # 서비스 키
        h = open_reg(hive, svc_path)
        if not h:
            continue
        ts = lastwrite_iso(h)

        try:
            data, typ = QueryValueEx(h, "ImagePath")
            out.append({
                "key": f"{hive}\\{svc_path}",
                "value": "ImagePath",
                "data": data,
                "timestamp": ts,
                "type": type_name(typ),
            })
        except OSError:
            pass

        p = open_reg(hive, svc_path + r"\Parameters")
        if p:
            try:
                data, typ = QueryValueEx(p, "ServiceDll")
                out.append({
                    "key": f"{hive}\\{svc_path}\\Parameters",
                    "value": "ServiceDll",
                    "data": data,
                    "timestamp": lastwrite_iso(p) or ts,
                    "type": type_name(typ),
                })
            except OSError:
                pass

    return out
