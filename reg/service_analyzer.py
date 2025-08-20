from typing import List, Dict, Any
from winreg import QueryValueEx
from .reg_comm import open_reg, enum_subkeys, lastwrite_iso, type_name

# 서비스 레지스트리 Image Path, ServiceDll 항목 받아서 리스트 반환
def collect_service_registry() -> List[Dict[str, Any]]:
    """
    서비스 레지스트리 값 확인
    key, value, data, timestamp, type 딕셔너리 리스트 반환

    Returns:
        
        "key": f"{hive}\\{path}",
        "value": name,
        "data": data, 
        "timestamp": ts,
        "type": type_name(typ),

    """

    
    hive = "HKLM"
    base_path = r"SYSTEM\CurrentControlSet\Services"
    out: List[Dict[str, Any]] = []


    # 서비스 루트
    root = open_reg(hive, base_path)
    if not root:
        return out
    
    # 하위 서비스 확인
    for svc in enum_subkeys(root):
        svc_path = f"{base_path}\\{svc}"

        # 서비스 키
        h = open_reg(hive, svc_path)
        if not h:
            continue
        ts = lastwrite_iso(h)

        # ImagePath 수집
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

        # 파라미터-ServiceDll 수집
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
