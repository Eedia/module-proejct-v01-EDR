from winreg import *
from datetime import datetime, timezone
from typing import List, Tuple, Optional


TYPE_NAME = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_LITTLE_ENDIAN: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BE",
    REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_QWORD: "REG_QWORD",
}

HIVES = {
    "HKLM": HKEY_LOCAL_MACHINE, 
    "HKCU": HKEY_CURRENT_USER
    }



def type_name(t:int) -> str:
    return TYPE_NAME.get(t, str(t))

def open_reg(hive: str, path: str):
    try:
        return OpenKey(HIVES[hive], path, 0, KEY_READ)
    except OSError:
        return None

def enum_values(hkey) -> List[Tuple[str, object, int]]:
    out=[]; i=0
    if not hkey: return out
    while True:
        try:
            out.append(EnumValue(hkey, i)); i+=1
        except OSError:
            break
    return out

def enum_subkeys(hkey) -> List[str]:
    out=[]; i=0
    if not hkey: return out
    while True:
        try:
            out.append(EnumKey(hkey, i)); i+=1
        except OSError:
            break
    return out

def lastwrite_iso(hkey) -> Optional[str]:
    try:
        _, _, ft = QueryInfoKey(hkey)
        if not ft: return None
        sec = ft/10_000_000 - 11644473600
        return datetime.utcfromtimestamp(sec).replace(tzinfo=timezone.utc)\
            .isoformat().replace("+00:00","Z")
    except Exception:
        return None

def get_dword(hive: str, path: str, name: str) -> Optional[int]:
    h = open_reg(hive, path)
    if not h: return None
    try:
        val, typ = QueryValueEx(h, name)
        if typ in (REG_DWORD, REG_DWORD_LITTLE_ENDIAN, REG_DWORD_BIG_ENDIAN):
            return int(val)
    except OSError:
        pass
    return None