from winreg import *
from datetime import datetime, timezone
from typing import List, Tuple, Optional

# 레지스트리 키 종류
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

# HIVE
HIVES = {
    "HKLM": HKEY_LOCAL_MACHINE, 
    "HKCU": HKEY_CURRENT_USER
    }


# 레지스트리 키 종류 문자열로 반환함
def type_name(t:int) -> str:
    return TYPE_NAME.get(t, str(t))

# 레지스트리 키 값 읽음(OpenKey)
def open_reg(hive: str, path: str):
    try:
        return OpenKey(HIVES[hive], path, 0, KEY_READ)
    except OSError:
        return None

# 키 내부값 확인
def enum_values(hkey) -> List[Tuple[str, object, int]]:
    out=[]; i=0
    if not hkey: return out
    while True:
        try:
            out.append(EnumValue(hkey, i)); i+=1
        except OSError:
            break
    return out

# 키 내 서브키 값 나열
def enum_subkeys(hkey) -> List[str]:
    out=[]; i=0
    if not hkey: return out
    while True:
        try:
            out.append(EnumKey(hkey, i)); i+=1
        except OSError:
            break
    return out

# 시간대 키값(LastWriteTime) UTC 문자열로 반환
def lastwrite_iso(hkey) -> Optional[str]:
    try:
        _, _, ft = QueryInfoKey(hkey)
        if not ft: return None
        sec = ft/10_000_000 - 11644473600
        return datetime.utcfromtimestamp(sec).replace(tzinfo=timezone.utc)\
            .isoformat().replace("+00:00","Z")
    except Exception:
        return None

# 지정한 위치 DWORD값 일거어서 정수로 반환
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