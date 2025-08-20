import os, json, re
from datetime import datetime
import pandas as pd
from checklist import paths_to_extract
from winreg import *

# openpyxl 내장 정규식
try:
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
except Exception:
    ILLEGAL_CHARACTERS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]')

_NONCHARS_RE = re.compile(r'[\uFFFE\uFFFF]')

MAX_XLSX_CELL = 32767  # 엑셀 한 셀 최대 글자수


##################################
############ 공통 유틸 ############
##################################

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


# 하이브 => 딕셔너리로 관리
HIVES = {
    "HKLM": HKEY_LOCAL_MACHINE,
    "HKCU": HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE": HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": HKEY_CURRENT_USER,
}

# 엑셀 컬럼 지정
STD_COLS = [
    "hive", "path", "subkey",     # 위치 정보
    "name", "type", "source",     # 값 메타
    "value", "value_dec", "value_hex",  # 사람이 읽는 값/숫자 파생
    "raw_hex", "raw_len",         # 원본(표시는 셀 한도 내에서)
]

# 키 로드(스캐닝)
def open_key(root, path):
    """
    키 로드(KEY_READ 고정)

    Args:
        hive: 하이브
        path: 레지스트리 경로
    """
    try:
        if isinstance(root, str):
            root_handle = HIVES[root]
        else:
            root_handle = root
        return OpenKey(root_handle, path, 0, KEY_READ)
    except OSError:
        return None

# 키 값 나열
def enum_values(hkey):
    """
    키 내부 값(name, data, type, ...) 나열. 리스트로 반환

    Args:
        hkey: 키 핸들
    """
    out=[]; i=0
    # 키 값 없으면 빈 리스트 반환
    if not hkey: return out

    # OSError 나올때까지 레지스트리 값 저장
    while True:
        try: out.append(EnumValue(hkey, i)); i+=1
        except OSError: break
    return out 

# 키 내부의 서브키 값 이름 나열(전부)
def enum_subkeys(hkey):
    """
    하위키 값 모두 나열. 리스트로 반환
    서비스 목록 확인시 필요

    Args:
        hkey: 키 핸들
    """
    out=[]; i=0
    if not hkey: return out
    while True:
        try: out.append(EnumKey(hkey, i)); i+=1
        except OSError: break
    return out

# 값 정규화
def normalize(val):
    """
    데이터 값 정규화

    Args:
        val: 레지스트리 값의 데이터
    """

    # 문자열/숫자인경우 -> 그냥 사용(정규화X)
    if isinstance(val, (str, int, float)): return val

    # 바이너리(UTF-16LE/UTF-8) -> 정규화
    if isinstance(val, (bytes, bytearray)):
        for enc in ("utf-16-le","utf-8"):
            try: return val.decode(enc, errors="ignore")
            except Exception: pass
        
        # decode 안되는 경우에 16진수 문자열로 반환
        return val.hex()
    # 그 외 타입 => 문자열로 캐스팅 후 반환
    return str(val)


def to_record(hive:str, path:str, name:str, data, vtype:int, filename:str=None):
    """
    데이터(원본) 저장용

    """
    rec = {
        "hive": hive,
        "path": path,
        "name": name,
        "type": TYPE_NAME.get(vtype, str(vtype)),
    }
    if filename is not None:
        rec["source"] = filename


    # 바이너리: hex로 원본 저장 + 프리뷰 
    if isinstance(data, (bytes, bytearray)):
        hexstr = data.hex()
        rec["raw_hex"] = hexstr
        rec["raw_len"] = len(data)
        rec["value"] = hexstr

    # 정수형: 숫자/hex 둘다
    elif isinstance(data, int):
        rec["value"] = data
        rec["value_dec"] = data
        rec["value_hex"] = hex(data)

    # 문자열/리스트 -> 그대로
    else:
        rec["value"] = data
        if isinstance(data, str) and data.isdigit():
            try:
                n = int(data)
                rec["value_dec"] = n
                rec["value_hex"] = hex(n)
            except Exception:
                pass

    return rec


def collect_one_path(item: dict):
    """
    checklist2 항목 수집
    """
    root_h, root_name, full_path = resolve_root_and_path(item["hive"], item.get("path",""))
    want = set(item.get("values") or [])  
    filename = item.get("filename","")
    recurse = bool(item.get("recurse"))
    msg = item.get("message","")


    records = []

    # 레지스트리 키 가져옴(핸들반환)
    base = open_key(root_h, full_path)

    def keep(name):
        return True if not want else (name in want)

    # 하위키 순환 없으면
    if not recurse:
        # 현재 키의 값만
        for n, d, t in enum_values(base):
            if keep(n):
                records.append(to_record(root_name, full_path, n, d, t, filename))
    else:
        for sub in enum_subkeys(base):
            sk_path = f"{full_path}\\{sub}" if full_path else sub
            sk = open_key(root_h, sk_path)
            for n, d, t in enum_values(sk):
                if keep(n):
                    rec = to_record(root_name, sk_path, n, d, t, filename)
                    rec["subkey"] = sub
                    records.append(rec)

    meta = {"message": msg, "full_path": full_path, "hive_root": root_name}
    return records, meta


def resolve_root_and_path(hive_field: str, path_field: str):
    """
    루트랑 path 결합해서 최종 경로 생성
    """
    parts = hive_field.split("\\", 1)
    # 대문자로 통일
    root_token = parts[0].upper()
    prefix = parts[1] if len(parts) > 1 else ""
    root_handle = HIVES[root_token]
    root_name = "HKLM" if "LOCAL_MACHINE" in root_token else ("HKCU" if "CURRENT_USER" in root_token else root_token)
    # fullpath 생성
    if prefix and path_field:
        full_path = prefix + "\\" + path_field
    else:
        full_path = prefix or path_field or ""

    
    return root_handle, root_name, full_path


##########################################
############ 엑셀 저장 관련 함수 ############
##########################################


def excel_safe(v):
    """
    엑셀로 쓸 때만 문자열의 금지문자를 제거
    """
    if isinstance(v, str):
        s = v.replace("\x00", "")
        s = ILLEGAL_CHARACTERS_RE.sub("", s)
        s = _NONCHARS_RE.sub("", s)
        return s
    return v

def standardize_df(df: pd.DataFrame) -> pd.DataFrame:
    # 없는 컬럼은 빈칸으로 추가
    for c in STD_COLS:
        if c not in df.columns:
            df[c] = ""

    # 숫자 표기 통일
    if "value_dec" in df.columns:
        df["value_dec"] = df["value_dec"].apply(lambda x: "" if pd.isna(x) else f"{x}")
    if "value_hex" in df.columns:
        df["value_hex"] = df["value_hex"].apply(lambda x: "" if pd.isna(x) else f"{x}")

    # 긴 문자열은 셀 한도까지만 잘라 표시 => 원본은 JSON에 보존
    for col in ("value", "raw_hex"):
        if col in df.columns:
            df[col] = df[col].astype(str).str.slice(0, MAX_XLSX_CELL)

    # 컬럼 순서 고정 & 표준 외 컬럼은 버림
    df = df[STD_COLS]

    return df

def sanitize_df(df):
    return df.map(excel_safe) if hasattr(df, "map") else df.applymap(excel_safe)

########################################
############ 스캐닝 실행 함수 ############
########################################


def collect_from_paths(paths_to_extract: list):
    """
    전체 paths_to_extract를 돌며 섹션별로 수집
    반환:
      artifacts: { "<filename>": [records...] }
      meta:      { "<filename>": {"message": "...", "full_path": "..."} }
    """
    artifacts = {}
    meta = {}
    for item in paths_to_extract:
        fname = item.get("filename","(unnamed)")
        recs, m = collect_one_path(item)
        artifacts[fname] = recs
        meta[fname] = m
    return artifacts, meta


######################################
############ 파일 저장 함수 ############
######################################

def save_paths_outputs(artifacts: dict, meta: dict, outdir="output"):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base = os.path.join(outdir, f"scan_{ts}")

    # JSON
    with open(base + "_paths_registry.json", "w", encoding="utf-8") as f:
        json.dump({"artifacts": artifacts, "meta": meta}, f, ensure_ascii=False, indent=2)

    # XLSX
    used_sheets = set()
    with pd.ExcelWriter(base + "_paths_registry.xlsx", engine="openpyxl") as w:
        for section, rows in artifacts.items():
            df = pd.DataFrame(rows)
            if df.empty:
                # 그래도 표준 헤더만 가진 빈 시트 하나는 쓰고 싶으면:
                df = pd.DataFrame(columns=STD_COLS)

            # 표준화 → 금지문자 제거
            df = standardize_df(df)
            df = sanitize_df(df)  # excel_safe/map 적용 함수 (앞서 만든 것)

            # 시트명(간단)
            sheet = (section or "sheet")[:31]
            base_name, suffix = sheet, 2
            while sheet in used_sheets:
                tail = f" ({suffix})"
                sheet = (base_name[: (31 - len(tail))] + tail)
                suffix += 1
            used_sheets.add(sheet)

            df.to_excel(w, sheet_name=sheet, index=False)

    return base


if __name__ == "__main__":
    artifacts, meta = collect_from_paths(paths_to_extract)
    base = save_paths_outputs(artifacts, meta)
    print("Saved:", base + "_paths_registry.json/.xlsx")