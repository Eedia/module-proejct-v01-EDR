import os, json, re
from datetime import datetime
import pandas as pd

from .reg_comm import open_reg, enum_values, enum_subkeys, lastwrite_iso, type_name
from .security_settings import collect_security_settings
from .autorun_analyzer import collect_autorun_entries
from .service_analyzer import collect_service_registry

# 엑셀 저장용 설정
try:
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
except Exception:
    ILLEGAL_CHARACTERS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]')
_NONCHARS_RE = re.compile(r'[\uFFFE\uFFFF]')

# 엑셀 금지문자 제거하는 함수
def _excel_safe(v):
    if isinstance(v, str):
        v = v.replace("\x00", "")
        v = ILLEGAL_CHARACTERS_RE.sub("", v)
        v = _NONCHARS_RE.sub("", v)
    return v

# Dataframe 전체 문자열 변환(엑셀 저장할때 깨지는거 방지)
def _sanitize_df(df: pd.DataFrame) -> pd.DataFrame:
    return df.map(_excel_safe) if hasattr(df, "map") else df.applymap(_excel_safe)


# 표준 스키마 => 시트 저장시 적용 
def _write_sheet(w, rows, sheet_name: str):
    if not rows:
        pd.DataFrame(columns=["key","value","data","type","timestamp"]).to_excel(
            w, sheet_name=sheet_name, index=False
        )
        return
    df = pd.DataFrame(rows)
    std = ["key","value","data","type","timestamp"]
    keep = [c for c in std if c in df.columns]
    df = df[keep]
    df = _sanitize_df(df)
    df.to_excel(w, sheet_name=sheet_name, index=False)


# 파일 저장(output 폴더에 저장됨)
def save_registry_outputs(autoruns, services, security, outdir="output"):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base = os.path.join(outdir, f"scan_{ts}")

    # JSON
    with open(base + "_registry.json", "w", encoding="utf-8") as f:
        json.dump(
            {"autoruns": autoruns, "services": services, "security": security},
            f, ensure_ascii=False, indent=2
        )

    # XLSX
    with pd.ExcelWriter(base + "_registry.xlsx", engine="openpyxl") as w:
        # 시트 나눔
        _write_sheet(w, autoruns, "autoruns")
        _write_sheet(w, services, "services")
        sec_rows = [{"setting": k, "value": v} for k, v in (security or {}).items()]
        if sec_rows:
            df = _sanitize_df(pd.DataFrame(sec_rows))
            df.to_excel(w, sheet_name="security", index=False)
        else:
            pd.DataFrame(columns=["setting","value"]).to_excel(w, sheet_name="security", index=False)

    return base

def run_and_save(outdir="output"):
    autoruns = collect_autorun_entries()
    services = collect_service_registry()
    try:
        from .security_settings import collect_security_settings
        security = collect_security_settings()
    except Exception:
        security = {}
    base = save_registry_outputs(autoruns, services, security, outdir)
    print("Saved:", base + "_registry.json", "and", base + "_registry.xlsx")

if __name__ == "__main__":
    run_and_save()
