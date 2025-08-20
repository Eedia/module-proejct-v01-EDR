import os, json, re
from datetime import datetime
import pandas as pd

from .reg_comm import open_reg, enum_values, enum_subkeys, lastwrite_iso, type_name
from .security_settings import collect_security_settings
from .autorun_analyzer import collect_autorun_entries
from .service_analyzer import collect_service_registry

try:
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
except Exception:
    ILLEGAL_CHARACTERS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]')
_NONCHARS_RE = re.compile(r'[\uFFFE\uFFFF]')

def _excel_safe(v):
    if isinstance(v, str):
        v = v.replace("\x00", "")
        v = ILLEGAL_CHARACTERS_RE.sub("", v)
        v = _NONCHARS_RE.sub("", v)
    return v

def _sanitize_df(df: pd.DataFrame) -> pd.DataFrame:
    return df.map(_excel_safe) if hasattr(df, "map") else df.applymap(_excel_safe)

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

def save_registry_outputs(autoruns, services, security, outdir="output"):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base = os.path.join(outdir, f"scan_{ts}")

    # JSON: 원본 그대로
    with open(base + "_registry.json", "w", encoding="utf-8") as f:
        json.dump(
            {"autoruns": autoruns, "services": services, "security": security},
            f, ensure_ascii=False, indent=2
        )

    with pd.ExcelWriter(base + "_registry.xlsx", engine="openpyxl") as w:
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
