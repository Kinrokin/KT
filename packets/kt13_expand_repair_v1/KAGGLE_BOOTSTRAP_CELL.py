# KT13 expand/repair one-cell Kaggle bootstrap.
# Upload this zip as a Kaggle dataset or place it in /kaggle/input, then run this single cell.
import os
import zipfile
from pathlib import Path

os.environ.setdefault("KT_REQUESTED_HEAD", "4de572be825acb0e7551174575e225b74d6cf523")
os.environ.setdefault("KT_HF_ADAPTER_STORE", "Kinrokin/kt13-full-e2e-final-only-20260524-174447")
os.environ.setdefault("KT_OUT_DIR", "/kaggle/working/kt13_expand_repair_v1_outputs")

packet_zip = None
for candidate in Path("/kaggle/input").rglob("kt13_expand_repair_v1.zip"):
    packet_zip = candidate
    break
if packet_zip is None:
    for candidate in Path("/kaggle/working").rglob("kt13_expand_repair_v1.zip"):
        packet_zip = candidate
        break
if packet_zip is None:
    raise FileNotFoundError("Could not find kt13_expand_repair_v1.zip in /kaggle/input or /kaggle/working")

work = Path("/kaggle/working/kt13_expand_repair_v1_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet_zip, "r") as zf:
    zf.extractall(work)

runner = work / "KT13_EXPAND_REPAIR_V1_RUNNER.py"
if not runner.exists():
    runner = next(work.rglob("KT13_EXPAND_REPAIR_V1_RUNNER.py"))

exec(compile(runner.read_text(encoding="utf-8"), str(runner), "exec"))
