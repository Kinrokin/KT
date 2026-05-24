# KT13 expand/repair one-cell Kaggle bootstrap.
# Upload this zip as a Kaggle dataset or place it in /kaggle/input, then run this single cell.
import hashlib
import os
import zipfile
from pathlib import Path

os.environ.setdefault("KT_REQUESTED_HEAD", "4de572be825acb0e7551174575e225b74d6cf523")
os.environ.setdefault("KT_HF_ADAPTER_STORE", "Kinrokin/kt13-full-e2e-final-only-20260524-174447")
os.environ.setdefault("KT_OUT_DIR", "/kaggle/working/kt13_expand_repair_v1_outputs")

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_extract(zf, target):
    root = target.resolve()
    for member in zf.infolist():
        dest = (root / member.filename).resolve()
        if root != dest and root not in dest.parents:
            raise RuntimeError(f"Unsafe zip member path: {member.filename}")
    zf.extractall(root)

explicit = os.environ.get("KT_PACKET_ZIP_PATH")
if explicit:
    candidates = [Path(explicit)]
else:
    preferred = Path("/kaggle/input/kt13-expand-repair-v1/kt13_expand_repair_v1.zip")
    if preferred.exists():
        candidates = [preferred]
    else:
        candidates = list(Path("/kaggle/input").glob("*/kt13_expand_repair_v1.zip")) + list(Path("/kaggle/working").glob("kt13_expand_repair_v1.zip"))

existing = [candidate for candidate in candidates if candidate.exists()]
if len(existing) > 1:
    raise RuntimeError(f"Multiple candidate packets found; set KT_PACKET_ZIP_PATH explicitly: {[str(p) for p in existing]}")
packet_zip = existing[0] if existing else None
if packet_zip is None:
    raise FileNotFoundError("Could not find kt13_expand_repair_v1.zip in /kaggle/input or /kaggle/working")

expected_sha = os.environ.get("KT_PACKET_SHA256")
if expected_sha and _sha256(packet_zip).lower() != expected_sha.lower():
    raise RuntimeError("KT packet sha256 mismatch; refusing to extract or execute")

work = Path("/kaggle/working/kt13_expand_repair_v1_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet_zip, "r") as zf:
    _safe_extract(zf, work)

runner = work / "KT13_EXPAND_REPAIR_V1_RUNNER.py"
if not runner.exists():
    matches = list(work.rglob("KT13_EXPAND_REPAIR_V1_RUNNER.py"))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one runner, found {len(matches)}")
    runner = matches[0]

namespace = {"__name__": "__kt_runner__"}
exec(compile(runner.read_text(encoding="utf-8"), str(runner), "exec"), namespace)
exit_code = int(namespace["main"]())
if exit_code != 0:
    raise RuntimeError(f"KT runner failed with exit code {exit_code}")
