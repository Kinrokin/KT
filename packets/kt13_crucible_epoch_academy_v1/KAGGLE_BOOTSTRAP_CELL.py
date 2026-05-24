# KT13 Crucible/Epoch/Academy V1 one-cell Kaggle bootstrap.
# This is a bounded pressure-curriculum evaluation packet, not a training or promotion packet.
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

PACKET_NAME = "kt13_crucible_epoch_academy_v1.zip"
WORK_DIR = Path(os.environ.get("KT_ACADEMY_PACKET_WORK_DIR", "/kaggle/working/kt13_crucible_epoch_academy_v1_packet"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract(zf, target):
    root = target.resolve()
    for member in zf.infolist():
        dest = (root / member.filename).resolve()
        if root != dest and root not in dest.parents:
            raise RuntimeError(f"Unsafe zip member path: {member.filename}")
    zf.extractall(root)


explicit = os.environ.get("KT_ACADEMY_PACKET_ZIP_PATH")
if explicit:
    candidates = [Path(explicit)]
else:
    candidates = list(Path("/kaggle/input").glob(f"*/{PACKET_NAME}")) + list(Path("/kaggle/working").glob(PACKET_NAME)) + [Path(PACKET_NAME)]

existing = [candidate for candidate in candidates if candidate.exists()]
if len(existing) > 1:
    raise RuntimeError(f"Multiple Academy packets found; set KT_ACADEMY_PACKET_ZIP_PATH explicitly: {[str(p) for p in existing]}")
if not existing:
    raise FileNotFoundError(f"Could not find {PACKET_NAME} in /kaggle/input, /kaggle/working, or current directory")

packet_zip = existing[0]
expected_sha = os.environ.get("KT_ACADEMY_PACKET_SHA256")
actual_sha = sha256(packet_zip)
if expected_sha and actual_sha.lower() != expected_sha.lower():
    raise RuntimeError("Academy packet sha256 mismatch; refusing to extract or execute")

WORK_DIR.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet_zip, "r") as zf:
    safe_extract(zf, WORK_DIR)

runner = WORK_DIR / "packets" / "kt13_crucible_epoch_academy_v1" / "KT13_CRUCIBLE_EPOCH_ACADEMY_V1_RUNNER.py"
if not runner.exists():
    matches = list(WORK_DIR.rglob("KT13_CRUCIBLE_EPOCH_ACADEMY_V1_RUNNER.py"))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one Academy runner, found {len(matches)}")
    runner = matches[0]

subprocess.check_call([sys.executable, str(runner)], cwd=WORK_DIR)
print(json.dumps({
    "status": "PASS",
    "packet_sha256": actual_sha,
    "outcome": "KT_CRUCIBLE_EPOCH_ACADEMY_PRESSURE_CURRICULUM_BOUND__TARGETED_REPAIR_PRESSURE_NEXT"
}, indent=2))
