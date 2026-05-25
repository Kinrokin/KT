from __future__ import annotations

import hashlib
import os
from pathlib import Path
import zipfile


def _packet_zip() -> Path:
    override = os.environ.get("KT_PACKET_ZIP_PATH", "").strip()
    if override:
        packet = Path(override)
        if not packet.exists():
            raise FileNotFoundError(f"KT_PACKET_ZIP_PATH not found: {packet}")
        return packet
    candidates = sorted(Path("/kaggle/input").rglob("ktg3_run_v1.zip"))
    if not candidates:
        raise FileNotFoundError("ktg3_run_v1.zip not found under /kaggle/input")
    if len(candidates) > 1:
        rendered = ", ".join(str(path) for path in candidates)
        raise RuntimeError(f"Multiple candidate packets found; set KT_PACKET_ZIP_PATH: {rendered}")
    return candidates[0]


def _verify_sha256(path: Path) -> None:
    expected = os.environ.get("KT_PACKET_SHA256", "").strip().lower()
    if not expected:
        return
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f"KT_PACKET_SHA256 mismatch: expected {expected}, got {actual}")


def _safe_extract(packet: Path, work: Path) -> None:
    root = work.resolve()
    with zipfile.ZipFile(packet) as zf:
        for member in zf.namelist():
            target = (root / member).resolve()
            if not (target == root or root in target.parents):
                raise RuntimeError(f"Unsafe zip member path: {member}")
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(member))


packet_zip = _packet_zip()
_verify_sha256(packet_zip)
work = Path("/kaggle/working/ktg3_run_v1")
work.mkdir(parents=True, exist_ok=True)
_safe_extract(packet_zip, work)
exec((work / "KTG3_TARGETED_REPAIR_RUNNER.py").read_text(encoding="utf-8"), {"__name__": "__main__"})
