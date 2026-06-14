import json
import subprocess
import sys
import zipfile
from pathlib import Path

from ktpareto_helpers import ensure_ktpareto_built


ROOT = Path(__file__).resolve().parents[1]


def test_ktpareto_packet_generates_and_validates():
    ensure_ktpareto_built()
    result = subprocess.run(
        [sys.executable, "scripts/validate_ktpareto_packet.py"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    receipt = json.loads(result.stdout)
    assert receipt["status"] == "PASS"
    assert receipt["packet_path"] == "packets/ktpareto_v1.zip"


def test_ktpareto_packet_has_required_members():
    ensure_ktpareto_built()
    packet = ROOT / "packets" / "ktpareto_v1.zip"
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
    assert {
        "runtime/KT_CANONICAL_RUNNER.py",
        "KAGGLE_BOOTSTRAP_CELL.py",
        "COPY_PASTE_NOW_ktpareto_v1.txt",
        "PACKET_MANIFEST.json",
        "SHA256_MANIFEST.json",
        "README.md",
        "requirements.txt",
        "tests/smoke_test.py",
    } <= names
