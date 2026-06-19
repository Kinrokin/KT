import os
import subprocess
import sys
import zipfile
from pathlib import Path


def test_v4_bootstrap_smoke_from_unrelated_cwd(tmp_path):
    with zipfile.ZipFile(Path("packets/ktstop300_v4.zip")) as zf:
        zf.extractall(tmp_path / "packet")
    env = os.environ.copy()
    env.update({
        "KT_STOP300_BOOTSTRAP_SMOKE_ONLY": "1",
        "KT_STOP300_SKIP_DEP_INSTALL": "1",
        "KT_AUTHORIZED_PACKET_SHA256": "test",
        "KT_AUTHORIZED_PACKET_SUBJECT_HEAD": "subject",
        "KT_CURRENT_MAIN_HEAD": "current",
        "KT_EXPECTED_RUN_MODE": "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V4",
    })
    other = tmp_path / "other"
    other.mkdir()
    proc = subprocess.run([sys.executable, str(tmp_path / "packet" / "KAGGLE_BOOTSTRAP_CELL.py")], cwd=other, env=env, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
