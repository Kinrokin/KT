import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def test_v3_bootstrap_subprocess_from_unrelated_cwd():
    packet = Path("packets/ktstop300_v3.zip")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "packet"
        other = Path(td) / "other"
        root.mkdir()
        other.mkdir()
        with zipfile.ZipFile(packet) as zf:
            zf.extractall(root)
        env = os.environ.copy()
        env["KT_STOP300_BOOTSTRAP_SMOKE_ONLY"] = "1"
        env["KT_AUTHORIZED_PACKET_SHA256"] = "test_sha"
        env["KT_AUTHORIZED_MERGE_HEAD"] = "test_head"
        result = subprocess.run([sys.executable, str(root / "KAGGLE_BOOTSTRAP_CELL.py")], cwd=other, env=env, text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stderr
