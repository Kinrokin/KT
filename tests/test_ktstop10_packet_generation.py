from __future__ import annotations

import json
import zipfile
from pathlib import Path


def test_ktstop10_packet_generated_with_required_shape() -> None:
    packet = Path("packets/ktstop10_v1.zip")
    assert packet.exists()
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        assert {
            "KAGGLE_BOOTSTRAP_CELL.py",
            "runtime/KT_CANONICAL_RUNNER.py",
            "runtime/ktstop10_config.json",
            "requirements.txt",
            "tests/smoke_test.py",
            "PACKET_MANIFEST.json",
            "SHA256_MANIFEST.json",
            "README.md",
            "COPY_PASTE_NOW_ktstop10_v1.txt",
        } <= names
        manifest = json.loads(zf.read("PACKET_MANIFEST.json"))
    assert manifest["run_mode"] == "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1"
    assert manifest["kaggle_dataset_name"] == "ktstop10-v1"
    assert manifest["training_authority"] is False
