from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop50_packet_shape_and_manifest() -> None:
    with zipfile.ZipFile(ROOT / "packets/ktstop50_v1.zip") as zf:
        members = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
    assert "runtime/KT_CANONICAL_RUNNER.py" in members
    assert "KAGGLE_BOOTSTRAP_CELL.py" in members
    assert manifest["run_mode"] == "RUN_STOPSEQ_RUNTIME_STOP_CRITERIA_50ROW_V1"
    assert manifest["kaggle_dataset_name"] == "ktstop50-v1"
    assert manifest["row_count"] == 50
    assert manifest["runtime_authority"] is False
