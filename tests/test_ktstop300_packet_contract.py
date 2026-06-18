from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_stop300_packet_shape_and_authority() -> None:
    with zipfile.ZipFile(ROOT / "packets/ktstop300_v1.zip") as zf:
        members = set(zf.namelist())
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop300_config.json").decode("utf-8-sig"))
    assert "runtime/KT_CANONICAL_RUNNER.py" in members
    assert "runtime/stop_fsm_v31.py" in members
    assert "runtime/reference_court_v31.py" in members
    assert manifest["run_mode"] == "RUN_KTSTOP_RUNTIME_STOP_PAIRED300_V1"
    assert manifest["kaggle_dataset_name"] == "ktstop300-v1"
    assert len(config["natural_rows"]) == 300
    assert len(config["timing_panel_rows"]) == 60
    assert manifest["sandbox_inference_authority"] is True
    assert manifest["runtime_authority"] is False
    assert manifest["shadow_runtime_authority"] is False


def test_stop300_packet_validator_receipt_passes() -> None:
    receipt = json.loads((ROOT / "reports/stop300_packet_validation_receipt.json").read_text(encoding="utf-8-sig"))
    assert receipt["status"] == "PASS"
    assert receipt["packet_sha256"]
    assert receipt["errors"] == []
