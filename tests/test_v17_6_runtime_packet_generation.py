from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_6_runtime_packet_is_short_lean_and_fail_closed():
    receipt = json.loads((ROOT / "reports/v17_6_runtime_packet_generation_receipt.json").read_text(encoding="utf-8"))
    packet = ROOT / receipt["packet_path"]
    assert packet.name == "ktv176_e2e_v1.zip"
    assert packet.exists()
    assert receipt["kaggle_dataset_name"] == "ktv176-e2e-v1"
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        runner = archive.read("KTG3FULL_V17_6_ORACLE_AUTOPSY_E2E_V1_RUNNER.py").decode("utf-8")
    assert {
        "KTG3FULL_V17_6_ORACLE_AUTOPSY_E2E_V1_RUNNER.py",
        "V17_6_ORACLE_AUTOPSY_PATCHED_POLICY.json",
        "V17_6_LEAN_PACKAGING_CONTRACT.json",
        "PACKET_MANIFEST.json",
        "ONE_CELL.md",
    }.issubset(names)
    assert "missing non-empty measured benchmark_predictions.jsonl" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in runner
    assert "ASSESSMENT_ONLY.zip" in runner
    assert "KAGGLE_E2E_BLOCKED__LOW_DISK_AFTER_MEASURED_ROWS" in runner
