from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_5_runtime_packet_exact_name_and_fail_closed_contract():
    receipt = json.loads((ROOT / "reports/v17_5_runtime_packet_readiness_receipt.json").read_text(encoding="utf-8"))
    packet = ROOT / receipt["packet_path"]
    assert packet.name == "ktg3full_v17_5_multirescuer_e2e_v1.zip"
    assert packet.exists()
    assert receipt["packet_sha256"]
    with zipfile.ZipFile(packet) as archive:
        names = set(archive.namelist())
        runner = archive.read("KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py").decode("utf-8")
    assert {"KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py", "V17_5_MULTIRESCUER_POLICY_CONFIG.json", "PACKET_MANIFEST.json", "ONE_CELL.md"}.issubset(names)
    assert "missing non-empty measured benchmark_predictions.jsonl" in runner
    assert "synthetic rows are forbidden in real evidence mode" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in runner
    assert "ASSESSMENT_ONLY.zip" in runner
