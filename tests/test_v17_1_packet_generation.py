from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v17_1_packet_exact_name_and_runtime_contract():
    receipt = json.loads((ROOT / "reports/v17_1_packet_readiness_receipt.json").read_text(encoding="utf-8"))
    packet = ROOT / receipt["packet_path"]
    assert packet.name == "ktg3full_v17_e2e_v1_2.zip"
    assert packet.exists()
    assert receipt["packet_sha256"]
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        assert {"KTG3FULL_V17_E2E_V1_2_RUNNER.py", "V17_1_CANARY_POLICY_CONFIG.json", "PACKET_MANIFEST.json", "ONE_CELL.md"}.issubset(names)
        runner = zf.read("KTG3FULL_V17_E2E_V1_2_RUNNER.py").decode("utf-8")
    assert "json_safe" in runner
    assert "ASSESSMENT_ONLY.zip" in runner
    assert "PARTIAL_MEASURED_OUTPUTS.zip" in runner
