from __future__ import annotations

import zipfile

from g32_test_utils import ROOT, load_json


def test_v13_packet_generated_with_no_scaffold_gate_and_head_binding() -> None:
    packet = ROOT / "packets/ktg3full_v13.zip"
    manifest = load_json("packets/ktg3full_v13/PACKET_MANIFEST.json")
    receipt = load_json("reports/v13_superlane_receipt.json")

    assert packet.exists()
    assert receipt["packet_sha256"]
    assert manifest["packet_build_head"] == receipt["current_head"]
    assert manifest["no_scaffold_runtime_gate_required"] is True
    assert manifest["router_superiority_claim_authorized"] is False
    assert manifest["adapter_promotion_authorized"] is False
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
    assert {"KTG3FULL_V13_RUNNER.py", "KAGGLE_BOOTSTRAP_CELL.py", "PACKET_MANIFEST.json"} <= names
