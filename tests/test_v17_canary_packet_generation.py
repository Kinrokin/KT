from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_v17_packet_exact_name_hash_members_and_fail_closed_runner():
    receipt = json.loads((ROOT / "reports/v17_canary_packet_readiness_receipt.json").read_text(encoding="utf-8"))
    packet = ROOT / receipt["packet_path"]
    assert packet.name == "ktg3full_v17_canary_route_value.zip"
    assert packet.exists()
    assert receipt["packet_sha256"]
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        assert {
            "KTG3FULL_V17_CANARY_RUNNER.py",
            "V17_CANARY_POLICY_CONFIG.json",
            "V17_RUNTIME_FEATURE_CONTRACT.json",
            "PACKET_MANIFEST.json",
            "ONE_CELL.md",
        }.issubset(names)
        runner = zf.read("KTG3FULL_V17_CANARY_RUNNER.py").decode("utf-8")
    assert "missing non-empty benchmark_predictions.jsonl" in runner
    assert "raise SystemExit(2)" in runner
    assert receipt["runtime_authority"] is False
    assert receipt["promotion_authority"] is False
    assert receipt["claim_ceiling_preserved"] is True
