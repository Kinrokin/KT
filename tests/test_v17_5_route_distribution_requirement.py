from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_runtime_packet_blocks_degenerate_route_distribution():
    policy = json.loads((ROOT / "admission/v17_5_multirescuer_canary_policy_config.json").read_text(encoding="utf-8"))
    packet = ROOT / "packets/ktg3full_v17_5_multirescuer_e2e_v1.zip"
    with zipfile.ZipFile(packet) as archive:
        runner = archive.read("KTG3FULL_V17_5_MULTIRESCUER_E2E_V1_RUNNER.py").decode("utf-8")
    assert policy["minimum_route_distribution"]["degenerate_fallback_blocked"] is True
    assert "route distribution uses fewer than 3 candidate routes" in runner
    assert "KT_MIN_CANARY_ROUTE_DECISIONS" in json.dumps(policy)
