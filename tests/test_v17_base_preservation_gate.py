from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_base_preservation_repair_passes_threshold_without_claim_expansion():
    receipt = json.loads((ROOT / "reports/v17_1_base_preservation_policy_receipt.json").read_text(encoding="utf-8"))
    config = json.loads((ROOT / "admission/v17_1_canary_policy_config.json").read_text(encoding="utf-8"))
    assert receipt["BPR"] >= receipt["minimum_required"] == 0.95
    assert config["no_override_base_protection"] is True
    assert config["base_preservation_epsilon"] == 0.08
    assert config["runtime_authority"] is False
