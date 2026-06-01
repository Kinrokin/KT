from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v17_1_policy_config_has_thresholds_and_blockers():
    config = json.loads((ROOT / "admission/v17_1_canary_policy_config.json").read_text(encoding="utf-8"))
    thresholds = config["route_confidence_thresholds"]
    assert thresholds["formal_math_repair_adapter_global"]["min_margin_over_base"] == 0.10
    assert thresholds["base_kt_hat_compact"]["min_margin_over_base"] == 0.12
    assert thresholds["route_regret_policy_adapter_global"]["min_margin_over_base"] == 0.08
    assert config["pass_blocks"]["BPR_lt_0_95"] is True
    assert config["pass_blocks"]["OCR_lte_0_363636"] is True
    assert config["claim_ceiling_preserved"] is True
