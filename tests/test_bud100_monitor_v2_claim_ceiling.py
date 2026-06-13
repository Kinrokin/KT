from __future__ import annotations

import json
from pathlib import Path


def test_bud100_monitor_v2_claim_ceiling_and_authorities() -> None:
    summary = json.loads(Path("reports/bud100_v2_review_builder_summary.json").read_text(encoding="utf-8"))

    assert summary["outcome"] == (
        "KT_BUD100_ADAPTIVE_MONITOR_V2_POLICY_REPAIRED__"
        "V2_OFFLINE_REPLAY_NO_GAIN__FIXED512_BASELINE_RETAINED__CLAIM_CEILING_PRESERVED"
    )
    assert summary["bud100_v2_truth_binding_status"] == "PASS"
    assert summary["bud100_v2_input_artifacts_status"] == "PASS"
    assert summary["bud100_v2_offline_replay_status"] == "PASS_NO_GAIN_FIXED512_RETAINED"
    assert summary["bud100_v2_vs_fixed512_status"] == "PASS_FIXED512_BASELINE_RETAINED"
    assert summary["adaptive_monitor_v2_verdict"] == "NO_DEPLOYABLE_OFFLINE_GAIN_FIXED512_RETAINED"
    assert summary["packet_path_if_any"] is None
    assert summary["runtime_authority"] is False
    assert summary["dataset_generation_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["production_prompt_mutation_authority"] is False
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["next_lawful_move"] == "AUTHOR_BUD100_FIXED512_MATH_MODE_BASELINE_REPLAY_V1"
