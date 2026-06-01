from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_WHY = {
    "feature_missing",
    "weight_wrong",
    "margin_blocked",
    "rescuer_not_admitted",
    "base_preservation_overrode",
    "route_overdominance",
    "benchmark_artifact",
    "unknown_blocked",
}
ALLOWED_PATCH = {
    "increase_route_regret_prior",
    "decrease_route_regret_prior",
    "admit_hat_on_signal",
    "admit_math_act_on_signal",
    "lower_margin_for_route",
    "raise_margin_for_route",
    "add_runtime_feature",
    "fallback_base",
    "quarantine_sample",
    "unknown_blocked",
}


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_v17_5_remaining_oracle_gap_autopsy_has_26_row_level_records():
    summary = json.loads((ROOT / "reports/v17_5_remaining_oracle_gap_summary.json").read_text(encoding="utf-8"))
    rows = _jsonl(ROOT / "admission/v17_5_remaining_oracle_gap_autopsy.jsonl")
    assert summary["status"] == "PASS"
    assert summary["oracle_gap_rows"] == 26
    assert len(rows) == 26
    required = {
        "sample_id",
        "dataset",
        "slice",
        "canary_route",
        "canary_correct",
        "oracle_route",
        "oracle_correct",
        "oracle_rescuer",
        "base_correct",
        "all_arm_correctness",
        "pre_generation_features",
        "why_canary_missed",
        "next_policy_patch",
        "repair_surface",
        "claim_relevance",
    }
    for row in rows:
        assert required.issubset(row)
        assert row["why_canary_missed"] in ALLOWED_WHY
        assert row["next_policy_patch"] in ALLOWED_PATCH
        assert row["oracle_correctness_used_as_feature"] is False
