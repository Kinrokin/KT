from __future__ import annotations

from g32_test_utils import load_json, read_jsonl


def test_g32s_authority_flags_are_false() -> None:
    summary = load_json("reports/g32s_builder_summary.json")
    next_lane = load_json("reports/g32s_next_lane_decision.json")
    micro = load_json("reports/g32s_next_microfurnace_spec.json")

    for payload in [summary, next_lane, micro]:
        assert payload["training_authority"] is False
        assert payload["promotion_authority"] is False
        assert payload["selector_deployment_authority"] is False
        assert payload["runtime_authority"] is False
        assert payload["claim_ceiling_status"] == "PRESERVED"


def test_g32s_counts_bind_pareto_assessment() -> None:
    summary = load_json("reports/g32s_builder_summary.json")

    assert summary["counts"]["row_count"] == 100
    assert summary["counts"]["fixed512_failures"] == 18
    assert summary["counts"]["no_correct_arm_rows"] == 14
    assert summary["counts"]["false384_rows"] == 7
    assert summary["counts"]["cot640_recovery_rows"] == 4
    assert summary["counts"]["cot640_damage_rows"] == 2


def test_g32s_no_correct_rows_are_counterfactual_not_training_fuel() -> None:
    rows = read_jsonl("reports/g32s_no_correct_counterfactual_matrix.jsonl")

    assert len(rows) == 14
    assert all(row["repair_owner_candidate"] == "UNKNOWN_BLOCKED" for row in rows)
    assert all(row["human_anchor_required"] is True for row in rows)
    assert all(row["training_authority"] is False for row in rows)

