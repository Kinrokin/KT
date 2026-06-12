from __future__ import annotations

from scripts import ktbud100_common as bud


def test_bud_lane_never_grants_training_or_promotion() -> None:
    summary = bud.read_json(bud.REPORTS / "bud100_builder_summary.json")

    for key in bud.AUTHORITY_FALSE:
        assert summary[key] is False
    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["next_lawful_move"] == "RUN_KT_BUDGET_MONITOR_GSM8K_100"
