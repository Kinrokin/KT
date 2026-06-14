from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_g32_next_lane_selects_exactly_one_budget_pareto_sweep() -> None:
    ledger = read_json("reports/g32_next_ledger.json")
    summary = read_json("reports/g32sel_builder_summary.json")

    selected = [
        lane
        for lane, disposition in ledger["candidate_lanes"].items()
        if isinstance(disposition, str) and disposition.startswith("SELECTED")
    ]
    assert selected == ["AUTHOR_BUDGET_PARETO_SWEEP_KAGGLE_V1"]
    assert ledger["selected_next_lawful_move"] == "AUTHOR_BUDGET_PARETO_SWEEP_KAGGLE_V1"
    assert summary["next_lawful_move"] == ledger["selected_next_lawful_move"]
    assert summary["runtime_authority"] is False
    assert summary["claim_ceiling_status"] == "PRESERVED"
