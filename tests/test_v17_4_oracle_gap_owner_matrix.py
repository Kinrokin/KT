from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_oracle_gap_owner_matrix_covers_remaining_gap_and_rescuer_surfaces():
    report = json.loads((ROOT / "reports/v17_4_oracle_gap_owner_matrix.json").read_text(encoding="utf-8"))
    rows = [
        json.loads(line)
        for line in (ROOT / "admission/v17_4_oracle_gap_owner_matrix.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert report["oracle_gap_rows"] == 28
    assert len(rows) == 28
    assert set(report["candidate_repair_surface_counts"]).issuperset({"HAT_SALVAGE_CANDIDATE", "ROUTE_REGRET_CANDIDATE"})
    assert all(row["oracle_correct"] is True and row["current_canary_correct"] is False for row in rows)
    assert all(row["oracle_correctness_used_as_feature"] is False for row in rows)
