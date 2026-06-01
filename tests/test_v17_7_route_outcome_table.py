from __future__ import annotations

from pathlib import Path

from scripts.v17_7_oats_sddr_common import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_route_outcome_table_is_measured_and_row_level() -> None:
    rows = read_jsonl(ROOT / "admission" / "v17_7_route_outcome_table.jsonl")
    assert len(rows) == 260
    assert {row["schema_id"] for row in rows} == {"kt.v17_7.route_outcome_row.v1"}
    assert all(row["claim_ceiling_preserved"] is True for row in rows)
    assert all(row["oracle_correctness_used_as_input_feature"] is False for row in rows)
    assert len({row["sample_id"] for row in rows}) == 260
    assert {row["v17_7_route"] for row in rows} >= {
        "base_raw",
        "formal_math_repair_adapter_global",
        "route_regret_policy_adapter_global",
    }
