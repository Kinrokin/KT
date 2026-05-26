from __future__ import annotations

from g32_test_utils import load_json, read_jsonl


def test_route_regret_matrix_uses_outcome_utility_contract() -> None:
    matrix = load_json("reports/route_regret_matrix.json")
    rows = read_jsonl("reports/route_regret_matrix.jsonl")

    assert "1.0*correct" in matrix["utility_formula"]
    assert "- 0.20*normalized_tokens" in matrix["utility_formula"]
    assert matrix["router_superiority_claimed"] is False
    assert rows
    assert {"chosen_route", "candidate_routes", "best_route", "route_regret", "oracle_best_route", "route_regret_closure"}.issubset(rows[0])
