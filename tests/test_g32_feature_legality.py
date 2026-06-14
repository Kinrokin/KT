from __future__ import annotations

import json
from pathlib import Path


FORBIDDEN = {
    "expected_answer",
    "row_id",
    "measured_arm_correctness",
    "measured_correctness_any_arm",
    "hindsight_label",
    "posthoc_correctness",
    "post_hoc_token_count",
}


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_g32_feature_law_forbids_leakage_features() -> None:
    law = read_json("reports/g32_feature_law.json")
    policy = read_json("policies/g32_noregret_v1.json")

    assert law["status"] == "PASS"
    assert set(law["forbidden"]) == FORBIDDEN
    assert set(policy["feature_legality"]["forbidden"]) == FORBIDDEN


def test_g32_economy_seed_does_not_use_forbidden_features_for_selection() -> None:
    rows = read_jsonl("reports/kt512base_economy_classifier_seed.jsonl")

    assert rows
    for row in rows:
        assert FORBIDDEN.isdisjoint(row["selection_features"].keys())
        assert set(row["forbidden_features_excluded"]) == FORBIDDEN
