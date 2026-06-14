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


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_kt512base_economy_seed_excludes_forbidden_selection_features() -> None:
    rows = load_jsonl("reports/kt512base_economy_classifier_seed.jsonl")

    assert len(rows) == 200
    assert any(row["label"] == "COT512_INSUFFICIENT" for row in rows)
    for row in rows:
        assert row["row_id_role"] == "identifier_not_selection_feature"
        assert FORBIDDEN.isdisjoint(row["selection_features"].keys())
        assert set(row["forbidden_features_excluded"]) == FORBIDDEN
        assert row["training_authority"] is False


def test_kt512base_no_regret_policy_has_negative_class_and_regret_accounting() -> None:
    policy = load_json("reports/kt512base_no_regret_selector_seed_policy.json")
    regret = load_json("reports/kt512base_regret_distribution.json")

    assert policy["status"] == "SEED_ONLY_NO_RUNTIME_AUTHORITY"
    assert policy["default_arm"] == "A0_COT_512_FIXED_PRIMARY"
    assert policy["negative_class"] == "COT512_INSUFFICIENT"
    assert policy["runtime_authority"] is False
    assert regret["negative_class"]["class_id"] == "COT512_INSUFFICIENT"
    assert regret["negative_class"]["required"] is True
    for downshift in regret["downshift_classes"]:
        assert "false_downshift_count" in downshift
        assert "false_downshift_damage" in downshift
        assert "regret_vs_fixed512" in downshift
        assert "token_savings_when_correct" in downshift
        assert "net_expected_value" in downshift
        assert downshift["advance_allowed"] is False
        assert downshift["expected_regret_bounded"] is False
