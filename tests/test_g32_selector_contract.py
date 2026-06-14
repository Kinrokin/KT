from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_g32_no_regret_selector_contract_is_replay_only() -> None:
    policy = read_json("policies/g32_noregret_v1.json")

    assert policy["policy_id"] == "KT_NO_REGRET_SELECTOR_V1"
    assert policy["baseline"] == "FIXED512"
    assert policy["correctness_floor"] == 0.92
    assert policy["false_downshift_tolerance"] == 0
    assert policy["max_regret_absolute"] == 0.0
    assert policy["uncertainty_action"] == "DEFAULT_TO_COT512"
    assert policy["required_negative_class"] == "COT512_INSUFFICIENT"
    assert policy["status"] == "REPLAY_ONLY_NO_RUNTIME_AUTHORITY"
    assert policy["runtime_authority"] is False


def test_g32_selector_replay_blocks_unsafe_downshifts() -> None:
    replay = read_json("reports/g32_selector_replay.json")
    regret = read_json("reports/g32_regret_dist.json")

    assert replay["status"] == "PASS_REPLAY_DEPLOYMENT_BLOCKED_FALSE_DOWNSHIFT"
    assert replay["deployment_gate"] == "BLOCKED"
    assert regret["negative_class"]["class_id"] == "COT512_INSUFFICIENT"
    assert all(row["false_downshift_count"] >= 0 for row in regret["downshift_classes"])
    assert any(row["false_downshift_count"] > 0 for row in regret["downshift_classes"])
