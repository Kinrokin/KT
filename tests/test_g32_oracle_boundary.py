from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_g32_oracle_frontier_is_not_deployable() -> None:
    oracle = read_json("reports/g32_oracle_frontier.json")
    boot = read_json("reports/g32_oracle_boot.json")

    assert oracle["authority"] == "HINDSIGHT_ONLY_NOT_DEPLOYABLE"
    assert oracle["runtime_selector_claim"] == "BLOCKED"
    assert oracle["selector_deployment_authority"] is False
    assert boot["claim_boundary"] == "HINDSIGHT_ONLY_NOT_DEPLOYABLE"
    assert boot["bootstrap_n"] >= 1000


def test_g32_process_verifier_is_design_only() -> None:
    procver = read_json("reports/g32_procver_spec.json")

    assert procver["status"] == "DESIGN_ONLY_REQUIRES_SEPARATE_VERIFIER_VALIDATION_LANE"
    assert procver["production_scoring_authority"] is False
    assert procver["training_authority"] is False
    assert {"ARITHMETIC_VALID", "UNIT_CONSISTENT", "LOGICAL_FOLLOW", "NO_CONTRADICTION", "FINAL_MATCH"}.issubset(
        set(procver["step_validity_labels"])
    )
