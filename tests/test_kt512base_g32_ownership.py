from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_kt512base_fixed512_failures_are_autopsied_and_unknowns_block_training() -> None:
    failures = load_jsonl("reports/kt512base_fixed512_failure_autopsy.jsonl")
    genome = load_json("reports/kt512base_failure_genome.json")
    decision = load_json("reports/kt512base_g32_ownership_decision_receipt.json")

    assert len(failures) == 16
    assert genome["fixed512_failure_count"] == 16
    assert genome["unknown_failure_rate"] > 0.10
    assert genome["status"] == "PASS_TRAINING_BLOCKED_UNKNOWN_RATE_HIGH"
    assert "UNKNOWN_BLOCKED" in genome["owner_counts"]
    assert decision["schema_id"] == "kt.g32_training_decision_receipt.v1"
    assert decision["status"] == "BLOCKED_TRAINING_DECISION_UNKNOWN_FAILURE_RATE_HIGH"
    assert decision["training_authority"] is False
    assert decision["next_lawful_move"] == "AUTHOR_G32_CAUSAL_OWNERSHIP_FOR_FIXED512_FAILURES_AND_NO_REGRET_SELECTOR_REPLAY_V1"


def test_kt512base_path_mapping_reuses_existing_g32_law_surfaces() -> None:
    mapping = load_json("reports/kt512g32_path_mapping.json")

    assert mapping["status"] == "PASS"
    substitutions = {row["requested_surface"]: row["used_existing_surface"] for row in mapping["substitutions"]}
    assert substitutions["schemas/kt.g32_training_decision_receipt.schema.json"] == "schemas/kt.g32_training_decision_receipt.schema.json"
    assert substitutions["schemas/kt.do_not_train_receipt.schema.json"] == "schemas/kt.do_not_train_receipt.schema.json"
