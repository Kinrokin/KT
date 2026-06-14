from __future__ import annotations

import json
from pathlib import Path


def read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_g32_training_decision_stays_blocked_by_unknown_rate() -> None:
    owner = read_json("reports/g32_owner_receipt.json")
    train = read_json("reports/g32_train_decision.json")

    assert owner["unknown_failure_rate"] > 0.10
    assert owner["training_authority"] is False
    assert train["action"] == "NO_TRAIN"
    assert train["status"] == "BLOCKED_TRAINING_DECISION_UNKNOWN_FAILURE_RATE_HIGH"
    assert train["minimum_viable_signal"]["pass"] is False
    assert train["training_authority"] is False


def test_g32_do_not_train_rows_cover_fixed512_failures() -> None:
    failures = read_jsonl("reports/g32_failure_genome.jsonl")
    receipts = read_jsonl("reports/g32_do_not_train.jsonl")

    assert len(failures) == 16
    assert len(receipts) == len(failures)
    assert all(row["training_authority"] is False for row in receipts)
