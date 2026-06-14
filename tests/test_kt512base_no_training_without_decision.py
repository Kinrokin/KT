from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def test_kt512base_do_not_train_receipts_cover_fixed512_failures() -> None:
    receipts = load_jsonl("reports/kt512base_do_not_train_receipts.jsonl")

    assert len(receipts) == 16
    assert {receipt["forbidden_action"] for receipt in receipts} == {"TRAIN_ADAPTER"}
    assert all(receipt["claim_ceiling_preserved"] is True for receipt in receipts)
    assert any(receipt["counterfactual_owner"] == "UNKNOWN_BLOCKED" for receipt in receipts)


def test_kt512base_summary_keeps_all_authorities_false() -> None:
    summary = load_json("reports/kt512g32_builder_summary.json")

    assert summary["outcome"] == (
        "KT_512BASE_IMPORTED__FIXED512_STRONG_BASELINE_CONFIRMED__"
        "G32_MINING_READY__NO_REGRET_SELECTOR_SEED_NEXT__CLAIM_CEILING_PRESERVED"
    )
    assert summary["runtime_authority"] is False
    assert summary["dataset_generation_authority"] is False
    assert summary["training_authority"] is False
    assert summary["promotion_authority"] is False
    assert summary["adapter_mutation_authority"] is False
    assert summary["production_prompt_mutation_authority"] is False
    assert summary["claim_ceiling_status"] == "PRESERVED"
