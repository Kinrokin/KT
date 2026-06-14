from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_kt512base_claim_boundary_blocks_overclaims() -> None:
    claim = load_json("reports/kt512base_claim_boundary_receipt.json")

    assert claim["status"] == "PASS"
    assert "repo-side G3.2 mining/no-regret selector seed work only" in claim["allowed_internal_claim"]
    assert "production_math_mode_ready" in claim["forbidden_claims"]
    assert "router_superiority" in claim["forbidden_claims"]
    assert claim["runtime_authority"] is False
    assert claim["training_authority"] is False
    assert claim["promotion_authority"] is False
    assert claim["claim_ceiling_preserved"] is True


def test_kt512base_selected_exactly_one_next_lane() -> None:
    summary = load_json("reports/kt512g32_builder_summary.json")

    assert summary["next_lawful_move"] == "AUTHOR_G32_CAUSAL_OWNERSHIP_FOR_FIXED512_FAILURES_AND_NO_REGRET_SELECTOR_REPLAY_V1"
    assert summary["packet_path_if_any"] is None
    assert summary["kaggle_dataset_name_if_any"] is None
    assert summary["blockers"] == []
