from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def assert_no_authority(payload: dict) -> None:
    assert payload["claim_ceiling_preserved"] is True
    assert payload["runtime_authority"] is False
    assert payload["promotion_authority"] is False
    assert payload["adapter_training_authorized"] is False
    assert payload["router_training_authorized"] is False
    assert payload["policy_optimization_authorized"] is False
    assert payload["learned_router_superiority_claim"] is False
    assert payload["v18_runtime_authority"] is False


def authority_report(name: str) -> dict:
    return read_json(f"reports/{name}")
