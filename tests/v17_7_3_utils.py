from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))


def read_jsonl(relative: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / relative).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def assert_no_authority(payload: dict) -> None:
    assert payload.get("claim_ceiling_preserved") is True
    assert payload.get("runtime_authority") is False
    assert payload.get("promotion_authority") is False
    assert payload.get("adapter_training_authorized") is False
    assert payload.get("learned_router_superiority_claim") is False
    assert payload.get("v18_runtime_authority") is False


def packet_names(relative: str) -> set[str]:
    with zipfile.ZipFile(ROOT / relative) as archive:
        return set(archive.namelist())
