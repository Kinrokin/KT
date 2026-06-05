from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_13_lobe_targets_remain_trainable_specialists() -> None:
    registry = json.loads((ROOT / "adaptive" / "cognitive_lobe_registry.json").read_text(encoding="utf-8"))
    entries = registry.get("lobes") or registry.get("entries") or registry
    rows = list(entries.values()) if isinstance(entries, dict) else list(entries)
    assert len(rows) == 13
    for row in rows:
        assert row["canonical_lobe"] is True
        assert row["training_target"] is True
        assert row["gate_or_court"] is False
