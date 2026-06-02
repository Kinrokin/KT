from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_truegen_row_manifest_is_v1773_decision_bound() -> None:
    manifest = json.loads((ROOT / "admission" / "v17_7_4_truegen_row_manifest.json").read_text())
    assert manifest["row_count"] == 100
    assert manifest["selection_source"] == "V17.7.3 authority decision needs"
    for row in manifest["rows"]:
        assert row["schema_id"] == "kt.v17_7_4.truegen_row.v1"
        assert row["prompt_hash"]
        assert row["source_replay_reference_if_any"]["source_seed_sample_id"]
        assert row["label_source"] == "SOURCE_SEED_SAMPLE_ID_DIAGNOSTIC_LABEL"
        assert row["claim_ceiling_preserved"] is True
        assert row["promotion_authority"] is False
