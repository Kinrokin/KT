import json
from pathlib import Path


def test_v2_authoritative_freshness_zero_overlap():
    registry = json.loads(Path("registry/gsm8k_row_authority_registry.json").read_text(encoding="utf-8-sig"))
    receipt = json.loads(Path("reports/stop300_v2_freshness_receipt.json").read_text(encoding="utf-8-sig"))
    manifest = json.loads(Path("admission/stop300_v2_stratified_hash_selected_manifest.json").read_text(encoding="utf-8-sig"))
    selected = {row["row_id"] for row in manifest["rows"]}
    consumed = set(registry["authoritative_consumed_rows"])
    assert receipt["status"] == "PASS_300_UNIQUE_ZERO_AUTHORITY_OVERLAP"
    assert receipt["overlap_count"] == 0
    assert len(selected) == 300
    assert selected.isdisjoint(consumed)
