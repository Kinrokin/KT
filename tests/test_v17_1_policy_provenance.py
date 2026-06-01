from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_policy_provenance_distinguishes_repaired_reference_from_v16_replay():
    receipt = json.loads((ROOT / "reports/v17_1_canary_policy_provenance_receipt.json").read_text(encoding="utf-8"))
    assert receipt["policy_source"] == "REPAIRED_REFERENCE_POLICY"
    assert receipt["v16_policy_artifact_path"] == "admission/v16_shadow_route_policy.json"
    assert receipt["v16_policy_sha256"]
    assert receipt["policy_imported_from_repo"] is True
    assert receipt["claim_authority"] == "NONE"
    assert receipt["runtime_authority"] is False
