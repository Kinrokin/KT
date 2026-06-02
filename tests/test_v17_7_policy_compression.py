from __future__ import annotations

from pathlib import Path

from scripts.v17_7_1_mhm_common import read_json


ROOT = Path(__file__).resolve().parents[1]


def test_v17_7_policy_compression_is_targeted_replay_pending_only() -> None:
    policy = read_json(ROOT / "admission" / "v17_7_1_compressed_candidate_policy.json")
    receipt = read_json(ROOT / "reports" / "v17_7_1_policy_compression_receipt.json")
    assert policy["runtime_authority"] is False
    assert policy["promotion_authority"] is False
    assert policy["claim_authority"] == "TARGETED_REPLAY_PENDING"
    assert receipt["compression_status"] == "READY_FOR_TARGETED_REPLAY_DESIGN_ONLY"
