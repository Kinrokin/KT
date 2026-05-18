from __future__ import annotations

from tools.operator import highway_common as highway


def test_highway_authority_gate_blocks_activation_while_external_attestation_missing(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["mode"] == "PREP_ONLY"
    assert receipt["activation_allowed"] is False
    assert receipt["truth_lock_replay_canonical"] is True
    assert receipt["reason"] == highway.EXTERNAL_ATTESTATION_BLOCKER


def test_highway_authority_gate_keeps_canonical_promotion_blocked(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["truth_lock_validation_authorized"] is True
    assert highway.HIGHWAY_CANONICAL_PROMOTION_BLOCKER in receipt["blockers"]


def test_highway_authority_gate_reflects_detached_verifier_advanced(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["detached_verifier_authorized"] is True
    assert highway.DETACHED_VERIFIER_BLOCKER not in receipt["blockers"]


def test_highway_authority_gate_blocks_fp0_activation_while_prep_only(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["fp0_authority"] == "PREP_ONLY_NO_CLAIM_EXPANSION"
    assert highway.FP0_BLOCKER in receipt["blockers"]
