from __future__ import annotations

from tools.operator import highway_common as highway


def test_highway_authority_gate_blocks_activation_while_pr200_not_canonical(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["mode"] == "PREP_ONLY"
    assert receipt["activation_allowed"] is False
    assert receipt["truth_lock_replay_canonical"] is False
    assert receipt["reason"] == highway.PR200_BLOCKER


def test_highway_authority_gate_blocks_truth_lock_validation_while_not_authorized(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["truth_lock_validation_authorized"] is False
    assert highway.TRUTH_LOCK_VALIDATION_BLOCKER in receipt["blockers"]


def test_highway_authority_gate_blocks_detached_verifier_while_not_authorized(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["detached_verifier_authorized"] is False
    assert highway.DETACHED_VERIFIER_BLOCKER in receipt["blockers"]


def test_highway_authority_gate_blocks_fp0_activation_while_prep_only(tmp_path):
    receipt = highway.write_authority_gate_receipt(tmp_path)
    assert receipt["fp0_authority"] == "PREP_ONLY_QUEUED_NONAUTHORITATIVE"
    assert highway.FP0_BLOCKER in receipt["blockers"]
