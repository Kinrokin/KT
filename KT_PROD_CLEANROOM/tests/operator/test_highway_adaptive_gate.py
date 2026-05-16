from __future__ import annotations

from tools.operator import highway_common as highway


def test_adaptive_gate_blocks_fp0_activation_before_authority(tmp_path):
    receipt = highway.adaptive_gate("FP0_HIGHWAY_ACTIVE", tmp_path)
    assert "BLOCK_FP0_PREP_ONLY" in receipt["blockers"]
    assert receipt["status"] == "BLOCKED"


def test_adaptive_gate_blocks_router_order_violation(tmp_path):
    receipt = highway.adaptive_gate("LEARNED_ROUTER_ACTIVE", tmp_path)
    assert "BLOCK_ROUTER_ORDER_VIOLATION" in receipt["blockers"]
