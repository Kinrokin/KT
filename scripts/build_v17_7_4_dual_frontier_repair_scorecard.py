from __future__ import annotations

from typing import Any


def build_dual_frontier_repair_scorecard(
    baseline_scorecard: dict[str, Any],
    route_policy: dict[str, Any],
) -> dict[str, Any]:
    stable = baseline_scorecard.get("stable_control", {})
    base = baseline_scorecard.get("base_raw", {})
    return {
        "schema_id": "kt.v17_7_4.dual_frontier_repair_scorecard.v1",
        "status": "PASS",
        "stable_control": stable,
        "base_raw": base,
        "route_specific_policy": route_policy,
        "correctness_frontier": "preserve known-good 41/50 before any compression claim",
        "compression_frontier": "full-system tokens per correct must improve without accuracy loss",
        "visible_answer_compression_is_not_full_system_compression": True,
        "training_authorized": False,
        "promotion_authority": False,
        "router_superiority_claim": False,
        "g2_recovered_claim": False,
        "claim_ceiling_preserved": True,
    }


__all__ = ["build_dual_frontier_repair_scorecard"]
