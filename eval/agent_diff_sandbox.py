from __future__ import annotations

import hashlib
import json
from typing import Any


def state_hash(state: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def evaluate_state_diff(before: dict[str, Any], after: dict[str, Any], expected_delta: dict[str, Any]) -> dict[str, Any]:
    actual_delta = {key: after.get(key) for key in sorted(set(after) | set(before)) if before.get(key) != after.get(key)}
    pass_state = actual_delta == expected_delta
    return {
        "schema_id": "kt.v17_7_4.agent_diff_state_contract_result.v1",
        "status": "PASS" if pass_state else "HARD_ZERO_STATE_MISMATCH",
        "before_hash": state_hash(before),
        "after_hash": state_hash(after),
        "expected_delta_hash": state_hash(expected_delta),
        "actual_delta_hash": state_hash(actual_delta),
        "actual_delta": actual_delta,
        "score": 1.0 if pass_state else 0.0,
        "semantic_trace_grading_allowed": False,
        "claim_ceiling_preserved": True,
    }


__all__ = ["evaluate_state_diff", "state_hash"]
