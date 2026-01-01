from __future__ import annotations

from typing import Any, Dict, List

from schemas.schema_hash import sha256_json


STEP_TYPES = ("DECOMPOSE", "EVALUATE", "CHECK_POLICY", "SUMMARIZE", "FINALIZE")


def plan_steps(*, request_hash: str, max_steps: int, artifact_refs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Hash-only planning: uses only bounded metadata (hashes/ids) and explicit bounds.
    refs_count = len(artifact_refs)
    steps_count = min(max_steps, max(1, min(8, refs_count or 1)))

    steps: List[Dict[str, Any]] = []
    for i in range(steps_count):
        step_type = STEP_TYPES[i % len(STEP_TYPES)]
        step_hash = sha256_json({"request_hash": request_hash, "step_index": i, "step_type": step_type})
        steps.append({"step_index": i, "step_type": step_type, "step_hash": step_hash})
    return steps

