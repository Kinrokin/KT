from __future__ import annotations

from typing import Any, Dict, Iterable, List

from schemas.schema_hash import sha256_json


STEP_TYPES = (
    "CHECK_POLICY",
    "INSPECT_EVIDENCE",
    "DECOMPOSE",
    "EVALUATE",
    "SUMMARIZE",
    "FINALIZE",
)

_SEMANTIC_RULES = (
    ("paradox", "CHECK_POLICY"),
    ("policy", "CHECK_POLICY"),
    ("constraint", "CHECK_POLICY"),
    ("claim", "CHECK_POLICY"),
    ("trace", "INSPECT_EVIDENCE"),
    ("replay", "INSPECT_EVIDENCE"),
    ("memory", "INSPECT_EVIDENCE"),
    ("state", "INSPECT_EVIDENCE"),
    ("vault", "INSPECT_EVIDENCE"),
    ("provider", "EVALUATE"),
    ("adapter", "EVALUATE"),
    ("council", "EVALUATE"),
    ("router", "EVALUATE"),
    ("verifier", "SUMMARIZE"),
    ("receipt", "SUMMARIZE"),
    ("audit", "SUMMARIZE"),
    ("proof", "SUMMARIZE"),
)


def _artifact_ids(artifact_refs: Iterable[Dict[str, Any]]) -> List[str]:
    ids: List[str] = []
    for ref in artifact_refs:
        aid = ref.get("artifact_id")
        if isinstance(aid, str):
            normalized = aid.strip().lower()
            if normalized:
                ids.append(normalized)
    return ids


def _step_candidates(*, artifact_ids: List[str], max_branching: int, max_depth: int) -> List[str]:
    ordered: List[str] = ["CHECK_POLICY"]

    for artifact_id in artifact_ids:
        for marker, step_type in _SEMANTIC_RULES:
            if marker in artifact_id and step_type not in ordered:
                ordered.append(step_type)

    if artifact_ids and "INSPECT_EVIDENCE" not in ordered:
        ordered.append("INSPECT_EVIDENCE")
    if max_depth > 1 and "DECOMPOSE" not in ordered:
        ordered.append("DECOMPOSE")
    if max_branching > 1 and "EVALUATE" not in ordered:
        ordered.append("EVALUATE")
    if len(artifact_ids) > 1 and "SUMMARIZE" not in ordered:
        ordered.append("SUMMARIZE")

    ordered.append("FINALIZE")

    for step_type in STEP_TYPES:
        if step_type not in ordered:
            ordered.append(step_type)
    return ordered


def plan_steps(
    *,
    request_hash: str,
    input_hash: str,
    max_steps: int,
    max_branching: int,
    max_depth: int,
    artifact_refs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    artifact_ids = _artifact_ids(artifact_refs)
    candidate_steps = _step_candidates(
        artifact_ids=artifact_ids,
        max_branching=max_branching,
        max_depth=max_depth,
    )
    steps_count = max(1, min(max_steps, len(candidate_steps)))

    steps: List[Dict[str, Any]] = []
    for i in range(steps_count):
        step_type = candidate_steps[i]
        step_hash = sha256_json(
            {
                "request_hash": request_hash,
                "input_hash": input_hash,
                "step_index": i,
                "step_type": step_type,
                "artifact_ids": artifact_ids,
                "max_branching": max_branching,
                "max_depth": max_depth,
            }
        )
        steps.append({"step_index": i, "step_type": step_type, "step_hash": step_hash})
    return steps
