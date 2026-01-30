from __future__ import annotations

from typing import Any, Dict, List

from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import sha256_json
from tools.verification.fl3_validators import validate_schema_bound_object


_PROMPT_TRANSFORM_STYLE = [
    "clarify_first",
    "expand_context",
    "compress",
    "reframe",
    "structured_outline",
]
_REASONING_DIRECTIVE = [
    "steps_tagged",
    "bullet_proof",
    "decision_tree",
    "minimal_chain",
    "evidence_first",
]
_UNCERTAINTY_POLICY = [
    "explicit_calibration",
    "conservative",
    "neutral",
]
_GUARDRAIL_STRENGTH = [
    "strict",
    "balanced",
    "permissive",
]
_SCORING_BIAS = [
    "precision",
    "recall",
    "calibration",
]


def _schema_hash(schema_file: str) -> str:
    from schemas.schema_files import schema_version_hash  # type: ignore

    return schema_version_hash(schema_file)


def build_policy_bundles(*, job_id: str, seed: int, parent_hash: str, count: int) -> List[Dict[str, Any]]:
    """
    MRT-0 hypothesis generator (AdapterType.A-only).

    Deterministic, CPU-only, no network, no entropy:
    - Generate a bounded set of policy bundles (genotypes) deterministically from job_id + seed.
    - Output is schema-bound (kt.policy_bundle.v1).
    """
    if count < 1:
        raise ValueError("count must be >= 1 (fail-closed)")

    # Generate a deterministic, distribution-neutral selection of genotypes.
    # Each bundle is mapped purely from hash(job_id, seed, parent_hash, i)
    # to genotype dimensions. No coverage shaping, no ordering bias.
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    i = 0
    while len(out) < count:
        h = sha256_json({"job_id": job_id, "seed": int(seed), "parent_hash": parent_hash, "i": i})
        # Use disjoint slices of the hash to map each gene dimension.
        style = _PROMPT_TRANSFORM_STYLE[int(h[0:8], 16) % len(_PROMPT_TRANSFORM_STYLE)]
        directive = _REASONING_DIRECTIVE[int(h[8:16], 16) % len(_REASONING_DIRECTIVE)]
        upol = _UNCERTAINTY_POLICY[int(h[16:24], 16) % len(_UNCERTAINTY_POLICY)]
        guard = _GUARDRAIL_STRENGTH[int(h[24:32], 16) % len(_GUARDRAIL_STRENGTH)]
        bias = _SCORING_BIAS[int(h[32:40], 16) % len(_SCORING_BIAS)]
        geno = {
            "prompt_transform_style": style,
            "reasoning_directive": directive,
            "uncertainty_policy": upol,
            "guardrail_strength": guard,
            "scoring_bias": bias,
        }

        record: Dict[str, Any] = {
            "schema_id": "kt.policy_bundle.v1",
            "schema_version_hash": _schema_hash("fl3/kt.policy_bundle.v1.json"),
            "bundle_id": "",
            "adapter_type": "A",
            "genotype": geno,
            "parent_hash": parent_hash,
            "created_at": utc_now_z(),
        }
        record["bundle_id"] = sha256_json({k: v for k, v in record.items() if k not in {"created_at", "bundle_id"}})
        if record["bundle_id"] not in seen:
            validate_schema_bound_object(record)
            out.append(record)
            seen.add(record["bundle_id"])
        i += 1

    # Stable ordering (canonical): sort by bundle_id.
    out.sort(key=lambda r: str(r.get("bundle_id", "")))
    return out
