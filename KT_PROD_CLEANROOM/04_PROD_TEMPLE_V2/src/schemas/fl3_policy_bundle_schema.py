from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import SchemaValidationError, enforce_max_fields, reject_unknown_keys, require_dict, require_keys, validate_hex_64
from schemas.fl3_schema_common import sha256_hex_of_obj, validate_created_at_utc_z
from schemas.schema_files import schema_version_hash


FL3_POLICY_BUNDLE_SCHEMA_ID = "kt.policy_bundle.v1"
FL3_POLICY_BUNDLE_SCHEMA_FILE = "fl3/kt.policy_bundle.v1.json"
FL3_POLICY_BUNDLE_SCHEMA_VERSION_HASH = schema_version_hash(FL3_POLICY_BUNDLE_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "bundle_id",
    "adapter_type",
    "genotype",
    "parent_hash",
    "created_at",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)
_HASH_DROP_KEYS = {"created_at", "bundle_id"}

_GENOTYPE_KEYS = {
    "prompt_transform_style",
    "reasoning_directive",
    "uncertainty_policy",
    "guardrail_strength",
    "scoring_bias",
}

_ENUMS: Dict[str, Set[str]] = {
    "prompt_transform_style": {"clarify_first", "expand_context", "compress", "reframe", "structured_outline"},
    "reasoning_directive": {"steps_tagged", "bullet_proof", "decision_tree", "minimal_chain", "evidence_first"},
    "uncertainty_policy": {"explicit_calibration", "conservative", "neutral"},
    "guardrail_strength": {"strict", "balanced", "permissive"},
    "scoring_bias": {"precision", "recall", "calibration"},
}


def validate_fl3_policy_bundle(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="FL3/FL4 policy bundle")
    enforce_max_fields(entry, max_fields=32)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)

    if entry.get("schema_id") != FL3_POLICY_BUNDLE_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_POLICY_BUNDLE_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    validate_hex_64(entry, "bundle_id")
    validate_hex_64(entry, "parent_hash")
    validate_created_at_utc_z(entry.get("created_at"))

    if entry.get("adapter_type") != "A":
        raise SchemaValidationError("adapter_type must be A (fail-closed)")

    genotype = require_dict(entry.get("genotype"), name="genotype")
    if set(genotype.keys()) != _GENOTYPE_KEYS:
        raise SchemaValidationError("genotype keys mismatch (fail-closed)")
    for k, allowed in _ENUMS.items():
        v = genotype.get(k)
        if not isinstance(v, str) or v not in allowed:
            raise SchemaValidationError(f"genotype.{k} invalid (fail-closed)")

    expected = sha256_hex_of_obj(entry, drop_keys=_HASH_DROP_KEYS)
    if entry.get("bundle_id") != expected:
        raise SchemaValidationError("bundle_id does not match canonical hash surface (fail-closed)")

