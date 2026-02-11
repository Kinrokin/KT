from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


PHASE2_WORK_ORDER_SCHEMA_ID = "kt.phase2_work_order.v1"
PHASE2_WORK_ORDER_SCHEMA_FILE = "fl3/kt.phase2_work_order.v1.json"
PHASE2_WORK_ORDER_SCHEMA_VERSION_HASH = schema_version_hash(PHASE2_WORK_ORDER_SCHEMA_FILE)

_REQ = (
    "schema_id",
    "schema_version_hash",
    "schema_version",
    "work_order_id",
    "title",
    "status",
    "authority",
    "objective",
    "prime_constraints",
    "inputs",
    "deliverables",
    "work_packages",
    "exit_criteria",
    "completion",
)
_REQ_SET: Set[str] = set(_REQ)


def _require_nonempty_str_list(obj: Dict[str, Any], key: str, *, max_len: int = 256) -> None:
    v = obj.get(key)
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x.strip() and len(x) <= max_len for x in v):
        raise SchemaValidationError(f"{key} must be non-empty list of non-empty strings (fail-closed)")


def validate_phase2_work_order(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="Phase 2 work order")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQ_SET)
    reject_unknown_keys(entry, allowed=_REQ_SET)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)

    if entry.get("schema_id") != PHASE2_WORK_ORDER_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != PHASE2_WORK_ORDER_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    if entry.get("schema_version") != 1:
        raise SchemaValidationError("schema_version must be 1 (fail-closed)")

    validate_short_string(entry, "work_order_id", max_len=128)
    validate_short_string(entry, "title", max_len=256)
    validate_short_string(entry, "status", max_len=64)

    auth = require_dict(entry.get("authority"), name="authority")
    if set(auth.keys()) != {
        "treat_as_law",
        "fail_closed",
        "no_implicit_fallbacks",
        "behavior_cannot_precede_artifact",
        "append_only_policy",
        "explicit_non_changes",
    }:
        raise SchemaValidationError("authority keys mismatch (fail-closed)")
    for k in (
        "treat_as_law",
        "fail_closed",
        "no_implicit_fallbacks",
        "behavior_cannot_precede_artifact",
    ):
        if not isinstance(auth.get(k), bool):
            raise SchemaValidationError(f"authority.{k} must be boolean (fail-closed)")
    _require_nonempty_str_list(auth, "append_only_policy", max_len=128)
    _require_nonempty_str_list(auth, "explicit_non_changes", max_len=256)

    objective = require_dict(entry.get("objective"), name="objective")
    if set(objective.keys()) != {"primary", "success_definition"}:
        raise SchemaValidationError("objective keys mismatch (fail-closed)")
    validate_short_string(objective, "primary", max_len=4096)
    _require_nonempty_str_list(objective, "success_definition", max_len=512)

    pc = require_dict(entry.get("prime_constraints"), name="prime_constraints")
    if set(pc.keys()) != {"forbidden", "required"}:
        raise SchemaValidationError("prime_constraints keys mismatch (fail-closed)")
    _require_nonempty_str_list(pc, "forbidden", max_len=128)
    _require_nonempty_str_list(pc, "required", max_len=128)

    inputs = require_dict(entry.get("inputs"), name="inputs")
    if set(inputs.keys()) != {"required_refs", "runtime_environment"}:
        raise SchemaValidationError("inputs keys mismatch (fail-closed)")
    refs = require_dict(inputs.get("required_refs"), name="inputs.required_refs")
    if set(refs.keys()) != {"phase1c_tag", "law_bundle_file", "phase1c_executor"}:
        raise SchemaValidationError("inputs.required_refs keys mismatch (fail-closed)")
    for k in refs.keys():
        validate_short_string(refs, k, max_len=256)

    env = require_dict(inputs.get("runtime_environment"), name="inputs.runtime_environment")
    if set(env.keys()) != {"platforms_supported", "offline_mode_required", "environment_vars_required"}:
        raise SchemaValidationError("inputs.runtime_environment keys mismatch (fail-closed)")
    plats = env.get("platforms_supported")
    if not isinstance(plats, list) or not plats or not all(isinstance(x, str) and x.strip() for x in plats):
        raise SchemaValidationError("inputs.runtime_environment.platforms_supported must be non-empty list of strings (fail-closed)")
    if not isinstance(env.get("offline_mode_required"), bool):
        raise SchemaValidationError("inputs.runtime_environment.offline_mode_required must be boolean (fail-closed)")
    evr = env.get("environment_vars_required")
    if not isinstance(evr, dict) or not evr:
        raise SchemaValidationError("inputs.runtime_environment.environment_vars_required must be non-empty object (fail-closed)")
    for k, v in evr.items():
        if not isinstance(k, str) or not k.strip() or not isinstance(v, str):
            raise SchemaValidationError("inputs.runtime_environment.environment_vars_required must map strings to strings (fail-closed)")

    deliv = require_dict(entry.get("deliverables"), name="deliverables")
    if set(deliv.keys()) != {"required_artifacts", "required_runtime_outputs"}:
        raise SchemaValidationError("deliverables keys mismatch (fail-closed)")
    _require_nonempty_str_list(deliv, "required_artifacts", max_len=512)
    _require_nonempty_str_list(deliv, "required_runtime_outputs", max_len=512)

    wps = entry.get("work_packages")
    if not isinstance(wps, list) or not wps:
        raise SchemaValidationError("work_packages must be non-empty list (fail-closed)")
    for wp in wps:
        wpo = require_dict(wp, name="work_package")
        if set(wpo.keys()) != {"wp_id", "intent", "actions"}:
            raise SchemaValidationError("work_package keys mismatch (fail-closed)")
        validate_short_string(wpo, "wp_id", max_len=64)
        validate_short_string(wpo, "intent", max_len=4096)
        actions = wpo.get("actions")
        if not isinstance(actions, list) or not actions:
            raise SchemaValidationError("work_package.actions must be non-empty list (fail-closed)")
        for act in actions:
            act_obj = require_dict(act, name="work_package.action")
            if "action_id" not in act_obj or "action" not in act_obj:
                raise SchemaValidationError("action missing action_id/action (fail-closed)")
            validate_short_string(act_obj, "action_id", max_len=64)
            validate_short_string(act_obj, "action", max_len=128)

    ec = require_dict(entry.get("exit_criteria"), name="exit_criteria")
    req_ec = {
        "all_wps_complete",
        "all_required_runtime_outputs_present",
        "training_receipted",
        "promotion_receipted_atomic",
        "seal_receipted_with_evidence_pack",
        "replay_passes",
        "offline_guard_enforced",
        "no_cross_adapter_bleed",
        "fail_closed_verified",
        "system_wide_audit_passed",
        "law_bundle_integrity_holds",
    }
    if set(ec.keys()) != req_ec:
        raise SchemaValidationError("exit_criteria keys mismatch (fail-closed)")
    for k in req_ec:
        if not isinstance(ec.get(k), bool):
            raise SchemaValidationError(f"exit_criteria.{k} must be boolean (fail-closed)")

    completion = require_dict(entry.get("completion"), name="completion")
    if set(completion.keys()) != {"completion_tag", "freeze_statement"}:
        raise SchemaValidationError("completion keys mismatch (fail-closed)")
    validate_short_string(completion, "completion_tag", max_len=128)
    validate_short_string(completion, "freeze_statement", max_len=4096)
