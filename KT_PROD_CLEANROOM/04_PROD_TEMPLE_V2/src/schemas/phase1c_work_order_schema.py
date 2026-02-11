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


PHASE1C_WORK_ORDER_SCHEMA_ID = "kt.phase1c_work_order.v1"
PHASE1C_WORK_ORDER_SCHEMA_FILE = "fl3/kt.phase1c_work_order.v1.json"
PHASE1C_WORK_ORDER_SCHEMA_VERSION_HASH = schema_version_hash(PHASE1C_WORK_ORDER_SCHEMA_FILE)

_REQ = (
    "schema_id",
    "schema_version_hash",
    "schema_version",
    "phase",
    "title",
    "law_binding",
    "prime_constraints",
    "objective",
    "scope",
    "runtime_authority_model",
    "required_runtime_artifacts",
    "work_packages",
    "exit_criteria",
    "completion_statement",
)
_REQ_SET: Set[str] = set(_REQ)


def validate_phase1c_work_order(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="Phase 1C work order")
    enforce_max_fields(entry, max_fields=64)
    require_keys(entry, required=_REQ_SET)
    reject_unknown_keys(entry, allowed=_REQ_SET)
    enforce_max_canonical_json_bytes(entry, max_bytes=256 * 1024)

    if entry.get("schema_id") != PHASE1C_WORK_ORDER_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != PHASE1C_WORK_ORDER_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_hex_64(entry, "schema_version_hash")
    if entry.get("schema_version") != 1:
        raise SchemaValidationError("schema_version must be 1 (fail-closed)")
    if entry.get("phase") != "PHASE_1C":
        raise SchemaValidationError("phase must be PHASE_1C (fail-closed)")
    validate_short_string(entry, "title", max_len=256)
    validate_short_string(entry, "objective", max_len=2048)
    validate_short_string(entry, "completion_statement", max_len=1024)

    law = require_dict(entry.get("law_binding"), name="law_binding")
    if set(law.keys()) != {"source", "treat_as_law", "retroactive_change_forbidden", "phase_1b_status_preserved"}:
        raise SchemaValidationError("law_binding keys mismatch (fail-closed)")
    validate_short_string(law, "source", max_len=128)
    for k in ("treat_as_law", "retroactive_change_forbidden", "phase_1b_status_preserved"):
        if not isinstance(law.get(k), bool):
            raise SchemaValidationError(f"law_binding.{k} must be boolean (fail-closed)")

    pc = require_dict(entry.get("prime_constraints"), name="prime_constraints")
    if set(pc.keys()) != {"forbidden", "required"}:
        raise SchemaValidationError("prime_constraints keys mismatch (fail-closed)")
    for k in ("forbidden", "required"):
        v = pc.get(k)
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x.strip() for x in v):
            raise SchemaValidationError(f"prime_constraints.{k} must be non-empty list of non-empty strings (fail-closed)")

    scope = require_dict(entry.get("scope"), name="scope")
    if set(scope.keys()) != {"nodes_activated", "nodes_inert", "no_new_nodes"}:
        raise SchemaValidationError("scope keys mismatch (fail-closed)")
    if not isinstance(scope.get("no_new_nodes"), bool):
        raise SchemaValidationError("scope.no_new_nodes must be boolean (fail-closed)")
    for k in ("nodes_activated", "nodes_inert"):
        v = scope.get(k)
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            raise SchemaValidationError(f"scope.{k} must be list of non-empty strings (fail-closed)")

    auth = require_dict(entry.get("runtime_authority_model"), name="runtime_authority_model")
    if set(auth.keys()) != {"judge", "watcher_spc", "promotion"}:
        raise SchemaValidationError("runtime_authority_model keys mismatch (fail-closed)")

    judge = require_dict(auth.get("judge"), name="runtime_authority_model.judge")
    if set(judge.keys()) != {"authoritative", "may_gate", "may_return_verdict"}:
        raise SchemaValidationError("judge keys mismatch (fail-closed)")
    for k in judge.keys():
        if not isinstance(judge.get(k), bool):
            raise SchemaValidationError(f"judge.{k} must be boolean (fail-closed)")

    watcher = require_dict(auth.get("watcher_spc"), name="runtime_authority_model.watcher_spc")
    if set(watcher.keys()) != {
        "authoritative",
        "may_execute",
        "may_emit",
        "may_gate",
        "may_veto",
        "may_route",
        "may_promote",
    }:
        raise SchemaValidationError("watcher_spc keys mismatch (fail-closed)")
    if watcher.get("may_emit") != "advisory_only":
        raise SchemaValidationError("watcher_spc.may_emit must be advisory_only (fail-closed)")
    for k in ("authoritative", "may_execute", "may_gate", "may_veto", "may_route", "may_promote"):
        if not isinstance(watcher.get(k), bool):
            raise SchemaValidationError(f"watcher_spc.{k} must be boolean (fail-closed)")

    promo = require_dict(auth.get("promotion"), name="runtime_authority_model.promotion")
    if set(promo.keys()) != {"mode", "may_write_candidate", "may_mutate_canonical_index"}:
        raise SchemaValidationError("promotion keys mismatch (fail-closed)")
    if promo.get("mode") != "shadow_only":
        raise SchemaValidationError("promotion.mode must be shadow_only (fail-closed)")
    if not isinstance(promo.get("may_write_candidate"), bool) or not isinstance(promo.get("may_mutate_canonical_index"), bool):
        raise SchemaValidationError("promotion booleans must be boolean (fail-closed)")

    rra = entry.get("required_runtime_artifacts")
    if not isinstance(rra, list) or not rra or not all(isinstance(x, str) and x.strip() for x in rra):
        raise SchemaValidationError("required_runtime_artifacts must be non-empty list of non-empty strings (fail-closed)")

    wps = entry.get("work_packages")
    if not isinstance(wps, list) or not wps:
        raise SchemaValidationError("work_packages must be non-empty list (fail-closed)")
    for wp in wps:
        wpo = require_dict(wp, name="work_package")
        if "wp_id" not in wpo or "intent" not in wpo:
            raise SchemaValidationError("work_package missing wp_id/intent (fail-closed)")
        validate_short_string(wpo, "wp_id", max_len=128)
        validate_short_string(wpo, "intent", max_len=2048)
        if "actions" not in wpo and "tests" not in wpo:
            raise SchemaValidationError("work_package must define actions or tests (fail-closed)")

    if not isinstance(entry.get("exit_criteria"), dict):
        raise SchemaValidationError("exit_criteria must be object (fail-closed)")

