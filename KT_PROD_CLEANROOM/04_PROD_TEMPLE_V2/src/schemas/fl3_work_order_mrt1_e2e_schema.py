from __future__ import annotations

from typing import Any, Dict, Set

from schemas.base_schema import (
    SchemaValidationError,
    enforce_max_canonical_json_bytes,
    enforce_max_fields,
    reject_unknown_keys,
    require_dict,
    require_keys,
    validate_bounded_json_value,
    validate_hex_64,
    validate_short_string,
)
from schemas.schema_files import schema_version_hash


FL3_WORK_ORDER_MRT1_E2E_SCHEMA_ID = "kt.work_order.mrt1_e2e.v1"
FL3_WORK_ORDER_MRT1_E2E_SCHEMA_FILE = "fl3/kt.work_order.mrt1_e2e.v1.json"
FL3_WORK_ORDER_MRT1_E2E_SCHEMA_VERSION_HASH = schema_version_hash(FL3_WORK_ORDER_MRT1_E2E_SCHEMA_FILE)

_REQUIRED_ORDER = (
    "schema_id",
    "schema_version_hash",
    "intent",
    "mode",
    "constraints",
    "preconditions",
    "phase_A_batteries",
    "phase_B_negative_live_checks",
    "phase_C1_mrt1_canary",
    "phase_C2_tournament_canary",
    "phase_D_determinism_check",
    "final_outputs",
)
_REQUIRED: Set[str] = set(_REQUIRED_ORDER)
_ALLOWED: Set[str] = set(_REQUIRED_ORDER)


def _require_nonempty_str_list(obj: Dict[str, Any], key: str, *, max_len: int = 4096) -> None:
    v = obj.get(key)
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x.strip() and len(x) <= max_len for x in v):
        raise SchemaValidationError(f"{key} must be non-empty list of non-empty strings (fail-closed)")


def validate_fl3_work_order_mrt1_e2e(obj: Dict[str, Any]) -> None:
    entry = require_dict(obj, name="work_order.mrt1_e2e")
    enforce_max_fields(entry, max_fields=128)
    enforce_max_canonical_json_bytes(entry, max_bytes=512 * 1024)
    require_keys(entry, required=_REQUIRED)
    reject_unknown_keys(entry, allowed=_ALLOWED)
    validate_bounded_json_value(entry, max_depth=10, max_string_len=32_768, max_list_len=2048)

    if entry.get("schema_id") != FL3_WORK_ORDER_MRT1_E2E_SCHEMA_ID:
        raise SchemaValidationError("schema_id mismatch (fail-closed)")
    if entry.get("schema_version_hash") != FL3_WORK_ORDER_MRT1_E2E_SCHEMA_VERSION_HASH:
        raise SchemaValidationError("schema_version_hash mismatch (fail-closed)")

    validate_short_string(entry, "intent", max_len=8192)
    validate_short_string(entry, "mode", max_len=128)

    constraints = require_dict(entry.get("constraints"), name="constraints")
    req_constraints = {
        "law_bundle_required",
        "canonical_lane_required",
        "attestation_mode_required",
        "fail_closed_on_any_violation",
        "no_repo_mutation_except_receipts",
    }
    require_keys(constraints, required=req_constraints)
    reject_unknown_keys(constraints, allowed=req_constraints)
    for k in ("law_bundle_required", "canonical_lane_required", "fail_closed_on_any_violation", "no_repo_mutation_except_receipts"):
        if not isinstance(constraints.get(k), bool):
            raise SchemaValidationError(f"constraints.{k} must be boolean (fail-closed)")
    validate_short_string(constraints, "attestation_mode_required", max_len=32)

    pre = require_dict(entry.get("preconditions"), name="preconditions")
    req_pre = {"env_vars_required", "env_assertions", "repo_state"}
    require_keys(pre, required=req_pre)
    reject_unknown_keys(pre, allowed=req_pre)
    _require_nonempty_str_list(pre, "env_vars_required", max_len=128)
    env_assert = pre.get("env_assertions")
    if not isinstance(env_assert, dict) or not env_assert:
        raise SchemaValidationError("preconditions.env_assertions must be non-empty object (fail-closed)")
    for k, v in env_assert.items():
        if not isinstance(k, str) or not k.strip() or not isinstance(v, str):
            raise SchemaValidationError("preconditions.env_assertions must map strings to strings (fail-closed)")

    repo_state = require_dict(pre.get("repo_state"), name="repo_state")
    req_repo = {"git_clean_required", "law_bundle_hash_required"}
    require_keys(repo_state, required=req_repo)
    reject_unknown_keys(repo_state, allowed=req_repo)
    if not isinstance(repo_state.get("git_clean_required"), bool):
        raise SchemaValidationError("repo_state.git_clean_required must be boolean (fail-closed)")
    validate_hex_64(repo_state, "law_bundle_hash_required")

    phase_a = require_dict(entry.get("phase_A_batteries"), name="phase_A_batteries")
    req_a = {"description", "commands", "pass_criteria"}
    require_keys(phase_a, required=req_a)
    reject_unknown_keys(phase_a, allowed=req_a)
    validate_short_string(phase_a, "description", max_len=4096)
    _require_nonempty_str_list(phase_a, "commands", max_len=4096)
    validate_short_string(phase_a, "pass_criteria", max_len=1024)

    phase_b = require_dict(entry.get("phase_B_negative_live_checks"), name="phase_B_negative_live_checks")
    req_b = {"description", "tests"}
    require_keys(phase_b, required=req_b)
    reject_unknown_keys(phase_b, allowed=req_b)
    validate_short_string(phase_b, "description", max_len=4096)
    tests = phase_b.get("tests")
    if not isinstance(tests, list) or not tests:
        raise SchemaValidationError("phase_B_negative_live_checks.tests must be non-empty list (fail-closed)")
    for t in tests:
        to = require_dict(t, name="phase_B_negative_live_checks.test")
        if set(to.keys()) != {"name", "command", "expected"}:
            raise SchemaValidationError("negative test keys mismatch (fail-closed)")
        validate_short_string(to, "name", max_len=256)
        validate_short_string(to, "command", max_len=4096)
        validate_short_string(to, "expected", max_len=64)

    c1 = require_dict(entry.get("phase_C1_mrt1_canary"), name="phase_C1_mrt1_canary")
    req_c1 = {"description", "job", "artifacts_expected", "output_root", "pass_criteria"}
    require_keys(c1, required=req_c1)
    reject_unknown_keys(c1, allowed=req_c1)
    validate_short_string(c1, "description", max_len=4096)
    job = require_dict(c1.get("job"), name="phase_C1_mrt1_canary.job")
    if set(job.keys()) != {"runner", "args"}:
        raise SchemaValidationError("phase_C1_mrt1_canary.job keys mismatch (fail-closed)")
    validate_short_string(job, "runner", max_len=256)
    args = require_dict(job.get("args"), name="phase_C1_mrt1_canary.job.args")
    if set(args.keys()) != {"job_path", "organ_contract"}:
        raise SchemaValidationError("phase_C1_mrt1_canary.job.args keys mismatch (fail-closed)")
    validate_short_string(args, "job_path", max_len=1024)
    validate_short_string(args, "organ_contract", max_len=1024)
    _require_nonempty_str_list(c1, "artifacts_expected", max_len=256)
    validate_short_string(c1, "output_root", max_len=1024)
    validate_short_string(c1, "pass_criteria", max_len=1024)

    c2 = require_dict(entry.get("phase_C2_tournament_canary"), name="phase_C2_tournament_canary")
    req_c2 = {"description", "tournament", "artifacts_expected", "pass_criteria"}
    require_keys(c2, required=req_c2)
    reject_unknown_keys(c2, allowed=req_c2)
    validate_short_string(c2, "description", max_len=4096)
    tournament = require_dict(c2.get("tournament"), name="phase_C2_tournament_canary.tournament")
    req_t = {"runner", "suites", "entrants_min", "entrants_max"}
    require_keys(tournament, required=req_t)
    reject_unknown_keys(tournament, allowed=req_t)
    validate_short_string(tournament, "runner", max_len=256)
    _require_nonempty_str_list(tournament, "suites", max_len=128)
    emin = tournament.get("entrants_min")
    emax = tournament.get("entrants_max")
    if not isinstance(emin, int) or not isinstance(emax, int) or emin < 1 or emax < 1 or emin > emax:
        raise SchemaValidationError("tournament entrants_min/max invalid (fail-closed)")
    _require_nonempty_str_list(c2, "artifacts_expected", max_len=256)
    validate_short_string(c2, "pass_criteria", max_len=1024)

    det = require_dict(entry.get("phase_D_determinism_check"), name="phase_D_determinism_check")
    req_det = {"description", "procedure", "pass_criteria"}
    require_keys(det, required=req_det)
    reject_unknown_keys(det, allowed=req_det)
    validate_short_string(det, "description", max_len=4096)
    _require_nonempty_str_list(det, "procedure", max_len=4096)
    validate_short_string(det, "pass_criteria", max_len=1024)

    final = require_dict(entry.get("final_outputs"), name="final_outputs")
    req_final = {"receipts_required", "verdict"}
    require_keys(final, required=req_final)
    reject_unknown_keys(final, allowed=req_final)
    _require_nonempty_str_list(final, "receipts_required", max_len=512)
    verdict = require_dict(final.get("verdict"), name="final_outputs.verdict")
    if set(verdict.keys()) != {"on_pass", "on_fail"}:
        raise SchemaValidationError("final_outputs.verdict keys mismatch (fail-closed)")
    validate_short_string(verdict, "on_pass", max_len=128)
    validate_short_string(verdict, "on_fail", max_len=128)

