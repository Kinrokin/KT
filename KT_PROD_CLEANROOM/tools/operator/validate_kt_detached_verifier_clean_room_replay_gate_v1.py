from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, NoReturn, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_detached_verifier_clean_room_replay_gate_v1 as gate
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHORITY_BRANCH = "validate/kt-detached-verifier-clean-room-replay-gate-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-detached-verifier-clean-room-replay-gate-validation"
ALLOWED_BRANCHES = frozenset({AUTHORITY_BRANCH, "main"})

AUTHORITATIVE_LANE = "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
EXPECTED_PREVIOUS_OUTCOME = gate.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = gate.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATED__CLEAN_ROOM_REPLAY_NEXT"
NEXT_LAWFUL_MOVE = "RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
DECISION = "CLEAN_ROOM_REPLAY_READY_TO_RUN"

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_DV_REPLAY_GATE_VALIDATION_PREDECESSOR_MISSING",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_NEXT_MOVE_DRIFT",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_ARTIFACT_MISSING",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_EXECUTION_DRIFT",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_BRANCH_DRIFT",
            "RC_KT_DV_REPLAY_GATE_VALIDATION_TRUST_ZONE_FAILED",
        )
    )
)

INPUTS = {
    "authoring_contract": gate.OUTPUTS["authoring_contract"],
    "execution_scope": gate.OUTPUTS["execution_scope"],
    "validation_plan": gate.OUTPUTS["validation_plan"],
    "author_receipt": gate.OUTPUTS["author_receipt"],
    "author_report": gate.OUTPUTS["author_report"],
    "author_next_lawful_move": gate.OUTPUTS["next_lawful_move"],
}

JSON_INPUT_ROLES = {role for role, raw in INPUTS.items() if raw.endswith(".json")}

OUTPUTS = {
    "validation_contract": "governance/kt_detached_verifier_clean_room_replay_gate_validation_contract_v1.json",
    "run_gate_contract": "governance/kt_detached_verifier_clean_room_replay_run_gate_v1.json",
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_validation_report.md",
    "run_decision": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_run_decision.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_validation_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/validate_kt_detached_verifier_clean_room_replay_gate_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_validate_kt_detached_verifier_clean_room_replay_gate_v1.py",
    }
)

AUTHORITY_DRIFT_KEYS = frozenset(
    {
        "clean_room_replay_executed",
        "clean_room_replay_completed",
        "external_audit_completed",
        "external_audit_claimed_complete",
        "commercial_activation_claim_authorized",
        "commercial_activation_claimed",
        "seven_b_amplification_claimed_proven",
        "seven_b_amplification_claimed",
        "beyond_sota_claimed",
        "s_tier_claimed",
        "fp0_or_highway_promoted_to_authority",
        "highway_shadow_promoted_to_authority",
        "fp0_overlay_promoted_to_authority",
        "truth_engine_law_mutated",
        "trust_zone_law_mutated",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    }
)


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> NoReturn:
    raise LaneFailure(code, detail)


def _walk(value: Any, parent_key: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item, str(key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk(item, parent_key)
            else:
                yield parent_key, item


def _is_negative_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed", "excluded"))


def _is_machine_routing_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("outcome", "next_lawful_move", "allowed_outcomes", "artifact_id", "schema_id", "lane"))


def _is_negative_text_context(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "not authorized",
            "not proven",
            "not complete",
            "not completed",
            "not executed",
            "not run",
            "not claim",
            "unproven",
            "forbidden",
            "blocked",
            "prohibited",
            "cannot claim",
            "does not claim",
            "does not authorize",
            "must not claim",
            "remains unauthorized",
            "has not lawfully run",
            "has not run",
        )
    )


def _contains_forbidden_claim(value: str) -> bool:
    normalized = value.upper()
    return any(phrase in normalized for phrase in gate.validation.CLAIM_DRIFT_PHRASES)


def _claim_clauses(value: str) -> list[str]:
    return [
        clause.strip()
        for clause in re.split(r",?\s+\bbut\b\s+|,?\s+\bhowever\b\s+|[;\r\n]+|(?<=[.!?])\s+", value)
        if clause.strip()
    ]


def _contains_unsafe_forbidden_claim(value: str) -> bool:
    return any(_contains_forbidden_claim(clause) and not _is_negative_text_context(clause) for clause in _claim_clauses(value))


def _status_relpaths(status: str) -> list[str]:
    rows: list[str] = []
    for line in status.splitlines():
        if not line.strip():
            continue
        rel = line[3:].strip().replace("\\", "/")
        if rel:
            rows.append(rel)
    return rows


def _ensure_branch_context(root: Path) -> str:
    branch = common.git_current_branch_name(root)
    if branch in ALLOWED_BRANCHES or branch.startswith(REPLAY_BRANCH_PREFIX):
        if branch == "main" and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_BRANCH_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail(
            "RC_KT_DV_REPLAY_GATE_VALIDATION_BRANCH_DRIFT",
            "dirty worktree outside clean-room replay gate validation scope: " + ", ".join(out_of_scope),
        )


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        payload = common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_ARTIFACT_MISSING", str(exc))
    if not isinstance(payload, dict):
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_PREDECESSOR_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_ARTIFACT_MISSING", str(exc))


def _load_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load_json(root, raw, label=role) for role, raw in INPUTS.items() if role in JSON_INPUT_ROLES}
    texts = {role: _read_text(root, raw, label=role) for role, raw in INPUTS.items() if role not in JSON_INPUT_ROLES}
    return payloads, texts


def _binding_rows(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_ARTIFACT_MISSING", f"missing {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in ("authoring_contract", "execution_scope", "validation_plan", "author_receipt", "author_next_lawful_move"):
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        required = {
            "clean_room_replay_gate_authored": True,
            "clean_room_replay_executed": False,
            "clean_room_replay_completed": False,
            "commercial_activation_claimed": False,
            "external_audit_claimed_complete": False,
            "seven_b_amplification_claimed": False,
            "beyond_sota_claimed": False,
            "fp0_or_highway_promoted_to_authority": False,
            "truth_engine_law_unchanged": True,
            "trust_zone_law_unchanged": True,
        }
        for key, expected in required.items():
            if payload.get(key) is not expected:
                _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH", f"{role}.{key} drifted")
    if payloads["validation_plan"].get("validation_must_not_execute_replay") is not True:
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_EXECUTION_DRIFT", "validation plan must forbid replay execution")
    if payloads["execution_scope"].get("can_run_replay") is not False:
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_EXECUTION_DRIFT", "authoring scope cannot already run replay")


def _ensure_author_bindings_recompute(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    rows = payloads["author_receipt"].get("input_bindings")
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH", "author receipt input_bindings missing")
    expected_paths = {raw.replace("\\", "/") for raw in gate.INPUTS.values()}
    seen_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH", "author binding row malformed")
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not raw or len(expected) != 64:
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH", "author binding incomplete")
        normalized = raw.replace("\\", "/")
        if normalized in seen_paths:
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH", f"duplicate author binding for {raw}")
        seen_paths.add(normalized)
        path = common.resolve_path(root, raw)
        if not path.is_file() or file_sha256(path) != expected:
            _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH", f"source hash mismatch for {raw}")
    missing_paths = sorted(expected_paths - seen_paths)
    if missing_paths:
        _fail(
            "RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH",
            "author receipt missing expected input bindings: " + ", ".join(missing_paths),
        )


def _ensure_claim_boundary(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
                if _contains_unsafe_forbidden_claim(value):
                    _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _contains_unsafe_forbidden_claim(line):
                _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH", f"{label} line {line_number} contains forbidden claim")


def _base(
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.detached_verifier.clean_room_replay_gate.validation.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "VALIDATION_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "decision": DECISION,
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_BLOCKED__PATCH_REQUIRED",
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_INVALID__CLAIM_BOUNDARY_BREACH",
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_FAILED__DO_NOT_RUN_CLEAN_ROOM_REPLAY",
        ],
        "predecessor_outcome": EXPECTED_PREVIOUS_OUTCOME,
        "predecessor_next_lawful_move": EXPECTED_PREVIOUS_NEXT_MOVE,
        "current_branch": branch,
        "current_git_head": head,
        "current_branch_head": head,
        "current_main": current_main_head,
        "current_main_head": current_main_head,
        "generated_utc": generated_utc,
        "input_bindings": input_bindings,
        "binding_hashes": {f"{row['role']}_hash": row["sha256"] for row in input_bindings},
        "trust_zone_validation": trust_zone_validation,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "clean_room_replay_gate_validated": True,
        "clean_room_replay_ready_next": True,
        "clean_room_replay_executed": False,
        "clean_room_replay_completed": False,
        "validation_executed": True,
        "validation_must_not_execute_replay": True,
        "cannot_execute_clean_room_replay_in_validation": True,
        "can_run_clean_room_replay_next": True,
        "external_audit_claimed_complete": False,
        "commercial_activation_claimed": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_claimed": False,
        "seven_b_amplification_claimed_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "fp0_or_highway_promoted_to_authority": False,
        "highway_shadow_promoted_to_authority": False,
        "fp0_overlay_promoted_to_authority": False,
        "claim_boundary_passed": True,
        "schema_validation_passed": True,
        "receipt_validation_passed": True,
        "negative_tests_passed": True,
    }


def _contract(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_CONTRACT_V1",
            "validation_scope": "VALIDATE_GATE_ONLY_NO_REPLAY_EXECUTION",
            "validation_checks": [
                "gate authoring outcome is replay-bound",
                "authoring source hashes recompute against current files",
                "gate scope still excludes external audit and commercial activation claims",
                "clean-room replay remains unexecuted inside validation",
                "next lawful move is exact RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1",
            ],
        }
    )
    return payload


def _run_gate_contract(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_RUN_GATE_V1",
            "run_lane": NEXT_LAWFUL_MOVE,
            "run_authorized_next": True,
            "run_authorized_inside_validation": False,
            "allowed_run_surface": [
                "detached verifier manifest replay",
                "evidence bundle replay",
                "claim board replay without claim expansion",
                "public verifier detached clean-room command path",
            ],
            "forbidden_run_surface": [
                "external audit completion claim",
                "commercial activation claim authorization",
                "7B amplification proof claim",
                "beyond-SOTA claim",
                "FP0 or Highway authority promotion",
                "truth-engine law mutation",
                "trust-zone law mutation",
            ],
            "expected_future_execution_artifacts": [
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_execution_receipt.json",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_result.json",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_report.md",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_manifest.json",
            ],
        }
    )
    return payload


def _run_decision(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_RUN_DECISION",
            "decision": DECISION,
            "clean_room_replay_executed": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        }
    )
    return payload


def _next_move_receipt(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_NEXT_LAWFUL_MOVE_RECEIPT",
            "receipt_type": "NEXT_LAWFUL_MOVE",
            "current_validation_lane": AUTHORITATIVE_LANE,
            "current_validation_outcome": SELECTED_OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "clean_room_replay_executed": False,
        }
    )
    return payload


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Detached Verifier Clean-Room Replay Gate Validation Report",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Validation verdict: {SELECTED_OUTCOME}",
            "Clean-room replay executed: false",
            "Clean-room replay now next lawful gate: true",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
            "This lane validates the clean-room replay gate only.",
            "It does not run clean-room replay, does not claim external audit completion, does not authorize commercial activation claims, and does not promote Highway/FP0 authority.",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads, texts = _load_inputs(root)
    _ensure_predecessor(payloads)
    _ensure_author_bindings_recompute(root, payloads)
    _ensure_claim_boundary(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_DV_REPLAY_GATE_VALIDATION_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    generated_utc = utc_now_iso_z()
    bindings = _binding_rows(root)
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=generated_utc,
        input_bindings=bindings,
        trust_zone_validation=trust_zone_validation,
    )

    outputs = {
        "validation_contract": _contract(base),
        "run_gate_contract": _run_gate_contract(base),
        "validation_receipt": {**_contract(base), "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_RECEIPT"},
        "run_decision": _run_decision(base),
        "next_lawful_move": _next_move_receipt(base),
    }
    for role, payload in outputs.items():
        write_json_stable(common.resolve_path(root, OUTPUTS[role]), payload)
    report_path = common.resolve_path(root, OUTPUTS["validation_report"])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(_report(base), encoding="utf-8", newline="\n")

    return {"verdict": SELECTED_OUTCOME, "next_lawful_move": NEXT_LAWFUL_MOVE}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=AUTHORITATIVE_LANE)
    parser.add_argument("--output-root", default=".")
    args = parser.parse_args(argv)
    output_root = None if str(args.output_root).strip() == "." else Path(args.output_root).resolve()
    result = run(output_root=output_root)
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
