from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, NoReturn, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import validate_kt_detached_verifier_kit_superlane_v1 as validation
from tools.operator.titanium_common import file_sha256, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-detached-verifier-clean-room-replay-gate-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-detached-verifier-clean-room-replay-gate"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
EXPECTED_PREVIOUS_OUTCOME = validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = validation.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_AUTHORED__CLEAN_ROOM_REPLAY_GATE_VALIDATION_NEXT"
NEXT_LAWFUL_MOVE = "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_DV_REPLAY_GATE_PREDECESSOR_MISSING",
            "RC_KT_DV_REPLAY_GATE_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_DV_REPLAY_GATE_NEXT_MOVE_DRIFT",
            "RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH",
            "RC_KT_DV_REPLAY_GATE_ARTIFACT_MISSING",
            "RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH",
            "RC_KT_DV_REPLAY_GATE_EXECUTION_DRIFT",
            "RC_KT_DV_REPLAY_GATE_BRANCH_DRIFT",
            "RC_KT_DV_REPLAY_GATE_TRUST_ZONE_FAILED",
        )
    )
)

INPUTS = {
    "validation_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_kit_validation_receipt.json",
    "validation_report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_kit_validation_report.md",
    "validation_contract": "governance/kt_detached_verifier_kit_validation_superlane_v1.json",
    "validation_gate": "governance/kt_detached_verifier_clean_room_replay_gate_v1.json",
    "gate_decision": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_decision.json",
    "path_map": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_h01_expected_to_actual_path_map.json",
    "kit_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_kit_superlane_receipt.json",
    "kit_manifest": "governance/detached_verifier_kit_manifest_v1.json",
    "kit_replay_protocol": "governance/detached_verifier_replay_protocol_v1.json",
    "kit_claim_limiter": "governance/detached_verifier_claim_limiter_v1.json",
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "public_verifier_detached_receipt": "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_receipt.json",
}

JSON_INPUT_ROLES = {role for role, raw in INPUTS.items() if raw.endswith(".json")}

OUTPUTS = {
    "authoring_contract": "governance/kt_detached_verifier_clean_room_replay_gate_authoring_contract_v1.json",
    "execution_scope": "governance/kt_detached_verifier_clean_room_replay_scope_v1.json",
    "validation_plan": "governance/kt_detached_verifier_clean_room_replay_gate_validation_plan_v1.json",
    "author_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_author_receipt.json",
    "author_report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_author_report.md",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_gate_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_detached_verifier_clean_room_replay_gate_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_detached_verifier_clean_room_replay_gate_v1.py",
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
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed"))


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
    return any(phrase in normalized for phrase in validation.CLAIM_DRIFT_PHRASES)


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
            _fail("RC_KT_DV_REPLAY_GATE_BRANCH_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_DV_REPLAY_GATE_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_DV_REPLAY_GATE_BRANCH_DRIFT", "dirty worktree outside clean-room replay gate scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    try:
        payload = common.load_json_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_DV_REPLAY_GATE_ARTIFACT_MISSING", str(exc))
    if not isinstance(payload, dict):
        _fail("RC_KT_DV_REPLAY_GATE_PREDECESSOR_MISSING", f"{label} must be a JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_DV_REPLAY_GATE_ARTIFACT_MISSING", str(exc))


def _load_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load_json(root, raw, label=role) for role, raw in INPUTS.items() if role in JSON_INPUT_ROLES}
    texts = {role: _read_text(root, raw, label=role) for role, raw in INPUTS.items() if role not in JSON_INPUT_ROLES}
    return payloads, texts


def _binding_rows(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_DV_REPLAY_GATE_ARTIFACT_MISSING", f"missing {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in ("validation_receipt", "validation_contract", "validation_gate", "gate_decision"):
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_DV_REPLAY_GATE_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_DV_REPLAY_GATE_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        required = {
            "clean_room_replay_executed": False,
            "commercial_activation_claimed": False,
            "external_audit_claimed_complete": False,
            "seven_b_amplification_claimed": False,
            "beyond_sota_claimed": False,
            "fp0_or_highway_promoted_to_authority": False,
        }
        for key, expected in required.items():
            if payload.get(key) is not expected:
                _fail("RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH", f"{role}.{key} drifted")
    if payloads["gate_decision"].get("decision") != validation.DECISION:
        _fail("RC_KT_DV_REPLAY_GATE_NEXT_MOVE_DRIFT", "validation gate decision drifted")


def _ensure_validation_bindings_recompute(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    rows = payloads["validation_receipt"].get("input_bindings")
    if not isinstance(rows, list) or not rows:
        _fail("RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH", "validation input_bindings missing")
    for row in rows:
        if not isinstance(row, dict):
            _fail("RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH", "validation binding row malformed")
        raw = str(row.get("path", "")).strip()
        expected = str(row.get("sha256", "")).strip()
        if not raw or len(expected) != 64:
            _fail("RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH", "validation binding incomplete")
        path = common.resolve_path(root, raw)
        if not path.is_file() or file_sha256(path) != expected:
            _fail("RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH", f"source hash mismatch for {raw}")


def _ensure_claim_boundary(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
                if _contains_forbidden_claim(value) and not _is_negative_text_context(value):
                    _fail("RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _contains_forbidden_claim(line) and not _is_negative_text_context(line):
                _fail("RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH", f"{label} line {line_number} contains forbidden claim")


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
        "schema_id": "kt.detached_verifier.clean_room_replay_gate.authoring.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "AUTHORING_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "allowed_outcomes": [
            SELECTED_OUTCOME,
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_AUTHORING_BLOCKED__PATCH_REQUIRED",
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_AUTHORING_INVALID__CLAIM_BOUNDARY_BREACH",
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
        "clean_room_replay_gate_authored": True,
        "clean_room_replay_executed": False,
        "clean_room_replay_completed": False,
        "cannot_execute_clean_room_replay": True,
        "requires_future_validation_before_replay": True,
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
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_AUTHORING_CONTRACT_V1",
            "clean_room_replay_mode": "DETACHED_CLEAN_ROOM_REPLAY_GATE_AUTHORED_ONLY",
            "allowed_clean_room_replay_surface": [
                "detached verifier manifest inspection",
                "evidence bundle replay from bounded manifest",
                "claim board replay without claim expansion",
                "public verifier detached dry-run inputs",
            ],
            "excluded_clean_room_replay_surface": [
                "external audit completion",
                "commercial activation claim authorization",
                "7B amplification proof",
                "beyond-SOTA claim",
                "FP0 or Highway authority promotion",
                "truth-engine law mutation",
                "trust-zone law mutation",
            ],
            "execution_preconditions": [
                "this gate authoring lane protected-merged and replayed on main",
                "future gate validation selects clean-room replay execution",
                "clean-room replay environment declared before execution",
                "all claim boundaries remain false unless separately authorized",
            ],
        }
    )
    return payload


def _scope(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_SCOPE_V1",
            "scope": "AUTHOR_CLEAN_ROOM_REPLAY_GATE_ONLY",
            "can_prepare_replay_inputs": True,
            "can_run_replay": False,
            "can_claim_replay_complete": False,
            "expected_future_execution_artifacts": [
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_execution_receipt.json",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_result.json",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_report.md",
                "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_manifest.json",
            ],
            "failure_paths": [
                "PATCH_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1",
                "FORENSIC_KT_DETACHED_VERIFIER_REPLAY_REVIEW_NEXT",
            ],
        }
    )
    return payload


def _validation_plan(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_VALIDATION_PLAN_V1",
            "validation_lane": NEXT_LAWFUL_MOVE,
            "validation_must_not_execute_replay": True,
            "validation_checks": [
                "predecessor validation replay bound",
                "source hashes recompute",
                "gate scope excludes external audit and commercial activation claims",
                "clean-room replay execution remains false",
                "exact next move is either RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1 or blocked",
                "claim-boundary scanner rejects replay completion text before execution",
            ],
        }
    )
    return payload


def _next_move_receipt(base: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(base)
    payload.update(
        {
            "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_NEXT_LAWFUL_MOVE_RECEIPT",
            "receipt_type": "NEXT_LAWFUL_MOVE",
            "current_authoring_lane": AUTHORITATIVE_LANE,
            "current_authoring_outcome": SELECTED_OUTCOME,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
            "clean_room_replay_executed": False,
        }
    )
    return payload


def _report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Detached Verifier Clean-Room Replay Gate Authoring Report",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Authoring verdict: {SELECTED_OUTCOME}",
            "Clean-room replay executed: false",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
            "This lane authors the clean-room replay gate contract and validation plan only.",
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
    _ensure_validation_bindings_recompute(root, payloads)
    _ensure_claim_boundary(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_DV_REPLAY_GATE_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
        "authoring_contract": _contract(base),
        "execution_scope": _scope(base),
        "validation_plan": _validation_plan(base),
        "author_receipt": {**_contract(base), "artifact_id": "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_AUTHOR_RECEIPT"},
        "next_lawful_move": _next_move_receipt(base),
    }
    for role, payload in outputs.items():
        write_json_stable(common.resolve_path(root, OUTPUTS[role]), payload)
    report_path = common.resolve_path(root, OUTPUTS["author_report"])
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
