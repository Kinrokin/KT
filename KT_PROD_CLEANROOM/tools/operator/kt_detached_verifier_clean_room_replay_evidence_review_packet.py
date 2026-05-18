from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import run_kt_detached_verifier_clean_room_replay_gate_v1 as replay
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-detached-verifier-clean-room-replay-evidence-review-packet"
REPLAY_BRANCH_PREFIX = "replay/kt-detached-verifier-clean-room-replay-evidence-review-packet-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"
EXPECTED_PREVIOUS_OUTCOME = replay.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = replay.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET_BOUND__"
    "EVIDENCE_REVIEW_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"
PREFERRED_VALIDATION_OUTCOME = (
    "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATED__"
    "SUPPLY_CHAIN_RELEASE_CORRIDOR_NEXT"
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PREDECESSOR_MISSING",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_NEXT_MOVE_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_ARTIFACT_MISSING",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PUBLIC_VERIFIER_NOT_PASS",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_BRANCH_DRIFT",
            "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_TRUST_ZONE_FAILED",
        )
    )
)

INPUTS = {
    "execution_receipt": replay.OUTPUTS["execution_receipt"],
    "result": replay.OUTPUTS["result"],
    "evidence_manifest": replay.OUTPUTS["evidence_manifest"],
    "execution_report": replay.OUTPUTS["report"],
    "run_next_lawful_move": replay.OUTPUTS["next_lawful_move"],
    **{f"public_verifier_{role}": raw for role, raw in replay.PUBLIC_VERIFIER_OUTPUTS.items()},
}

JSON_INPUT_ROLES = {role for role, raw in INPUTS.items() if raw.endswith(".json")}

OUTPUTS = {
    "packet_contract": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_packet_report.md",
    "evidence_inventory": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_inventory.json",
    "evidence_scorecard": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_scorecard.json",
    "supply_chain_readiness_matrix": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_supply_chain_readiness_matrix.json",
    "external_audit_readiness_matrix": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_external_audit_readiness_matrix.json",
    "claim_boundary_review": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_claim_boundary_review.json",
    "no_authority_drift_receipt": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_no_authority_drift_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_detached_verifier_clean_room_replay_evidence_review_packet.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_detached_verifier_clean_room_replay_evidence_review_packet.py",
    }
)

AUTHORITY_DRIFT_KEYS = frozenset(
    {
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

FORBIDDEN_CLAIM_PATTERNS = (
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed)\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation claims? (?:are |is )?authorized\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation (?:is )?(?:complete|live|authorized)\b", re.IGNORECASE),
    re.compile(r"\b7b amplification (?:is )?(?:proven|validated|complete)\b", re.IGNORECASE),
    re.compile(r"\bbeyond[- ]sota (?:is )?(?:proven|validated|allowed)\b", re.IGNORECASE),
    re.compile(r"\bs[- ]tier (?:is )?(?:claimed|validated|allowed)\b", re.IGNORECASE),
    re.compile(r"\b(?:fp0|highway shadow).{0,40}\b(?:canonical authority|promoted to authority)\b", re.IGNORECASE),
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
            yield from _walk(item, str(key))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                yield from _walk(item, parent_key)
            else:
                yield parent_key, item
    else:
        yield parent_key, value


def _is_negative_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("forbidden", "blocked", "prohibited", "cannot", "disallowed", "refusal"))


def _is_machine_routing_field(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("outcome", "next_lawful_move", "allowed_outcomes", "artifact_id", "schema_id", "lane"))


def _is_negative_text(value: str) -> bool:
    lowered = value.lower()
    if re.search(r"\b(?:authorized|claimed|complete|completed|proven|promoted|live|allowed)\s*[:=]\s*false\b", lowered):
        return True
    return any(
        marker in lowered
        for marker in (
            "not authorized",
            "not proven",
            "not complete",
            "not completed",
            "does not claim",
            "does not authorize",
            "must not claim",
            "remains unauthorized",
            "requires separate",
            "requires a separate",
            "forbidden",
            "blocked",
            "prohibited",
        )
    )


def _has_forbidden_claim(value: str) -> bool:
    clauses = re.split(r"\b(?:but|however|although|though)\b|[.;\n]", value, flags=re.IGNORECASE)
    return any(any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not _is_negative_text(clause) for clause in clauses)


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
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_BRANCH_DRIFT", "main replay requires HEAD to equal origin/main")
        return branch
    _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_BRANCH_DRIFT", "dirty worktree outside evidence-review scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_ARTIFACT_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_ARTIFACT_MISSING", f"{label} must be JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    try:
        return common.read_text_required(root, raw, label=label)
    except Exception as exc:  # noqa: BLE001
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_ARTIFACT_MISSING", str(exc))


def _load_inputs(root: Path) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    payloads = {role: _load_json(root, raw, label=role) for role, raw in INPUTS.items() if role in JSON_INPUT_ROLES}
    texts = {role: _read_text(root, raw, label=role) for role, raw in INPUTS.items() if role not in JSON_INPUT_ROLES}
    return payloads, texts


def _binding_rows(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_ARTIFACT_MISSING", f"missing {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _ensure_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in ("execution_receipt", "result", "run_next_lawful_move"):
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("clean_room_replay_executed") is not True or payload.get("clean_room_replay_passed") is not True:
            _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PREDECESSOR_MISSING", f"{role} does not prove replay pass")
    if payloads["public_verifier_detached_receipt"].get("status") != "PASS":
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PUBLIC_VERIFIER_NOT_PASS", "detached verifier receipt did not pass")
    if payloads["public_verifier_detached_runtime_receipt"].get("status") != "PASS":
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PUBLIC_VERIFIER_NOT_PASS", "detached runtime receipt did not pass")
    env = payloads["public_verifier_detached_runtime_receipt"].get("detached_environment", {})
    if env.get("detached_root_detected") is not True or env.get("git_head_available") is not False:
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PUBLIC_VERIFIER_NOT_PASS", "detached runtime environment proof drifted")


def _ensure_claim_boundary(payloads: Dict[str, Dict[str, Any]], texts: Dict[str, str]) -> None:
    for label, payload in payloads.items():
        for key, value in _walk(payload):
            if key in AUTHORITY_DRIFT_KEYS and value is not False:
                _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
            if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
                if _has_forbidden_claim(value):
                    _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH", f"{label}.{key}={value!r}")
    for label, text in texts.items():
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _has_forbidden_claim(line):
                _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH", f"{label} line {line_number} contains forbidden claim")


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
        "schema_id": "kt.detached_verifier.clean_room_replay.evidence_review.packet.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "AUTHORING_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "preferred_validation_outcome": PREFERRED_VALIDATION_OUTCOME,
        "allowed_validation_outcomes": [
            PREFERRED_VALIDATION_OUTCOME,
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATED__EXTERNAL_AUDIT_DELTA_PACKET_NEXT",
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_DEFERRED__NAMED_REVIEW_DEFECT_REMAINS",
            "KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_INVALID__FORENSIC_REVIEW_NEXT",
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
        "clean_room_replay_executed": True,
        "clean_room_replay_completed": True,
        "clean_room_replay_passed": True,
        "evidence_review_packet_authored": True,
        "evidence_review_validated": False,
        "supply_chain_release_corridor_authorized": False,
        "external_audit_claimed_complete": False,
        "external_audit_completed": False,
        "commercial_activation_claimed": False,
        "commercial_activation_claim_authorized": False,
        "seven_b_amplification_claimed": False,
        "seven_b_amplification_claimed_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "fp0_or_highway_promoted_to_authority": False,
        "highway_shadow_promoted_to_authority": False,
        "fp0_overlay_promoted_to_authority": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "claim_boundary_passed": True,
    }


def _artifact(base: Dict[str, Any], *, role: str, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id, "artifact_role": role})
    payload.update(extra)
    return payload


def _outputs(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    inventory_rows = [{"role": row["role"], "path": row["path"], "sha256": row["sha256"]} for row in base["input_bindings"]]
    scorecard = {
        "overall_grade": "PASS",
        "recommendation": "VALIDATE_EVIDENCE_REVIEW_PACKET_BEFORE_SUPPLY_CHAIN_RELEASE_CORRIDOR",
        "clean_room_replay_passed": True,
        "detached_runtime_without_repo_checkout": True,
        "public_verifier_passed": True,
        "claim_boundary_preserved": True,
        "supply_chain_corridor_ready_for_validation_if_packet_validates": True,
    }
    return {
        "packet_contract": _artifact(base, role="packet_contract", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.contract.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET_CONTRACT"),
        "packet_receipt": _artifact(base, role="packet_receipt", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.receipt.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET_RECEIPT", verdict="BOUND_FOR_VALIDATION"),
        "evidence_inventory": _artifact(base, role="evidence_inventory", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.inventory.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_INVENTORY", evidence_artifacts=inventory_rows),
        "evidence_scorecard": _artifact(base, role="evidence_scorecard", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.scorecard.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_SCORECARD", scorecard=scorecard),
        "supply_chain_readiness_matrix": _artifact(base, role="supply_chain_readiness_matrix", schema_id="kt.detached_verifier.clean_room_replay.supply_chain_readiness.v1", artifact_id="KT_DETACHED_VERIFIER_SUPPLY_CHAIN_READINESS_MATRIX", ready_for_validation_next=True, authorized_now=False, blockers=["evidence_review_packet_not_validated"]),
        "external_audit_readiness_matrix": _artifact(base, role="external_audit_readiness_matrix", schema_id="kt.detached_verifier.clean_room_replay.external_audit_readiness.v1", artifact_id="KT_DETACHED_VERIFIER_EXTERNAL_AUDIT_READINESS_MATRIX", external_audit_complete=False, ready_for_external_audit=False, blockers=["supply_chain_release_corridor_not_validated"]),
        "claim_boundary_review": _artifact(base, role="claim_boundary_review", schema_id="kt.detached_verifier.clean_room_replay.claim_boundary_review.v1", artifact_id="KT_DETACHED_VERIFIER_CLAIM_BOUNDARY_REVIEW", allowed_claims=["Detached verifier clean-room replay evidence exists for validation."], forbidden_claims=["External audit is complete.", "Commercial activation claims are authorized.", "7B amplification is proven.", "Beyond-SOTA is proven.", "S-tier is allowed."]),
        "no_authority_drift_receipt": _artifact(base, role="no_authority_drift_receipt", schema_id="kt.detached_verifier.clean_room_replay.no_authority_drift.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_NO_AUTHORITY_DRIFT_RECEIPT", no_authority_drift=True),
        "validation_plan": _artifact(base, role="validation_plan", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.validation_plan.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VALIDATION_PLAN", validation_success_outcome=PREFERRED_VALIDATION_OUTCOME, validation_must_not_claim_external_audit=True),
        "validation_reason_codes": _artifact(base, role="validation_reason_codes", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.reason_codes.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_REASON_CODES", reason_codes=list(REASON_CODES)),
        "next_lawful_move": _artifact(base, role="next_lawful_move", schema_id="kt.detached_verifier.clean_room_replay.evidence_review.next_lawful_move.v1", artifact_id="KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_NEXT_LAWFUL_MOVE_RECEIPT", current_execution_lane=AUTHORITATIVE_LANE, current_execution_outcome=SELECTED_OUTCOME, next_lawful_move=NEXT_LAWFUL_MOVE),
        "packet_report": _report(base, payloads),
    }


def _report(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]]) -> str:
    runtime_env = payloads["public_verifier_detached_runtime_receipt"].get("detached_environment", {})
    return "\n".join(
        [
            "# KT Detached Verifier Clean-Room Replay Evidence Review Packet",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Authoring verdict: {SELECTED_OUTCOME}",
            "Clean-room replay executed: true",
            f"Detached root detected: {runtime_env.get('detached_root_detected')}",
            "External audit completed: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Highway/FP0 authority promoted: false",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
            "This packet reviews clean-room replay evidence and prepares validation.",
            "It does not authorize the supply-chain release corridor until validation selects that next gate.",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads, texts = _load_inputs(root)
    _ensure_predecessor(payloads)
    _ensure_claim_boundary(payloads, texts)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=_binding_rows(root),
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base, payloads)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if role == "packet_report":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(outputs[role]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Author the KT detached verifier clean-room replay evidence-review packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
