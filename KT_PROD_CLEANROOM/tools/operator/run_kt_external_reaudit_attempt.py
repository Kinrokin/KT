from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_external_audit_and_ratification_packet_superlane_v1 as packet
from tools.operator import validate_kt_external_audit_and_ratification_packet_superlane_v1 as validation
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


RUN_BRANCH = "run/kt-external-reaudit-attempt"
REPLAY_BRANCH_PREFIX = "replay/kt-external-reaudit-attempt-on-main"
ALLOWED_BRANCHES = frozenset({RUN_BRANCH, "main"})

AUTHORITATIVE_LANE = "RUN_KT_EXTERNAL_REAUDIT_ATTEMPT"
EXPECTED_PREVIOUS_OUTCOME = validation.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = validation.NEXT_LAWFUL_MOVE

OUTCOME_ACCEPTED = "KT_EXTERNAL_REAUDIT_ACCEPTED__COMMERCIAL_CLAIM_AUTHORIZATION_NEXT"
OUTCOME_DEFERRED = "KT_EXTERNAL_REAUDIT_DEFERRED__NAMED_EXTERNAL_GAP_REMAINS"
OUTCOME_FAILED = "KT_EXTERNAL_REAUDIT_FAILED__FORENSIC_REVIEW_NEXT"

NEXT_ACCEPTED = "AUTHOR_KT_COMMERCIAL_CLAIM_AUTHORIZATION_PACKET"
NEXT_DEFERRED = "COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION"
NEXT_FAILED = "AUTHOR_KT_FORENSIC_EXTERNAL_REAUDIT_REVIEW_PACKET"

OPTIONAL_EXTERNAL_ATTESTATION = "KT_PROD_CLEANROOM/reports/kt_external_reaudit_independent_attestation.json"

INPUTS = {
    "validation_contract": validation.OUTPUTS["validation_contract"],
    "validation_receipt": validation.OUTPUTS["validation_receipt"],
    "validation_scorecard": validation.OUTPUTS["validation_scorecard"],
    "external_reaudit_attempt_gate_decision": validation.OUTPUTS["external_reaudit_attempt_gate_decision"],
    "validation_next_lawful_move": validation.OUTPUTS["next_lawful_move"],
    "audit_packet_contract": packet.OUTPUTS["packet_contract"],
    "audit_packet_external_verifier_manifest": packet.OUTPUTS["external_verifier_manifest"],
    "audit_packet_evidence_bundle_index": packet.OUTPUTS["evidence_bundle_index"],
    "audit_packet_claim_boundary_receipt": packet.OUTPUTS["claim_boundary_receipt"],
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "external_audit_packet_manifest": "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
}

OUTPUTS = {
    "attempt_contract": "governance/kt_external_reaudit_attempt_v1.json",
    "attempt_receipt": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_receipt.json",
    "attempt_report": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_report.md",
    "evidence_manifest": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_evidence_manifest.json",
    "scorecard": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_scorecard.json",
    "decision": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_decision.json",
    "blocker_ledger": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_blocker_ledger.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_external_reaudit_attempt_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/run_kt_external_reaudit_attempt.py",
        "KT_PROD_CLEANROOM/tests/operator/test_run_kt_external_reaudit_attempt.py",
    }
)

REASON_CODES = (
    "RC_KT_EXTERNAL_REAUDIT_PREVIOUS_VALIDATION_MISSING",
    "RC_KT_EXTERNAL_REAUDIT_PREVIOUS_OUTCOME_DRIFT",
    "RC_KT_EXTERNAL_REAUDIT_PREVIOUS_NEXT_MOVE_DRIFT",
    "RC_KT_EXTERNAL_REAUDIT_SOURCE_MISSING",
    "RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED",
    "RC_KT_EXTERNAL_REAUDIT_ATTESTATION_MISSING",
    "RC_KT_EXTERNAL_REAUDIT_ATTESTATION_INVALID",
    "RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT",
    "RC_KT_EXTERNAL_REAUDIT_TRUST_ZONE_FAILED",
)


class LaneFailure(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> NoReturn:
    raise LaneFailure(code, detail)


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
        if (branch == "main" or branch.startswith(REPLAY_BRANCH_PREFIX)) and common.git_rev_parse(root, "HEAD") != common.git_rev_parse(root, "origin/main"):
            _fail("RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT", "main/replay run requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_EXTERNAL_REAUDIT_BRANCH_DRIFT", "dirty worktree outside external re-audit attempt scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str, required: bool = True) -> Dict[str, Any] | None:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        if required:
            _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_MISSING", f"missing {label}: {raw}")
        return None
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_MISSING", f"{label} must be JSON object")
    return payload


def _load_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in INPUTS.items()}  # type: ignore[misc]


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_MISSING", f"missing input {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    attestation_path = common.resolve_path(root, OPTIONAL_EXTERNAL_ATTESTATION)
    if attestation_path.is_file():
        rows.append(
            {
                "role": "independent_external_reaudit_attestation",
                "path": OPTIONAL_EXTERNAL_ATTESTATION,
                "sha256": file_sha256(attestation_path),
            }
        )
    return rows


def _validate_previous(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in ("validation_contract", "validation_receipt", "external_reaudit_attempt_gate_decision", "validation_next_lawful_move"):
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_EXTERNAL_REAUDIT_PREVIOUS_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_EXTERNAL_REAUDIT_PREVIOUS_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("external_reaudit_attempt_next") is not True:
            _fail("RC_KT_EXTERNAL_REAUDIT_PREVIOUS_VALIDATION_MISSING", f"{role} did not select external re-audit attempt next")
        if payload.get("external_reaudit_attempt_executed") is not False:
            _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", f"{role} already claims external re-audit attempt execution")
        if payload.get("external_audit_completed") is not False or payload.get("commercial_claims_authorized") is not False:
            _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", f"{role} claims premature authority")


def _validate_sources(payloads: Dict[str, Dict[str, Any]]) -> None:
    scorecard = payloads["validation_scorecard"]
    if scorecard.get("fail_count") != 0:
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "external audit ratification validation scorecard has failures")
    if not all(row.get("status") == "PASS" for row in scorecard.get("score_rows", []) if isinstance(row, dict)):
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "external audit ratification validation scorecard is not all PASS")

    public_verifier = payloads["public_verifier_manifest"]
    if public_verifier.get("status") != "PASS" or public_verifier.get("publication_receipt_status") != "PASS":
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "public verifier manifest must be PASS")
    if public_verifier.get("subject_verdict") != "PUBLISHED_HEAD_TRANSPARENCY_VERIFIED":
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "public verifier subject must be transparency verified")

    external_manifest = payloads["external_audit_packet_manifest"]
    if str(external_manifest.get("status", "")).upper() != "PASS":
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "external audit packet manifest must be PASS")

    claim_boundary = payloads["audit_packet_claim_boundary_receipt"]
    if claim_boundary.get("commercial_claims_authorized") is not False or claim_boundary.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_EXTERNAL_REAUDIT_SOURCE_STATUS_FAILED", "audit packet claim boundary authorizes commercial claims")


def _evaluate_attestation(root: Path) -> tuple[str, str, list[Dict[str, Any]], Dict[str, Any] | None]:
    attestation = _load_json(root, OPTIONAL_EXTERNAL_ATTESTATION, label="independent_external_reaudit_attestation", required=False)
    if attestation is None:
        return (
            OUTCOME_DEFERRED,
            NEXT_DEFERRED,
            [
                {
                    "blocker_id": "independent_external_reaudit_attestation_missing",
                    "status": "BLOCKING",
                    "required_artifact": OPTIONAL_EXTERNAL_ATTESTATION,
                    "repair": "Collect independent external re-audit attestation before acceptance can be selected.",
                }
            ],
            None,
        )

    required_true = (
        "external_reviewer_independent",
        "review_scope_includes_external_audit_packet",
        "review_scope_includes_public_verifier",
        "review_scope_includes_supply_chain",
        "review_scope_includes_claim_boundary",
        "claims_reviewed_against_claim_ceiling",
    )
    if str(attestation.get("attestation_status", "")).upper() == "ACCEPTED" and all(attestation.get(key) is True for key in required_true):
        return OUTCOME_ACCEPTED, NEXT_ACCEPTED, [], attestation
    if str(attestation.get("attestation_status", "")).upper() in {"FAILED", "REJECTED"}:
        return (
            OUTCOME_FAILED,
            NEXT_FAILED,
            [{"blocker_id": "independent_external_reaudit_rejected", "status": "FORENSIC_REVIEW_REQUIRED"}],
            attestation,
        )
    return (
        OUTCOME_DEFERRED,
        NEXT_DEFERRED,
        [{"blocker_id": "independent_external_reaudit_attestation_incomplete", "status": "BLOCKING"}],
        attestation,
    )


def _base(
    *,
    branch: str,
    head: str,
    current_main_head: str,
    generated_utc: str,
    input_bindings: list[Dict[str, str]],
    trust_zone_validation: Dict[str, Any],
    selected_outcome: str,
    next_lawful_move: str,
) -> Dict[str, Any]:
    accepted = selected_outcome == OUTCOME_ACCEPTED
    deferred = selected_outcome == OUTCOME_DEFERRED
    failed = selected_outcome == OUTCOME_FAILED
    return {
        "schema_id": "kt.external_reaudit_attempt.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "RUN_ONLY",
        "selected_outcome": selected_outcome,
        "next_lawful_move": next_lawful_move,
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
        "source_hashes_recomputed": True,
        "external_reaudit_attempt_executed": True,
        "external_reaudit_attempt_completed": True,
        "external_reaudit_accepted": accepted,
        "external_reaudit_deferred": deferred,
        "external_reaudit_failed": failed,
        "external_audit_completed": accepted,
        "external_audit_claimed_complete": accepted,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_claimed": False,
        "seven_b_amplification_claimed": False,
        "seven_b_amplification_claimed_proven": False,
        "beyond_sota_claimed": False,
        "s_tier_claimed": False,
        "fp0_or_highway_promoted_to_authority": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "truth_engine_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _artifact(base: Dict[str, Any], *, role: str, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id, "artifact_role": role})
    payload.update(extra)
    return payload


def _outputs(base: Dict[str, Any], *, blockers: list[Dict[str, Any]], attestation: Dict[str, Any] | None) -> Dict[str, Any]:
    pass_status = "PASS" if base["selected_outcome"] == OUTCOME_ACCEPTED else "DEFERRED" if base["selected_outcome"] == OUTCOME_DEFERRED else "FAIL"
    score_rows = [
        {"check_id": "h06_validation_canonical", "status": "PASS"},
        {"check_id": "public_verifier_manifest_pass", "status": "PASS"},
        {"check_id": "external_audit_packet_manifest_pass", "status": "PASS"},
        {"check_id": "independent_external_attestation_present", "status": "PASS" if attestation else "DEFERRED"},
        {"check_id": "commercial_claims_not_authorized", "status": "PASS"},
        {"check_id": "truth_trust_law_unchanged", "status": "PASS"},
    ]
    return {
        "attempt_contract": _artifact(
            base,
            role="attempt_contract",
            schema_id="kt.external_reaudit_attempt.contract.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_CONTRACT",
            required_independent_attestation=OPTIONAL_EXTERNAL_ATTESTATION,
            allowed_outcomes=[OUTCOME_ACCEPTED, OUTCOME_DEFERRED, OUTCOME_FAILED],
        ),
        "attempt_receipt": _artifact(
            base,
            role="attempt_receipt",
            schema_id="kt.external_reaudit_attempt.receipt.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_RECEIPT",
            verdict=base["selected_outcome"],
        ),
        "evidence_manifest": _artifact(
            base,
            role="evidence_manifest",
            schema_id="kt.external_reaudit_attempt.evidence_manifest.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_EVIDENCE_MANIFEST",
            evidence_rows=[
                {"role": row["role"], "path": row["path"], "sha256": row["sha256"], "external_review_input": row["role"] == "independent_external_reaudit_attestation"}
                for row in base["input_bindings"]
            ],
        ),
        "scorecard": _artifact(
            base,
            role="scorecard",
            schema_id="kt.external_reaudit_attempt.scorecard.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_SCORECARD",
            score_rows=score_rows,
            status=pass_status,
        ),
        "decision": _artifact(
            base,
            role="decision",
            schema_id="kt.external_reaudit_attempt.decision.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_DECISION",
            decision=base["selected_outcome"],
            independent_attestation_present=attestation is not None,
        ),
        "blocker_ledger": _artifact(
            base,
            role="blocker_ledger",
            schema_id="kt.external_reaudit_attempt.blocker_ledger.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_BLOCKER_LEDGER",
            blockers=blockers,
            blocker_count=len(blockers),
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.external_reaudit_attempt.next_lawful_move.v1",
            artifact_id="KT_EXTERNAL_REAUDIT_ATTEMPT_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=base["selected_outcome"],
            next_lawful_move=base["next_lawful_move"],
        ),
        "attempt_report": _report(base, blockers),
    }


def _report(base: Dict[str, Any], blockers: list[Dict[str, Any]]) -> str:
    return "\n".join(
        [
            "# KT External Re-Audit Attempt",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {base['selected_outcome']}",
            "External re-audit attempt executed: true",
            f"External re-audit accepted: {str(base['external_reaudit_accepted']).lower()}",
            f"External re-audit deferred: {str(base['external_reaudit_deferred']).lower()}",
            f"External re-audit failed: {str(base['external_reaudit_failed']).lower()}",
            f"External audit completed: {str(base['external_audit_completed']).lower()}",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
            f"Blocker count: {len(blockers)}",
            f"Next lawful move: {base['next_lawful_move']}",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_inputs(root)
    _validate_previous(payloads)
    _validate_sources(payloads)
    selected_outcome, next_lawful_move, blockers, attestation = _evaluate_attestation(root)

    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_EXTERNAL_REAUDIT_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
        selected_outcome=selected_outcome,
        next_lawful_move=next_lawful_move,
    )
    outputs = _outputs(base, blockers=blockers, attestation=attestation)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if raw.endswith(".md"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(outputs[role]), encoding="utf-8", newline="\n")
        else:
            write_json_stable(path, outputs[role])
    print(selected_outcome)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Run the KT external re-audit attempt gate.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
