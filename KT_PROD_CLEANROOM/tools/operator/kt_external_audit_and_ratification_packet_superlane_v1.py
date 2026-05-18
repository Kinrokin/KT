from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_adversarial_proof_corridor_superlane_v1 as adversarial_packet
from tools.operator import kt_commercial_proof_plane_superlane_v1 as commercial_plane
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator import kt_supply_chain_release_corridor_superlane_v1 as supply_chain
from tools.operator import validate_kt_adversarial_proof_corridor_superlane_v1 as predecessor
from tools.operator import validate_kt_supply_chain_release_corridor_superlane_v1 as supply_chain_validation
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-external-audit-and-ratification-packet-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-external-audit-and-ratification-packet-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = predecessor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = predecessor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_BOUND__"
    "EXTERNAL_AUDIT_AND_RATIFICATION_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_SUPERLANE_V1"
PREFERRED_VALIDATION_OUTCOME = "KT_EXTERNAL_REAUDIT_PACKET_VALIDATED__EXTERNAL_REAUDIT_ATTEMPT_NEXT"

PREDECESSOR_INPUTS = {
    "h05_validation_contract": predecessor.OUTPUTS["validation_contract"],
    "h05_validation_receipt": predecessor.OUTPUTS["validation_receipt"],
    "h05_validation_scorecard": predecessor.OUTPUTS["validation_scorecard"],
    "h05_external_audit_ratification_gate_decision": predecessor.OUTPUTS["external_audit_ratification_gate_decision"],
    "h05_next_lawful_move": predecessor.OUTPUTS["next_lawful_move"],
}

SOURCE_INPUTS = {
    "h05_packet_contract": adversarial_packet.OUTPUTS["packet_contract"],
    "h05_attack_matrix": adversarial_packet.OUTPUTS["attack_matrix"],
    "h05_claim_boundary_receipt": adversarial_packet.OUTPUTS["claim_boundary_receipt"],
    "detached_verifier_clean_room_evidence_validation": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_evidence_review_validation_receipt.json",
    "detached_verifier_clean_room_replay_result": "KT_PROD_CLEANROOM/reports/kt_detached_verifier_clean_room_replay_result.json",
    "supply_chain_validation_receipt": supply_chain_validation.OUTPUTS["validation_receipt"],
    "supply_chain_release_integrity_receipt": supply_chain.OUTPUTS["release_integrity_receipt"],
    "commercial_proof_plane_evidence_pack_manifest": commercial_plane.OUTPUTS["evidence_pack_manifest"],
    "commercial_proof_plane_security_review_packet": commercial_plane.OUTPUTS["security_review_packet"],
    "commercial_proof_plane_claim_boundary_receipt": commercial_plane.OUTPUTS["claim_boundary_receipt"],
    "claim_ceiling_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    "external_audit_packet_manifest": "KT_PROD_CLEANROOM/reports/external_audit_packet_manifest.json",
}

INPUTS = {**PREDECESSOR_INPUTS, **SOURCE_INPUTS}

OUTPUTS = {
    "packet_contract": "governance/kt_external_audit_and_ratification_packet_superlane_v1.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_packet_report.md",
    "source_manifest": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_source_manifest.json",
    "audit_scope_manifest": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_audit_scope_manifest.json",
    "external_verifier_manifest": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_external_verifier_manifest.json",
    "evidence_bundle_index": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_evidence_bundle_index.json",
    "auditor_instructions": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_auditor_instructions.md",
    "ratification_decision_matrix": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_decision_matrix.json",
    "claim_boundary_receipt": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_claim_boundary_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_external_audit_and_ratification_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_external_audit_and_ratification_packet_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_external_audit_and_ratification_packet_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_MISSING",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_NEXT_MOVE_DRIFT",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_MISSING",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_CLAIM_BOUNDARY_BREACH",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_DECISION_MATRIX_INCOMPLETE",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_REASON_CODE_DUPLICATE",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT",
            "RC_KT_EXTERNAL_AUDIT_RATIFICATION_TRUST_ZONE_FAILED",
        )
    )
)

DECISION_OUTCOMES = (
    "KT_EXTERNAL_REAUDIT_ACCEPTED__COMMERCIAL_CLAIM_AUTHORIZATION_NEXT",
    "KT_EXTERNAL_REAUDIT_DEFERRED__NAMED_EXTERNAL_GAP_REMAINS",
    "KT_EXTERNAL_REAUDIT_FAILED__FORENSIC_REVIEW_NEXT",
)

AUTHORITY_DRIFT_KEYS = predecessor.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "external_audit_and_ratification_packet_authored",
        "external_audit_and_ratification_authoring_complete",
        "external_audit_and_ratification_validation_next",
        "external_audit_and_ratification_validated",
        "external_audit_ratification_packet_authorized",
        "external_reaudit_attempt_authorized",
        "external_reaudit_accepted",
        "external_audit_completed",
        "external_audit_claimed_complete",
        "commercial_claims_authorized",
        "commercial_activation_claim_authorized",
        "commercial_activation_claims_authorized",
        "seven_b_amplification_claimed_proven",
        "beyond_sota_claimed",
        "s_tier_claimed",
        "fp0_or_highway_promoted_to_authority",
    }
)

ALLOWED_AUTHORITY_TRUE_KEYS = predecessor.ALLOWED_AUTHORITY_TRUE_KEYS | frozenset(
    {
        "external_audit_and_ratification_packet_authored",
        "external_audit_and_ratification_authoring_complete",
        "external_audit_and_ratification_validation_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "adversarial_proof_corridor_validated",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = predecessor.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed|accepted)\b", re.IGNORECASE),
    re.compile(r"\bexternal reaudit (?:is )?accepted\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation claims (?:are )?authorized\b", re.IGNORECASE),
    re.compile(r"\bcommercial claims (?:are )?authorized\b", re.IGNORECASE),
    re.compile(r"\bkt is production-commercial live\b", re.IGNORECASE),
    re.compile(r"\b7b amplification (?:is )?(?:proven|validated)\b", re.IGNORECASE),
    re.compile(r"\bbeyond-sota (?:is )?(?:proven|validated|claimed)\b", re.IGNORECASE),
    re.compile(r"\bs-tier (?:claim )?(?:is )?(?:allowed|proven|validated)\b", re.IGNORECASE),
)

MACHINE_ROUTING_FIELDS = adversarial_packet.MACHINE_ROUTING_FIELDS | frozenset(
    {
        "allowed_outcomes",
        "decision_outcomes",
        "preferred_validation_outcome",
    }
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
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT", "main/replay authoring requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT", "dirty worktree outside external audit ratification scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_MISSING", f"{label} must be JSON object")
    return payload


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_MISSING", f"missing input {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _load_json_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {role: _load_json(root, raw, label=role) for role, raw in INPUTS.items() if raw.endswith(".json")}


def _validate_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in PREDECESSOR_INPUTS:
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("adversarial_proof_corridor_validated") is not True:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_MISSING", f"{role} did not validate adversarial proof corridor")
        if payload.get("external_audit_ratification_packet_next") is not True:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_MISSING", f"{role} did not select external audit ratification next")
        if payload.get("external_audit_ratification_packet_authorized") is not False:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", f"{role} prematurely authorizes audit ratification")


def _leaf_key(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1].replace("[]", "")
    return re.sub(r"\[\d+\]$", "", leaf)


def _is_machine_routing_field(key: str) -> bool:
    return _leaf_key(key) in MACHINE_ROUTING_FIELDS or predecessor._is_machine_routing_field(key) or evidence_packet._is_machine_routing_field(key)  # noqa: SLF001


def _is_negative_field(key: str) -> bool:
    return predecessor._is_negative_field(key) or evidence_packet._is_negative_field(key)  # noqa: SLF001


def _is_negative_text(text: str) -> bool:
    return predecessor._is_negative_text(text) or evidence_packet._is_negative_text(text)  # noqa: SLF001


def _explicit_false_clause(text: str) -> bool:
    return bool(re.search(r":\s*false\s*$", text.strip(), flags=re.IGNORECASE))


def _scan_claim_text(label: str, text: str) -> None:
    clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", text, flags=re.IGNORECASE)
    for clause in clauses:
        if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not (_is_negative_text(clause) or _explicit_false_clause(clause)):
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_CLAIM_BOUNDARY_BREACH", f"{label} contains forbidden affirmative claim: {clause.strip()!r}")


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001 - use existing hardened recursive walker.
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            _scan_claim_text(f"{label}.{key}", value)


def _validate_sources(payloads: Dict[str, Dict[str, Any]]) -> None:
    clean_room_validation = payloads["detached_verifier_clean_room_evidence_validation"]
    if clean_room_validation.get("clean_room_replay_evidence_review_packet_validated") is not True:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED", "detached verifier evidence review is not validated")
    if clean_room_validation.get("external_audit_completed") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "detached verifier evidence claims external audit completion")

    supply_validation = payloads["supply_chain_validation_receipt"]
    if supply_validation.get("supply_chain_release_corridor_packet_validated") is not True:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED", "supply chain release corridor is not validated")
    if supply_validation.get("external_audit_completed") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "supply chain validation claims external audit completion")

    commercial_boundary = payloads["commercial_proof_plane_claim_boundary_receipt"]
    if commercial_boundary.get("no_claim_expansion") is not True:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED", "commercial proof plane claim boundary must preserve no_claim_expansion")
    if commercial_boundary.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "commercial proof plane authorizes commercial claims")
    if commercial_boundary.get("external_audit_completed") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "commercial proof plane claims external audit completion")

    security_packet = payloads["commercial_proof_plane_security_review_packet"]
    if security_packet.get("external_audit_completed") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "commercial proof plane security packet claims external audit completion")

    external_manifest = payloads["external_audit_packet_manifest"]
    if str(external_manifest.get("status", "")).upper() != "PASS":
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED", "external audit packet manifest must be PASS")

    claim_ceiling = payloads["claim_ceiling_current_state"]
    if claim_ceiling.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "claim ceiling authorizes commercial activation claims")
    if claim_ceiling.get("benchmark_prep_authorizes_commercial_activation") is not False:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "benchmark prep authorizes commercial activation")

    for role, payload in payloads.items():
        _scan_claim_boundary(role, payload)


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
        "schema_id": "kt.external_audit_and_ratification_packet.authoring.v1",
        "authoritative_lane": AUTHORITATIVE_LANE,
        "authority": "AUTHORING_ONLY",
        "selected_outcome": SELECTED_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "preferred_validation_outcome": PREFERRED_VALIDATION_OUTCOME,
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
        "adversarial_proof_corridor_validated": True,
        "external_audit_and_ratification_packet_authored": True,
        "external_audit_and_ratification_authoring_complete": True,
        "external_audit_and_ratification_validation_next": True,
        "external_audit_and_ratification_validated": False,
        "external_audit_ratification_packet_authorized": False,
        "external_reaudit_attempt_authorized": False,
        "external_reaudit_accepted": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
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
        "claim_boundary_passed": True,
    }


def _artifact(base: Dict[str, Any], *, role: str, schema_id: str, artifact_id: str, **extra: Any) -> Dict[str, Any]:
    payload = dict(base)
    payload.update({"schema_id": schema_id, "artifact_id": artifact_id, "artifact_role": role})
    payload.update(extra)
    return payload


def _manifest_rows(input_bindings: list[Dict[str, str]]) -> list[Dict[str, str]]:
    return [
        {"role": row["role"], "path": row["path"], "sha256": row["sha256"], "required_for_validation": True}
        for row in input_bindings
    ]


def _audit_scope_rows() -> list[Dict[str, Any]]:
    return [
        {"scope_id": "truth_lock_and_current_posture", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "detached_verifier_clean_room_replay", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "supply_chain_release_integrity", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "claim_compiler_and_commercial_language_gate", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "commercial_proof_plane", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "adversarial_proof_corridor", "required": True, "status": "PACKET_BOUND"},
        {"scope_id": "benchmark_or_7b_superiority", "required": False, "status": "NOT_CLAIMED"},
        {"scope_id": "commercial_claim_authorization", "required": False, "status": "NOT_AUTHORIZED"},
    ]


def _evidence_bundle_rows(input_bindings: list[Dict[str, str]]) -> list[Dict[str, Any]]:
    return [
        {
            "evidence_id": row["role"],
            "path": row["path"],
            "sha256": row["sha256"],
            "auditor_visible": True,
            "canonical_input": row["role"] in PREDECESSOR_INPUTS,
        }
        for row in input_bindings
    ]


def _decision_rows() -> list[Dict[str, Any]]:
    return [
        {
            "outcome": "KT_EXTERNAL_REAUDIT_ACCEPTED__COMMERCIAL_CLAIM_AUTHORIZATION_NEXT",
            "status": "AVAILABLE_TO_VALIDATION_ONLY",
            "selected_now": False,
            "requires_external_review_evidence": True,
        },
        {
            "outcome": "KT_EXTERNAL_REAUDIT_DEFERRED__NAMED_EXTERNAL_GAP_REMAINS",
            "status": "AVAILABLE_TO_VALIDATION_ONLY",
            "selected_now": False,
            "requires_external_review_evidence": True,
        },
        {
            "outcome": "KT_EXTERNAL_REAUDIT_FAILED__FORENSIC_REVIEW_NEXT",
            "status": "AVAILABLE_TO_VALIDATION_ONLY",
            "selected_now": False,
            "requires_external_review_evidence": True,
        },
    ]


def _validation_checks() -> list[str]:
    return [
        "recompute_h05_adversarial_validation_bindings",
        "verify_detached_verifier_evidence_review_validated",
        "verify_supply_chain_release_corridor_validated",
        "verify_external_audit_packet_manifest_pass",
        "verify_claim_boundary_no_expansion",
        "reject_external_audit_completion_claim",
        "reject_external_reaudit_acceptance_claim",
        "reject_commercial_claim_authorization",
        "reject_7b_beyond_sota_s_tier_claims",
        "preserve_truth_and_trust_law",
        "preserve_fp0_highway_nonpromotion",
    ]


def _outputs(base: Dict[str, Any]) -> Dict[str, Any]:
    input_bindings = list(base["input_bindings"])
    deliverables = [
        OUTPUTS["source_manifest"],
        OUTPUTS["audit_scope_manifest"],
        OUTPUTS["external_verifier_manifest"],
        OUTPUTS["evidence_bundle_index"],
        OUTPUTS["auditor_instructions"],
        OUTPUTS["ratification_decision_matrix"],
        OUTPUTS["claim_boundary_receipt"],
        OUTPUTS["validation_plan"],
        OUTPUTS["validation_reason_codes"],
    ]
    validation_checks = _validation_checks()
    return {
        "packet_contract": _artifact(
            base,
            role="packet_contract",
            schema_id="kt.external_audit_and_ratification.packet_contract.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_CONTRACT",
            deliverables=deliverables,
            validation_checks=validation_checks,
            audit_scope="external audit and ratification packet authoring only; no external audit acceptance",
        ),
        "packet_receipt": _artifact(
            base,
            role="packet_receipt",
            schema_id="kt.external_audit_and_ratification.packet_receipt.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_RECEIPT",
            verdict="EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_BOUND_VALIDATION_NEXT",
            deliverable_count=len(deliverables),
        ),
        "source_manifest": _artifact(
            base,
            role="source_manifest",
            schema_id="kt.external_audit_and_ratification.source_manifest.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_SOURCE_MANIFEST",
            sources=_manifest_rows(input_bindings),
        ),
        "audit_scope_manifest": _artifact(
            base,
            role="audit_scope_manifest",
            schema_id="kt.external_audit_and_ratification.audit_scope_manifest.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_AUDIT_SCOPE_MANIFEST",
            scope_rows=_audit_scope_rows(),
        ),
        "external_verifier_manifest": _artifact(
            base,
            role="external_verifier_manifest",
            schema_id="kt.external_audit_and_ratification.external_verifier_manifest.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_EXTERNAL_VERIFIER_MANIFEST",
            detached_verifier_required=True,
            clean_room_replay_evidence_required=True,
            external_audit_completed=False,
        ),
        "evidence_bundle_index": _artifact(
            base,
            role="evidence_bundle_index",
            schema_id="kt.external_audit_and_ratification.evidence_bundle_index.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_EVIDENCE_BUNDLE_INDEX",
            evidence_rows=_evidence_bundle_rows(input_bindings),
        ),
        "auditor_instructions": _auditor_instructions(base),
        "ratification_decision_matrix": _artifact(
            base,
            role="ratification_decision_matrix",
            schema_id="kt.external_audit_and_ratification.decision_matrix.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_DECISION_MATRIX",
            decision_rows=_decision_rows(),
            decision_selected_now=False,
        ),
        "claim_boundary_receipt": _artifact(
            base,
            role="claim_boundary_receipt",
            schema_id="kt.external_audit_and_ratification.claim_boundary_receipt.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_CLAIM_BOUNDARY_RECEIPT",
            no_claim_expansion=True,
        ),
        "validation_plan": _artifact(
            base,
            role="validation_plan",
            schema_id="kt.external_audit_and_ratification.validation_plan.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_VALIDATION_PLAN",
            validation_checks=validation_checks,
            expected_validation_outcome=PREFERRED_VALIDATION_OUTCOME,
            allowed_external_reaudit_outcomes=list(DECISION_OUTCOMES),
        ),
        "validation_reason_codes": _artifact(
            base,
            role="validation_reason_codes",
            schema_id="kt.external_audit_and_ratification.validation_reason_codes.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.external_audit_and_ratification.next_lawful_move.v1",
            artifact_id="KT_EXTERNAL_AUDIT_AND_RATIFICATION_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "packet_report": _packet_report(base),
    }


def _auditor_instructions(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT External Audit And Ratification Packet Instructions",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "This packet prepares external audit and ratification validation.",
            "External audit completed: false",
            "External reaudit accepted: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
            "FP0 or highway promoted to authority: false",
            "Truth-engine law unchanged: true",
            "Trust-zone law unchanged: true",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def _packet_report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT External Audit And Ratification Packet",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "External audit and ratification packet authored: true",
            "External audit and ratification validated: false",
            "External audit completed: false",
            "External reaudit accepted: false",
            "External reaudit attempt authorized: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
            "FP0 or highway promoted to authority: false",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def _validate_decision_matrix(outputs: Dict[str, Any]) -> None:
    matrix = outputs["ratification_decision_matrix"]
    rows = matrix.get("decision_rows", [])
    if not isinstance(rows, list) or len(rows) != len(DECISION_OUTCOMES):
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_DECISION_MATRIX_INCOMPLETE", "decision matrix row count mismatch")
    outcomes = {row.get("outcome") for row in rows if isinstance(row, dict)}
    missing = set(DECISION_OUTCOMES) - outcomes
    if missing:
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_DECISION_MATRIX_INCOMPLETE", "decision matrix missing outcomes: " + ", ".join(sorted(missing)))
    if any(row.get("selected_now") is not False for row in rows if isinstance(row, dict)):
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY", "decision matrix selected external audit outcome during authoring")


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_json_inputs(root)
    _validate_predecessor(payloads)
    _validate_sources(payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_EXTERNAL_AUDIT_RATIFICATION_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=_input_bindings(root),
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base)
    _validate_decision_matrix(outputs)
    for role, raw in OUTPUTS.items():
        path = common.resolve_path(root, raw)
        if raw.endswith(".md"):
            path.parent.mkdir(parents=True, exist_ok=True)
            text = str(outputs[role])
            _scan_claim_text(role, text)
            path.write_text(text, encoding="utf-8", newline="\n")
        else:
            _scan_claim_boundary(role, outputs[role])
            write_json_stable(path, outputs[role])
    print(SELECTED_OUTCOME)
    return outputs


def _parse_args() -> argparse.Namespace:
    return argparse.ArgumentParser(description="Author the KT external audit and ratification packet superlane.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
