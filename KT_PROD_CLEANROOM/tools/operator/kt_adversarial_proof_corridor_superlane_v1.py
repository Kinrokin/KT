from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_commercial_proof_plane_superlane_v1 as commercial_plane
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator import validate_kt_commercial_proof_plane_superlane_v1 as predecessor
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-adversarial-proof-corridor-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-adversarial-proof-corridor-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_ADVERSARIAL_PROOF_CORRIDOR_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = predecessor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = predecessor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_ADVERSARIAL_PROOF_CORRIDOR_PACKET_BOUND__"
    "ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_ADVERSARIAL_PROOF_CORRIDOR_SUPERLANE_V1"
PREFERRED_VALIDATION_OUTCOME = "KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATED__EXTERNAL_AUDIT_RATIFICATION_PACKET_NEXT"

PREDECESSOR_INPUTS = {
    "h04_validation_contract": predecessor.OUTPUTS["validation_contract"],
    "h04_validation_receipt": predecessor.OUTPUTS["validation_receipt"],
    "h04_validation_scorecard": predecessor.OUTPUTS["validation_scorecard"],
    "h04_adversarial_proof_corridor_gate_decision": predecessor.OUTPUTS["adversarial_proof_corridor_gate_decision"],
    "h04_next_lawful_move": predecessor.OUTPUTS["next_lawful_move"],
}

SOURCE_INPUTS = {
    "commercial_proof_plane_packet_contract": commercial_plane.OUTPUTS["packet_contract"],
    "commercial_proof_plane_evidence_pack_manifest": commercial_plane.OUTPUTS["evidence_pack_manifest"],
    "commercial_proof_plane_security_review_packet": commercial_plane.OUTPUTS["security_review_packet"],
    "commercial_proof_plane_claim_boundary_receipt": commercial_plane.OUTPUTS["claim_boundary_receipt"],
    "commercial_proof_plane_customer_safe_language": commercial_plane.OUTPUTS["customer_safe_language"],
    "claim_ceiling_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
}

INPUTS = {**PREDECESSOR_INPUTS, **SOURCE_INPUTS}

OUTPUTS = {
    "corridor_contract": "governance/kt_adversarial_proof_corridor_superlane_v1.json",
    "packet_contract": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_packet_report.md",
    "source_manifest": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_source_manifest.json",
    "attack_matrix": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_attack_matrix.json",
    "mutation_fixture_manifest": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_mutation_fixture_manifest.json",
    "red_team_protocol": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_red_team_protocol.json",
    "claim_boundary_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_claim_boundary_attack_plan.json",
    "supply_chain_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_supply_chain_attack_plan.json",
    "verifier_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_verifier_attack_plan.json",
    "runtime_escape_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_runtime_escape_attack_plan.json",
    "context_corruption_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_context_corruption_attack_plan.json",
    "evidence_capture_attack_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_evidence_capture_attack_plan.json",
    "claim_boundary_receipt": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_claim_boundary_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_adversarial_proof_corridor_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_adversarial_proof_corridor_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_adversarial_proof_corridor_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_MISSING",
            "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_NEXT_MOVE_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_SOURCE_MISSING",
            "RC_KT_ADVERSARIAL_PROOF_SOURCE_STATUS_FAILED",
            "RC_KT_ADVERSARIAL_PROOF_CLAIM_BOUNDARY_BREACH",
            "RC_KT_ADVERSARIAL_PROOF_ATTACK_MATRIX_INCOMPLETE",
            "RC_KT_ADVERSARIAL_PROOF_REASON_CODE_DUPLICATE",
            "RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY",
            "RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT",
            "RC_KT_ADVERSARIAL_PROOF_TRUST_ZONE_FAILED",
        )
    )
)

ATTACK_CLASSES = (
    "forged_receipts",
    "forged_sboms",
    "forged_rekor_bundles",
    "tuf_rollback_or_freeze",
    "prompt_injection",
    "tool_injection",
    "claim_ceiling_mutation",
    "mutable_overwritten_artifact_replay",
    "benchmark_contamination",
    "evaluator_capture",
    "credential_leakage",
    "ci_privilege_escalation",
    "adapter_schema_drift",
    "router_authority_drift",
    "self_written_skill_abuse",
    "contained_subagent_escape",
    "toon_context_corruption",
    "local_model_overclaiming",
    "high_risk_state_without_claim_ceiling_tightening",
)

AUTHORITY_DRIFT_KEYS = predecessor.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "adversarial_proof_corridor_packet_authored",
        "adversarial_proof_corridor_validation_next",
        "adversarial_proof_corridor_authorized",
        "adversarial_proof_corridor_validated",
        "adversarial_proof_corridor_active",
        "adversarial_attacks_executed",
        "external_audit_completed",
        "external_audit_claimed_complete",
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
        "adversarial_proof_corridor_packet_authored",
        "adversarial_proof_corridor_authoring_complete",
        "adversarial_proof_corridor_validation_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "commercial_proof_plane_validated",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = predecessor.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\badversarial proof corridor (?:is )?(?:validated|active|complete|completed)\b", re.IGNORECASE),
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed)\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation claims (?:are )?authorized\b", re.IGNORECASE),
    re.compile(r"\b7b amplification (?:is )?(?:proven|validated)\b", re.IGNORECASE),
    re.compile(r"\bbeyond-sota (?:is )?(?:proven|validated|claimed)\b", re.IGNORECASE),
    re.compile(r"\bs-tier (?:claim )?(?:is )?(?:allowed|proven|validated)\b", re.IGNORECASE),
)

MACHINE_ROUTING_FIELDS = commercial_plane.MACHINE_ROUTING_FIELDS | frozenset(
    {
        "preferred_validation_outcome",
        "external_audit_ratification_packet_next",
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
            _fail("RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT", "main/replay authoring requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT", "dirty worktree outside adversarial proof corridor scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_ADVERSARIAL_PROOF_SOURCE_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_ADVERSARIAL_PROOF_SOURCE_MISSING", f"{label} must be JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_ADVERSARIAL_PROOF_SOURCE_MISSING", f"missing {label}: {raw}")
    return path.read_text(encoding="utf-8")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_ADVERSARIAL_PROOF_SOURCE_MISSING", f"missing input {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _load_json_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    return {
        role: _load_json(root, raw, label=role)
        for role, raw in INPUTS.items()
        if raw.endswith(".json")
    }


def _validate_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in PREDECESSOR_INPUTS:
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("commercial_proof_plane_validated") is not True:
            _fail("RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_MISSING", f"{role} did not validate commercial proof plane")
        if payload.get("adversarial_proof_corridor_next") is not True:
            _fail("RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_MISSING", f"{role} did not select adversarial proof corridor next")
        if payload.get("adversarial_proof_corridor_authorized") is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", f"{role} prematurely authorizes adversarial proof corridor")


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
            _fail("RC_KT_ADVERSARIAL_PROOF_CLAIM_BOUNDARY_BREACH", f"{label} contains forbidden affirmative claim: {clause.strip()!r}")


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001 - reuse hardened recursive walker.
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_ADVERSARIAL_PROOF_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            _scan_claim_text(f"{label}.{key}", value)


def _validate_sources(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    boundary = payloads["commercial_proof_plane_claim_boundary_receipt"]
    if boundary.get("no_claim_expansion") is not True:
        _fail("RC_KT_ADVERSARIAL_PROOF_SOURCE_STATUS_FAILED", "commercial proof plane claim boundary must preserve no_claim_expansion")
    if boundary.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "commercial proof plane authorizes commercial activation claims")
    if boundary.get("external_audit_completed") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "commercial proof plane claims external audit completion")

    evidence_manifest = payloads["commercial_proof_plane_evidence_pack_manifest"]
    if evidence_manifest.get("evidence_pack_authorizes_commercial_activation_claims") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "commercial evidence pack authorizes commercial activation claims")

    security_packet = payloads["commercial_proof_plane_security_review_packet"]
    if security_packet.get("external_audit_completed") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "security packet claims external audit completion")

    claim_ceiling = payloads["claim_ceiling_current_state"]
    if claim_ceiling.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "claim ceiling authorizes commercial activation claims")
    if claim_ceiling.get("benchmark_prep_authorizes_commercial_activation") is not False:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "benchmark prep authorizes commercial activation")

    public_verifier = payloads["public_verifier_manifest"]
    if public_verifier.get("external_audit_completed") is True:
        _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "public verifier manifest claims external audit completion")

    _scan_claim_text(
        "commercial_proof_plane_customer_safe_language",
        _read_text(root, SOURCE_INPUTS["commercial_proof_plane_customer_safe_language"], label="commercial_proof_plane_customer_safe_language"),
    )
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
        "schema_id": "kt.adversarial_proof_corridor.authoring.v1",
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
        "commercial_proof_plane_validated": True,
        "adversarial_proof_corridor_packet_authored": True,
        "adversarial_proof_corridor_authoring_complete": True,
        "adversarial_proof_corridor_validation_next": True,
        "adversarial_proof_corridor_authorized": False,
        "adversarial_proof_corridor_validated": False,
        "adversarial_proof_corridor_active": False,
        "adversarial_attacks_executed": False,
        "external_audit_ratification_packet_next": False,
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


def _attack_rows() -> list[Dict[str, Any]]:
    return [
        {
            "attack_class": attack_class,
            "status": "PLANNED_NOT_EXECUTED",
            "must_fail_closed": True,
            "requires_validation_before_execution": True,
        }
        for attack_class in ATTACK_CLASSES
    ]


def _manifest_rows(input_bindings: list[Dict[str, str]]) -> list[Dict[str, str]]:
    return [
        {"role": row["role"], "path": row["path"], "sha256": row["sha256"], "required_for_validation": True}
        for row in input_bindings
    ]


def _common_deliverables() -> list[str]:
    return [
        OUTPUTS["attack_matrix"],
        OUTPUTS["mutation_fixture_manifest"],
        OUTPUTS["red_team_protocol"],
        OUTPUTS["claim_boundary_attack_plan"],
        OUTPUTS["supply_chain_attack_plan"],
        OUTPUTS["verifier_attack_plan"],
        OUTPUTS["runtime_escape_attack_plan"],
        OUTPUTS["context_corruption_attack_plan"],
        OUTPUTS["evidence_capture_attack_plan"],
        OUTPUTS["claim_boundary_receipt"],
    ]


def _outputs(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    input_bindings = list(base["input_bindings"])
    validation_checks = [
        "recompute_h04_commercial_proof_plane_validation_bindings",
        "verify_all_attack_classes_declared",
        "verify_attack_execution_not_performed_in_authoring_lane",
        "reject_commercial_activation_claim_authorization",
        "reject_external_audit_completion_claim",
        "reject_7b_beyond_sota_s_tier_claims",
        "preserve_truth_and_trust_law",
        "preserve_fp0_highway_nonpromotion",
    ]
    deliverables = _common_deliverables()
    attack_rows = _attack_rows()
    return {
        "corridor_contract": _artifact(
            base,
            role="corridor_contract",
            schema_id="kt.adversarial_proof_corridor.superlane_contract.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_SUPERLANE_CONTRACT",
            deliverables=deliverables,
            validation_checks=validation_checks,
            corridor_scope="hostile proof planning only; attack execution requires validation",
        ),
        "packet_contract": _artifact(
            base,
            role="packet_contract",
            schema_id="kt.adversarial_proof_corridor.packet_contract.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_PACKET_CONTRACT",
            deliverables=deliverables,
            validation_checks=validation_checks,
            attack_class_count=len(attack_rows),
        ),
        "packet_receipt": _artifact(
            base,
            role="packet_receipt",
            schema_id="kt.adversarial_proof_corridor.packet_receipt.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_PACKET_RECEIPT",
            verdict="ADVERSARIAL_PROOF_CORRIDOR_PACKET_BOUND_VALIDATION_NEXT",
            deliverable_count=len(deliverables),
        ),
        "source_manifest": _artifact(
            base,
            role="source_manifest",
            schema_id="kt.adversarial_proof_corridor.source_manifest.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_SOURCE_MANIFEST",
            sources=_manifest_rows(input_bindings),
        ),
        "attack_matrix": _artifact(
            base,
            role="attack_matrix",
            schema_id="kt.adversarial_proof_corridor.attack_matrix.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_ATTACK_MATRIX",
            attack_rows=attack_rows,
            attack_execution_performed=False,
        ),
        "mutation_fixture_manifest": _artifact(
            base,
            role="mutation_fixture_manifest",
            schema_id="kt.adversarial_proof_corridor.mutation_fixture_manifest.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_MUTATION_FIXTURE_MANIFEST",
            fixture_classes=list(ATTACK_CLASSES),
            fixture_execution_performed=False,
        ),
        "red_team_protocol": _artifact(
            base,
            role="red_team_protocol",
            schema_id="kt.adversarial_proof_corridor.red_team_protocol.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_RED_TEAM_PROTOCOL",
            protocol_state="AUTHORED_NOT_EXECUTED",
            evidence_required_before_external_audit=True,
        ),
        "claim_boundary_attack_plan": _attack_plan(base, "claim_boundary_attack_plan", "claim_boundary_mutation", ["claim_ceiling_mutation", "commercial_overclaim", "benchmark_overclaim"]),
        "supply_chain_attack_plan": _attack_plan(base, "supply_chain_attack_plan", "supply_chain_integrity", ["forged_sboms", "forged_rekor_bundles", "tuf_rollback_or_freeze"]),
        "verifier_attack_plan": _attack_plan(base, "verifier_attack_plan", "detached_verifier_integrity", ["forged_receipts", "mutable_overwritten_artifact_replay", "evaluator_capture"]),
        "runtime_escape_attack_plan": _attack_plan(base, "runtime_escape_attack_plan", "runtime_escape_integrity", ["tool_injection", "credential_leakage", "ci_privilege_escalation", "contained_subagent_escape"]),
        "context_corruption_attack_plan": _attack_plan(base, "context_corruption_attack_plan", "context_integrity", ["prompt_injection", "toon_context_corruption", "local_model_overclaiming"]),
        "evidence_capture_attack_plan": _attack_plan(base, "evidence_capture_attack_plan", "evidence_capture_integrity", ["benchmark_contamination", "adapter_schema_drift", "router_authority_drift", "self_written_skill_abuse"]),
        "claim_boundary_receipt": _artifact(
            base,
            role="claim_boundary_receipt",
            schema_id="kt.adversarial_proof_corridor.claim_boundary_receipt.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_CLAIM_BOUNDARY_RECEIPT",
            no_claim_expansion=True,
        ),
        "validation_plan": _artifact(
            base,
            role="validation_plan",
            schema_id="kt.adversarial_proof_corridor.validation_plan.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_PLAN",
            validation_checks=validation_checks,
            expected_validation_outcome=PREFERRED_VALIDATION_OUTCOME,
        ),
        "validation_reason_codes": _artifact(
            base,
            role="validation_reason_codes",
            schema_id="kt.adversarial_proof_corridor.validation_reason_codes.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.adversarial_proof_corridor.next_lawful_move.v1",
            artifact_id="KT_ADVERSARIAL_PROOF_CORRIDOR_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "packet_report": _packet_report(base),
    }


def _attack_plan(base: Dict[str, Any], role: str, plan_id: str, classes: list[str]) -> Dict[str, Any]:
    return _artifact(
        base,
        role=role,
        schema_id=f"kt.adversarial_proof_corridor.{role}.v1",
        artifact_id=f"KT_ADVERSARIAL_PROOF_CORRIDOR_{role.upper()}",
        plan_id=plan_id,
        attack_classes=classes,
        execution_status="PLANNED_NOT_EXECUTED",
        must_fail_closed=True,
    )


def _packet_report(base: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "# KT Adversarial Proof Corridor Packet",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "Adversarial proof corridor packet authored: true",
            "Adversarial proof corridor validated: false",
            "Adversarial proof corridor active: false",
            "Adversarial attacks executed: false",
            "External audit completed: false",
            "Commercial activation claims authorized: false",
            "7B amplification proven: false",
            "Beyond-SOTA claimed: false",
            "S-tier claimed: false",
            "FP0 or highway promoted to authority: false",
            f"Attack classes planned: {len(ATTACK_CLASSES)}",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def _validate_attack_matrix(outputs: Dict[str, Any]) -> None:
    matrix = outputs["attack_matrix"]
    rows = matrix.get("attack_rows", [])
    if not isinstance(rows, list) or len(rows) != len(ATTACK_CLASSES):
        _fail("RC_KT_ADVERSARIAL_PROOF_ATTACK_MATRIX_INCOMPLETE", "attack matrix row count mismatch")
    classes = {row.get("attack_class") for row in rows if isinstance(row, dict)}
    missing = set(ATTACK_CLASSES) - classes
    if missing:
        _fail("RC_KT_ADVERSARIAL_PROOF_ATTACK_MATRIX_INCOMPLETE", "attack matrix missing classes: " + ", ".join(sorted(missing)))
    for row in rows:
        if row.get("status") != "PLANNED_NOT_EXECUTED":
            _fail("RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY", "attack matrix executed attacks in authoring lane")


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_json_inputs(root)
    _validate_predecessor(payloads)
    _validate_sources(root, payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_ADVERSARIAL_PROOF_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
    outputs = _outputs(base, payloads)
    _validate_attack_matrix(outputs)
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
    return argparse.ArgumentParser(description="Author the KT adversarial proof corridor packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
