from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator import validate_kt_supply_chain_release_corridor_superlane_v1 as predecessor
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-claim-compiler-commercial-language-gate-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-claim-compiler-commercial-language-gate-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = predecessor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = predecessor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_PACKET_BOUND__"
    "CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_SUPERLANE_V1"
PREFERRED_VALIDATION_OUTCOME = (
    "KT_CLAIM_COMPILER_AND_COMMERCIAL_LANGUAGE_GATE_VALIDATED__"
    "COMMERCIAL_PROOF_PLANE_NEXT"
)

PREDECESSOR_INPUTS = {
    "h02_validation_contract": predecessor.OUTPUTS["validation_contract"],
    "h02_validation_receipt": predecessor.OUTPUTS["validation_receipt"],
    "h02_validation_scorecard": predecessor.OUTPUTS["validation_scorecard"],
    "h02_claim_compiler_gate_decision": predecessor.OUTPUTS["claim_compiler_gate_decision"],
    "h02_next_lawful_move": predecessor.OUTPUTS["next_lawful_move"],
}

CLAIM_INPUTS = {
    "claim_ceiling_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "commercial_claim_compiler_receipt": "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
    "product_claim_compiler": "KT_PROD_CLEANROOM/reports/kt_product_claim_compiler.json",
    "claim_compiler_policy": "KT_PROD_CLEANROOM/governance/closure_foundation/kt_claim_compiler_policy.json",
    "claim_proof_ceiling_policy": "KT_PROD_CLEANROOM/governance/kt_claim_proof_ceiling_compiler_policy_v2.json",
    "certification_pack": "KT_PROD_CLEANROOM/docs/commercial/KT_CERTIFICATION_PACK.md",
    "operator_factory_sku_catalog": "KT_PROD_CLEANROOM/docs/commercial/KT_OPERATOR_FACTORY_SKU_CATALOG.md",
    "bounded_trust_wedge": "KT_PROD_CLEANROOM/docs/commercial/E1_BOUNDED_TRUST_WEDGE.md",
    "demo_script": "KT_PROD_CLEANROOM/docs/commercial/E1_DEMO_SCRIPT.md",
}

INPUTS = {**PREDECESSOR_INPUTS, **CLAIM_INPUTS}

OUTPUTS = {
    "gate_contract": "governance/kt_claim_compiler_commercial_language_gate_superlane_v1.json",
    "packet_contract": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_packet_report.md",
    "source_manifest": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_source_manifest.json",
    "allowed_claims_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_allowed_claims_current_state.json",
    "forbidden_claims_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_forbidden_claims_current_state.json",
    "commercial_surface_scan_scope": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_commercial_surface_scan_scope.json",
    "claim_derivation_rules": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_claim_derivation_rules.json",
    "recursive_claim_scanner_contract": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_recursive_claim_scanner_contract.json",
    "markdown_language_gate_contract": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_markdown_language_gate_contract.json",
    "machine_routing_exemption_contract": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_machine_routing_exemption_contract.json",
    "no_claim_expansion_receipt": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_no_claim_expansion_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_claim_compiler_commercial_language_gate_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_claim_compiler_commercial_language_gate_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_claim_compiler_commercial_language_gate_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_CLAIM_GATE_PREDECESSOR_MISSING",
            "RC_KT_CLAIM_GATE_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_CLAIM_GATE_PREDECESSOR_NEXT_MOVE_DRIFT",
            "RC_KT_CLAIM_GATE_SOURCE_MISSING",
            "RC_KT_CLAIM_GATE_SOURCE_HASH_MISMATCH",
            "RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED",
            "RC_KT_CLAIM_GATE_REASON_CODE_DUPLICATE",
            "RC_KT_CLAIM_GATE_BOUNDARY_BREACH",
            "RC_KT_CLAIM_GATE_COMMERCIAL_SURFACE_UNBOUNDED",
            "RC_KT_CLAIM_GATE_PREMATURE_AUTHORITY",
            "RC_KT_CLAIM_GATE_BRANCH_DRIFT",
            "RC_KT_CLAIM_GATE_TRUST_ZONE_FAILED",
        )
    )
)

AUTHORITY_DRIFT_KEYS = evidence_packet.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "claim_compiler_commercial_language_gate_validated",
        "commercial_language_gate_active",
        "commercial_claims_authorized",
        "commercial_activation_claims_authorized",
        "commercial_proof_plane_authorized",
        "release_execution_authorized",
        "release_executed",
    }
)

# Kept as a forward-compatibility guard: if a future shared scanner widens
# AUTHORITY_DRIFT_KEYS to include positive evidence booleans, these known-safe
# authoring facts must remain legal while execution/claim authority still fails.
ALLOWED_AUTHORITY_TRUE_KEYS = frozenset(
    {
        "claim_compiler_commercial_language_gate_packet_authored",
        "claim_compiler_commercial_language_gate_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "supply_chain_release_corridor_packet_validated",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = evidence_packet.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bcommercial activation claims? (?:are|is) authorized\b", re.IGNORECASE),
    re.compile(r"\bcommercial activation (?:is )?authorized\b", re.IGNORECASE),
    re.compile(r"\bKT (?:is )?production[- ]commercial live\b", re.IGNORECASE),
    re.compile(r"\bexternal audit (?:is )?(?:complete|completed|done)\b", re.IGNORECASE),
    re.compile(r"\bfollow[- ]up audit readiness (?:is )?(?:validated|complete|completed)\b", re.IGNORECASE),
    re.compile(r"\b7B amplification (?:is )?(?:proven|validated|complete|completed)\b", re.IGNORECASE),
    re.compile(r"\bbeyond[- ]SOTA (?:is )?(?:proven|validated|allowed|claimed)\b", re.IGNORECASE),
    re.compile(r"\bS[- ]tier (?:is )?(?:proven|validated|allowed|claimed)\b", re.IGNORECASE),
    re.compile(r"\bFP0 (?:is )?(?:active|authoritative|canonical|promoted)\b", re.IGNORECASE),
    re.compile(r"\bhighway shadow (?:is )?(?:active|authoritative|canonical|promoted)\b", re.IGNORECASE),
    re.compile(r"\bclaim compiler (?:is )?(?:authorized|validated|active)\b", re.IGNORECASE),
)

MACHINE_ROUTING_FIELDS = frozenset(
    {
        "outcome",
        "selected_outcome",
        "next_lawful_move",
        "current_execution_outcome",
        "current_execution_lane",
        "predecessor_outcome",
        "predecessor_next_lawful_move",
        "preferred_validation_outcome",
        "allowed_outcomes",
        "routing_map",
        "decision",
        "artifact_id",
        "schema_id",
        "lane",
        "authoritative_lane",
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
            _fail("RC_KT_CLAIM_GATE_BRANCH_DRIFT", "main/replay authoring requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_CLAIM_GATE_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_CLAIM_GATE_BRANCH_DRIFT", "dirty worktree outside claim gate scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_CLAIM_GATE_SOURCE_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_CLAIM_GATE_SOURCE_MISSING", f"{label} must be JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_CLAIM_GATE_SOURCE_MISSING", f"missing {label}: {raw}")
    return path.read_text(encoding="utf-8")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_CLAIM_GATE_SOURCE_MISSING", f"missing input {role}: {raw}")
        rows.append({"role": role, "path": raw, "sha256": file_sha256(path)})
    return rows


def _load_json_inputs(root: Path) -> Dict[str, Dict[str, Any]]:
    json_roles = {
        role: raw
        for role, raw in INPUTS.items()
        if raw.endswith(".json")
    }
    return {role: _load_json(root, raw, label=role) for role, raw in json_roles.items()}


def _validate_predecessor(payloads: Dict[str, Dict[str, Any]]) -> None:
    for role in PREDECESSOR_INPUTS:
        payload = payloads[role]
        if payload.get("selected_outcome") != EXPECTED_PREVIOUS_OUTCOME:
            _fail("RC_KT_CLAIM_GATE_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_CLAIM_GATE_PREDECESSOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("claim_compiler_commercial_language_gate_next") is not True:
            _fail("RC_KT_CLAIM_GATE_PREDECESSOR_MISSING", f"{role} did not select claim compiler gate next")
        if payload.get("claim_compiler_authorized") is not False:
            _fail("RC_KT_CLAIM_GATE_PREMATURE_AUTHORITY", f"{role} prematurely authorizes claim compiler")


def _validate_claim_inputs(payloads: Dict[str, Dict[str, Any]]) -> None:
    claim_ceiling = payloads["claim_ceiling_current_state"]
    if not isinstance(claim_ceiling.get("allowed_claims"), list) or not isinstance(claim_ceiling.get("forbidden_claims"), list):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim ceiling must expose allowed_claims and forbidden_claims")
    if claim_ceiling.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_CLAIM_GATE_PREMATURE_AUTHORITY", "claim ceiling authorizes commercial activation claims")
    if "Commercial activation claims are authorized." not in claim_ceiling.get("forbidden_claims", []):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim ceiling must explicitly forbid commercial activation claim authorization")

    commercial_receipt = payloads["commercial_claim_compiler_receipt"]
    if commercial_receipt.get("status") != "PASS":
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "commercial claim compiler receipt must be PASS")
    if not commercial_receipt.get("claim_compiler_claim_boundary"):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "commercial claim compiler receipt must state claim boundary")

    product_compiler = payloads["product_claim_compiler"]
    if not isinstance(product_compiler.get("compiled_claims"), list):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "product claim compiler must expose compiled_claims")
    if not isinstance(product_compiler.get("blocked_current_claim_ids"), list):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "product claim compiler must expose blocked_current_claim_ids")

    policy = payloads["claim_compiler_policy"]
    if "Every public or commercial claim must be backed by cited machine-state receipts." not in policy.get("invariants", []):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim compiler policy invariant missing")
    if "claim_above_active_proof_class" not in policy.get("forbidden_states", []):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim compiler policy must forbid claim_above_active_proof_class")

    proof_policy = payloads["claim_proof_ceiling_policy"]
    if proof_policy.get("status") != "ACTIVE":
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim proof ceiling policy must be ACTIVE")
    if not isinstance(proof_policy.get("forbidden_public_claims"), list):
        _fail("RC_KT_CLAIM_GATE_SOURCE_STATUS_FAILED", "claim proof ceiling policy must expose forbidden_public_claims")


def _validate_commercial_docs(root: Path) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    required_markers = {
        "certification_pack": [
            "Documentary-only commercial surface.",
            "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            "kt_truth_ledger:ledger/current/current_pointer.json",
        ],
        "operator_factory_sku_catalog": [
            "Documentary-only commercial surface.",
            "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
            "kt_truth_ledger:ledger/current/current_pointer.json",
        ],
    }
    for role in ("certification_pack", "operator_factory_sku_catalog", "bounded_trust_wedge", "demo_script"):
        raw = CLAIM_INPUTS[role]
        text = _read_text(root, raw, label=role)
        missing = [marker for marker in required_markers.get(role, []) if marker not in text]
        if missing:
            _fail("RC_KT_CLAIM_GATE_COMMERCIAL_SURFACE_UNBOUNDED", f"{role} missing markers: {', '.join(missing)}")
        _scan_claim_text(f"{role}.markdown_text", text)
        rows.append({"role": role, "path": raw, "status": "PASS", "required_markers_missing": missing})
    return rows


def _leaf_key(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1].replace("[]", "")
    return re.sub(r"\[\d+\]$", "", leaf)


def _is_machine_routing_field(key: str) -> bool:
    return _leaf_key(key) in MACHINE_ROUTING_FIELDS or evidence_packet._is_machine_routing_field(key)  # noqa: SLF001


def _is_negative_field(key: str) -> bool:
    return evidence_packet._is_negative_field(key)  # noqa: SLF001


def _is_negative_text(text: str) -> bool:
    return evidence_packet._is_negative_text(text)  # noqa: SLF001


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_CLAIM_GATE_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", value, flags=re.IGNORECASE)
            for clause in clauses:
                if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not _is_negative_text(clause):
                    _fail("RC_KT_CLAIM_GATE_BOUNDARY_BREACH", f"{label}.{key}={value!r}")


def _scan_claim_text(label: str, text: str) -> None:
    clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", text, flags=re.IGNORECASE)
    for clause in clauses:
        if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not _is_negative_text(clause):
            _fail("RC_KT_CLAIM_GATE_BOUNDARY_BREACH", f"{label}={clause.strip()!r}")


def _validate_claim_boundary(payloads: Dict[str, Dict[str, Any]]) -> None:
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
        "schema_id": "kt.claim_compiler_commercial_language_gate.authoring.v1",
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
        "supply_chain_release_corridor_packet_validated": True,
        "claim_compiler_commercial_language_gate_packet_authored": True,
        "claim_compiler_commercial_language_gate_validated": False,
        "commercial_language_gate_active": False,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_claimed": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
        "release_execution_authorized": False,
        "release_executed": False,
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


def _allowed_claims(payloads: Dict[str, Dict[str, Any]]) -> list[str]:
    claim_ceiling = payloads["claim_ceiling_current_state"].get("allowed_claims", [])
    commercial_receipt = payloads["commercial_claim_compiler_receipt"].get("allowed_current_claims", [])
    product_compiler = payloads["product_claim_compiler"].get("compiled_claims", [])
    product_allowed = [
        str(row.get("statement", "")).strip()
        for row in product_compiler
        if isinstance(row, dict) and str(row.get("claim_status", "")).strip() in {"ALLOWED_CURRENT", "DOCUMENTARY_ONLY"}
    ]
    return [str(item) for item in [*claim_ceiling, *commercial_receipt, *product_allowed] if str(item).strip()]


def _forbidden_claims(payloads: Dict[str, Dict[str, Any]]) -> list[str]:
    claim_ceiling = payloads["claim_ceiling_current_state"].get("forbidden_claims", [])
    commercial_receipt = payloads["commercial_claim_compiler_receipt"].get("forbidden_current_claims", [])
    proof_policy = payloads["claim_proof_ceiling_policy"].get("forbidden_public_claims", [])
    fixed = [
        "External audit is complete.",
        "Commercial activation claims are authorized.",
        "KT is production-commercial live.",
        "7B amplification is proven.",
        "Beyond-SOTA capability is proven.",
        "S-tier claim is allowed.",
        "FP0 or highway shadow is canonical authority.",
    ]
    return [str(item) for item in [*claim_ceiling, *commercial_receipt, *proof_policy, *fixed] if str(item).strip()]


def _outputs(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]], doc_rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    allowed_claims = _allowed_claims(payloads)
    forbidden_claims = _forbidden_claims(payloads)
    input_bindings = list(base["input_bindings"])
    manifest_rows = [
        {"role": row["role"], "path": row["path"], "sha256": row["sha256"], "required_for_validation": True}
        for row in input_bindings
    ]
    scan_scope = [
        CLAIM_INPUTS["certification_pack"],
        CLAIM_INPUTS["operator_factory_sku_catalog"],
        CLAIM_INPUTS["bounded_trust_wedge"],
        CLAIM_INPUTS["demo_script"],
        "README.md",
        "KT_PROD_CLEANROOM/reports/*.json",
        "KT_PROD_CLEANROOM/docs/commercial/*.md",
    ]
    validation_checks = [
        "recompute_all_bound_source_hashes",
        "verify_h02_validation_handoff",
        "compile_allowed_and_forbidden_claims_from_current_truth",
        "scan_claim_bearing_json_strings_arrays_and_markdown",
        "exempt_machine_routing_identifiers_from_prose_claim_scan",
        "allow_explicit_forbidden_or_blocked_negative_contexts",
        "fail_closed_on_commercial_activation_claim_authorization",
        "fail_closed_on_external_audit_completion_claim",
        "fail_closed_on_7b_or_beyond_sota_or_s_tier_claim",
        "enforce_unique_reason_codes",
        "preserve_truth_and_trust_law",
    ]
    common_extra = {
        "allowed_claim_count": len(allowed_claims),
        "forbidden_claim_count": len(forbidden_claims),
        "commercial_surface_count": len(doc_rows),
        "claim_derivation_source": "current bound receipts and policies only",
    }
    return {
        "gate_contract": _artifact(
            base,
            role="gate_contract",
            schema_id="kt.claim_compiler.commercial_language_gate.superlane_contract.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_SUPERLANE_CONTRACT",
            gate_scope="author claim compiler and commercial language gate law; do not activate commercial claims",
            public_and_commercial_claims_must_derive_from_current_truth=True,
            validation_checks=validation_checks,
            **common_extra,
        ),
        "packet_contract": _artifact(
            base,
            role="packet_contract",
            schema_id="kt.claim_compiler.commercial_language_gate.packet_contract.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_PACKET_CONTRACT",
            validation_checks=validation_checks,
            **common_extra,
        ),
        "packet_receipt": _artifact(
            base,
            role="packet_receipt",
            schema_id="kt.claim_compiler.commercial_language_gate.packet_receipt.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_PACKET_RECEIPT",
            verdict="CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_PACKET_BOUND_VALIDATION_NEXT",
            **common_extra,
        ),
        "source_manifest": _artifact(
            base,
            role="source_manifest",
            schema_id="kt.claim_compiler.commercial_language_gate.source_manifest.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_SOURCE_MANIFEST",
            sources=manifest_rows,
        ),
        "allowed_claims_current_state": _artifact(
            base,
            role="allowed_claims_current_state",
            schema_id="kt.claim_compiler.commercial_language_gate.allowed_claims_current_state.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_ALLOWED_CLAIMS_CURRENT_STATE",
            allowed_claims=allowed_claims,
            allowed_claims_authorize_commercial_activation_claims=False,
        ),
        "forbidden_claims_current_state": _artifact(
            base,
            role="forbidden_claims_current_state",
            schema_id="kt.claim_compiler.commercial_language_gate.forbidden_claims_current_state.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_FORBIDDEN_CLAIMS_CURRENT_STATE",
            forbidden_claims=forbidden_claims,
        ),
        "commercial_surface_scan_scope": _artifact(
            base,
            role="commercial_surface_scan_scope",
            schema_id="kt.claim_compiler.commercial_language_gate.commercial_surface_scan_scope.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_COMMERCIAL_SURFACE_SCAN_SCOPE",
            scan_scope=scan_scope,
            commercial_doc_checks=doc_rows,
        ),
        "claim_derivation_rules": _artifact(
            base,
            role="claim_derivation_rules",
            schema_id="kt.claim_compiler.commercial_language_gate.claim_derivation_rules.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_CLAIM_DERIVATION_RULES",
            rules=[
                "public and commercial claims derive from bound current receipts only",
                "ambiguity downgrades to the lowest admissible claim tier",
                "documentary mirrors cannot be described as live truth sources",
                "commercial activation execution evidence does not authorize commercial activation claims",
                "supply-chain release validation does not imply external audit completion",
            ],
        ),
        "recursive_claim_scanner_contract": _artifact(
            base,
            role="recursive_claim_scanner_contract",
            schema_id="kt.claim_compiler.commercial_language_gate.recursive_claim_scanner_contract.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_RECURSIVE_CLAIM_SCANNER_CONTRACT",
            scanned_shapes=["json_objects", "json_arrays", "json_strings", "markdown_text"],
            forbidden_patterns=[pattern.pattern for pattern in FORBIDDEN_CLAIM_PATTERNS],
            negative_contexts_allowed=True,
        ),
        "markdown_language_gate_contract": _artifact(
            base,
            role="markdown_language_gate_contract",
            schema_id="kt.claim_compiler.commercial_language_gate.markdown_language_gate_contract.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_MARKDOWN_LANGUAGE_GATE_CONTRACT",
            required_markers=[
                "Documentary-only commercial surface.",
                "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
                "kt_truth_ledger:ledger/current/current_pointer.json",
            ],
            markdown_claims_must_be_documentary_or_receipt_backed=True,
        ),
        "machine_routing_exemption_contract": _artifact(
            base,
            role="machine_routing_exemption_contract",
            schema_id="kt.claim_compiler.commercial_language_gate.machine_routing_exemption_contract.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_MACHINE_ROUTING_EXEMPTION_CONTRACT",
            exempt_fields=sorted(MACHINE_ROUTING_FIELDS),
            exemption_scope="machine routing identifiers only; prose fields remain scanned",
        ),
        "no_claim_expansion_receipt": _artifact(
            base,
            role="no_claim_expansion_receipt",
            schema_id="kt.claim_compiler.commercial_language_gate.no_claim_expansion_receipt.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_NO_CLAIM_EXPANSION_RECEIPT",
            no_claim_expansion=True,
            commercial_activation_claim_authorized=False,
            external_audit_completed=False,
            seven_b_amplification_claimed_proven=False,
        ),
        "validation_plan": _artifact(
            base,
            role="validation_plan",
            schema_id="kt.claim_compiler.commercial_language_gate.validation_plan.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_VALIDATION_PLAN",
            validation_checks=validation_checks,
            expected_validation_outcome=PREFERRED_VALIDATION_OUTCOME,
        ),
        "validation_reason_codes": _artifact(
            base,
            role="validation_reason_codes",
            schema_id="kt.claim_compiler.commercial_language_gate.validation_reason_codes.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.claim_compiler.commercial_language_gate.next_lawful_move.v1",
            artifact_id="KT_CLAIM_COMPILER_COMMERCIAL_LANGUAGE_GATE_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "packet_report": _report(base, allowed_claims, forbidden_claims),
    }


def _report(base: Dict[str, Any], allowed_claims: list[str], forbidden_claims: list[str]) -> str:
    return "\n".join(
        [
            "# KT Claim Compiler And Commercial Language Gate Packet",
            "",
            f"Current main: {base['current_main_head']}",
            f"Lane: {AUTHORITATIVE_LANE}",
            f"Outcome: {SELECTED_OUTCOME}",
            "Claim compiler commercial language gate validated: false",
            "Commercial activation claims authorized: false",
            "External audit completed: false",
            "7B amplification proven: false",
            "FP0 or highway promoted to authority: false",
            f"Allowed claim rows bound: {len(allowed_claims)}",
            f"Forbidden claim rows bound: {len(forbidden_claims)}",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "",
        ]
    )


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    json_payloads = _load_json_inputs(root)
    _validate_predecessor(json_payloads)
    _validate_claim_inputs(json_payloads)
    doc_rows = _validate_commercial_docs(root)
    _validate_claim_boundary(json_payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_CLAIM_GATE_TRUST_ZONE_FAILED", "trust-zone validation failed")

    head = common.git_rev_parse(root, "HEAD")
    current_main_head = common.git_rev_parse(root, "origin/main" if branch != "main" else "HEAD")
    input_bindings = _input_bindings(root)
    base = _base(
        branch=branch,
        head=head,
        current_main_head=current_main_head,
        generated_utc=utc_now_iso_z(),
        input_bindings=input_bindings,
        trust_zone_validation=trust_zone_validation,
    )
    outputs = _outputs(base, json_payloads, doc_rows)
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
    return argparse.ArgumentParser(description="Author the KT claim compiler and commercial language gate packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
