from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, NoReturn

from tools.operator import cohort0_gate_f_common as common
from tools.operator import kt_claim_compiler_commercial_language_gate_superlane_v1 as claim_gate
from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as evidence_packet
from tools.operator import validate_kt_claim_compiler_commercial_language_gate_superlane_v1 as predecessor
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


AUTHOR_BRANCH = "author/kt-commercial-proof-plane-superlane-v1"
REPLAY_BRANCH_PREFIX = "replay/kt-commercial-proof-plane-on-main"
ALLOWED_BRANCHES = frozenset({AUTHOR_BRANCH, "main"})

AUTHORITATIVE_LANE = "AUTHOR_KT_COMMERCIAL_PROOF_PLANE_SUPERLANE_V1"
EXPECTED_PREVIOUS_OUTCOME = predecessor.SELECTED_OUTCOME
EXPECTED_PREVIOUS_NEXT_MOVE = predecessor.NEXT_LAWFUL_MOVE
SELECTED_OUTCOME = (
    "KT_COMMERCIAL_PROOF_PLANE_PACKET_BOUND__"
    "COMMERCIAL_PROOF_PLANE_VALIDATION_NEXT"
)
NEXT_LAWFUL_MOVE = "VALIDATE_KT_COMMERCIAL_PROOF_PLANE_SUPERLANE_V1"
PREFERRED_VALIDATION_OUTCOME = "KT_COMMERCIAL_PROOF_PLANE_VALIDATED__ADVERSARIAL_PROOF_CORRIDOR_NEXT"

PREDECESSOR_INPUTS = {
    "h03_validation_contract": predecessor.OUTPUTS["validation_contract"],
    "h03_validation_receipt": predecessor.OUTPUTS["validation_receipt"],
    "h03_validation_scorecard": predecessor.OUTPUTS["validation_scorecard"],
    "h03_commercial_proof_plane_gate_decision": predecessor.OUTPUTS["commercial_proof_plane_gate_decision"],
    "h03_next_lawful_move": predecessor.OUTPUTS["next_lawful_move"],
}

SOURCE_INPUTS = {
    "h03_allowed_claims": claim_gate.OUTPUTS["allowed_claims_current_state"],
    "h03_forbidden_claims": claim_gate.OUTPUTS["forbidden_claims_current_state"],
    "claim_ceiling_current_state": "KT_PROD_CLEANROOM/reports/kt_claim_ceiling_current_state.json",
    "commercial_claim_compiler_receipt": "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
    "product_operator_runbook": "KT_PROD_CLEANROOM/product/operator_runbook_v2.md",
    "product_deployment_profiles": "KT_PROD_CLEANROOM/product/deployment_profiles.json",
    "data_governance_pack_prep_only": "KT_PROD_CLEANROOM/reports/kt_data_governance_pack_prep_only.md",
    "public_verifier_manifest": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
}

INPUTS = {**PREDECESSOR_INPUTS, **SOURCE_INPUTS}

OUTPUTS = {
    "plane_contract": "governance/kt_commercial_proof_plane_superlane_v1.json",
    "packet_contract": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_packet_contract.json",
    "packet_receipt": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_packet_receipt.json",
    "packet_report": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_packet_report.md",
    "source_manifest": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_source_manifest.json",
    "quickstart": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_quickstart.md",
    "operator_runbook": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_operator_runbook.md",
    "deployment_profiles": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_deployment_profiles.json",
    "support_sla": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_support_sla.json",
    "data_governance_pack": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_data_governance_pack.md",
    "security_review_packet": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_security_review_packet.json",
    "evidence_pack_manifest": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_evidence_pack_manifest.json",
    "pilot_contract_rider": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_pilot_contract_rider.md",
    "pricing_license_options": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_pricing_license_options.json",
    "customer_safe_language": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_customer_safe_language.md",
    "claim_boundary_receipt": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_claim_boundary_receipt.json",
    "validation_plan": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_plan.json",
    "validation_reason_codes": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_validation_reason_codes.json",
    "next_lawful_move": "KT_PROD_CLEANROOM/reports/kt_commercial_proof_plane_next_lawful_move_receipt.json",
}

WORKSTREAM_FILES_TOUCHED = frozenset(
    {
        *OUTPUTS.values(),
        "KT_PROD_CLEANROOM/tools/operator/kt_commercial_proof_plane_superlane_v1.py",
        "KT_PROD_CLEANROOM/tests/operator/test_kt_commercial_proof_plane_superlane_v1.py",
    }
)

REASON_CODES = tuple(
    dict.fromkeys(
        (
            "RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_MISSING",
            "RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_OUTCOME_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_NEXT_MOVE_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_MISSING",
            "RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_STATUS_FAILED",
            "RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH",
            "RC_KT_COMMERCIAL_PROOF_PLANE_REASON_CODE_DUPLICATE",
            "RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY",
            "RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT",
            "RC_KT_COMMERCIAL_PROOF_PLANE_TRUST_ZONE_FAILED",
        )
    )
)

AUTHORITY_DRIFT_KEYS = predecessor.AUTHORITY_DRIFT_KEYS | frozenset(
    {
        "commercial_proof_plane_validated",
        "commercial_proof_plane_active",
        "commercial_activation_claim_authorized",
        "commercial_activation_claims_authorized",
        "allowed_claims_authorize_commercial_activation_claims",
        "benchmark_prep_authorizes_commercial_activation",
        "external_audit_completed",
        "external_audit_claimed_complete",
        "adversarial_proof_corridor_validated",
        "adversarial_proof_corridor_active",
    }
)

ALLOWED_AUTHORITY_TRUE_KEYS = predecessor.ALLOWED_AUTHORITY_TRUE_KEYS | frozenset(
    {
        "commercial_proof_plane_packet_authored",
        "commercial_proof_plane_authoring_complete",
        "commercial_proof_plane_validation_next",
        "claim_boundary_passed",
        "source_hashes_recomputed",
        "claim_compiler_commercial_language_gate_validated",
        "truth_engine_law_unchanged",
        "trust_zone_law_unchanged",
    }
)

FORBIDDEN_CLAIM_PATTERNS = claim_gate.FORBIDDEN_CLAIM_PATTERNS + (
    re.compile(r"\bcommercial proof plane (?:is )?(?:validated|active|authoritative)\b", re.IGNORECASE),
    re.compile(r"\badversarial proof corridor (?:is )?(?:validated|active|complete)\b", re.IGNORECASE),
)

MACHINE_ROUTING_FIELDS = claim_gate.MACHINE_ROUTING_FIELDS | frozenset(
    {
        "preferred_validation_outcome",
        "adversarial_proof_corridor_next",
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
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT", "main/replay authoring requires HEAD to equal origin/main before artifact generation")
        return branch
    _fail("RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT", f"branch {branch!r} is not allowed")


def _ensure_workspace_scope(root: Path) -> None:
    dirty = _status_relpaths(common.git_status_porcelain(root))
    out_of_scope = [path for path in dirty if path not in WORKSTREAM_FILES_TOUCHED]
    if out_of_scope:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT", "dirty worktree outside commercial proof plane scope: " + ", ".join(out_of_scope))


def _load_json(root: Path, raw: str, *, label: str) -> Dict[str, Any]:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_MISSING", f"missing {label}: {raw}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_MISSING", f"{label} must be JSON object")
    return payload


def _read_text(root: Path, raw: str, *, label: str) -> str:
    path = common.resolve_path(root, raw)
    if not path.is_file():
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_MISSING", f"missing {label}: {raw}")
    return path.read_text(encoding="utf-8")


def _input_bindings(root: Path) -> list[Dict[str, str]]:
    rows: list[Dict[str, str]] = []
    for role, raw in INPUTS.items():
        path = common.resolve_path(root, raw)
        if not path.is_file():
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_MISSING", f"missing input {role}: {raw}")
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
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_OUTCOME_DRIFT", f"{role} selected_outcome drifted")
        if payload.get("next_lawful_move") != EXPECTED_PREVIOUS_NEXT_MOVE:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_NEXT_MOVE_DRIFT", f"{role} next_lawful_move drifted")
        if payload.get("claim_compiler_commercial_language_gate_validated") is not True:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_MISSING", f"{role} did not validate the claim/language gate")
        if payload.get("commercial_proof_plane_next") is not True:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_MISSING", f"{role} did not select commercial proof plane next")
        if payload.get("commercial_proof_plane_authorized") is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY", f"{role} prematurely authorizes commercial proof plane")


def _leaf_key(key: str) -> str:
    leaf = key.rsplit(".", 1)[-1].replace("[]", "")
    return re.sub(r"\[\d+\]$", "", leaf)


def _is_machine_routing_field(key: str) -> bool:
    return _leaf_key(key) in MACHINE_ROUTING_FIELDS or evidence_packet._is_machine_routing_field(key)  # noqa: SLF001


def _is_negative_field(key: str) -> bool:
    return evidence_packet._is_negative_field(key)  # noqa: SLF001


def _is_negative_text(text: str) -> bool:
    return evidence_packet._is_negative_text(text)  # noqa: SLF001


def _explicit_false_clause(text: str) -> bool:
    return bool(re.search(r":\s*false\s*$", text.strip(), flags=re.IGNORECASE))


def _scan_claim_text(label: str, text: str) -> None:
    clauses = re.split(r"\b(?:and|but|however|although|though|while|whereas)\b|[.;\n]", text, flags=re.IGNORECASE)
    for clause in clauses:
        if any(pattern.search(clause) for pattern in FORBIDDEN_CLAIM_PATTERNS) and not (_is_negative_text(clause) or _explicit_false_clause(clause)):
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH", f"{label} contains forbidden affirmative claim: {clause.strip()!r}")


def _scan_claim_boundary(label: str, payload: Any) -> None:
    for key, value in evidence_packet._walk(payload):  # noqa: SLF001
        leaf_key = _leaf_key(key)
        if leaf_key in AUTHORITY_DRIFT_KEYS and leaf_key not in ALLOWED_AUTHORITY_TRUE_KEYS and value is not False:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH", f"{label}.{key} drifted non-false")
        if isinstance(value, str) and not _is_negative_field(key) and not _is_machine_routing_field(key):
            _scan_claim_text(f"{label}.{key}", value)


def _validate_sources(root: Path, payloads: Dict[str, Dict[str, Any]]) -> None:
    allowed = payloads["h03_allowed_claims"].get("allowed_claims", [])
    forbidden = payloads["h03_forbidden_claims"].get("forbidden_claims", [])
    if not isinstance(allowed, list) or not isinstance(forbidden, list):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_STATUS_FAILED", "H03 claim states must expose allowed and forbidden claims")
    if "Commercial activation claims are authorized." in allowed:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH", "allowed claims include commercial activation authorization")
    required_forbidden_claims = (
        "External audit is complete.",
        "Commercial activation claims are authorized.",
        "KT is production-commercial live.",
        "7B amplification is proven.",
        "Beyond-SOTA capability is proven.",
        "S-tier claim is allowed.",
        "FP0 or highway shadow is canonical authority.",
    )
    for required in required_forbidden_claims:
        if required not in forbidden:
            _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_STATUS_FAILED", f"forbidden claims missing {required!r}")
    if payloads["h03_allowed_claims"].get("allowed_claims_authorize_commercial_activation_claims") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY", "H03 allowed claims authorize commercial activation claims")

    claim_ceiling = payloads["claim_ceiling_current_state"]
    if claim_ceiling.get("commercial_activation_claim_authorized") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY", "claim ceiling authorizes commercial activation claims")
    if claim_ceiling.get("benchmark_prep_authorizes_commercial_activation") is not False:
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY", "benchmark prep authorizes commercial activation")

    commercial_receipt = payloads["commercial_claim_compiler_receipt"]
    if commercial_receipt.get("status") != "PASS":
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_STATUS_FAILED", "commercial claim compiler receipt must be PASS")

    profiles = payloads["product_deployment_profiles"]
    if not isinstance(profiles.get("profiles"), list) or not profiles.get("profiles"):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_SOURCE_STATUS_FAILED", "deployment profiles source must expose profiles")

    _scan_claim_text("product_operator_runbook", _read_text(root, SOURCE_INPUTS["product_operator_runbook"], label="product_operator_runbook"))
    _scan_claim_text("data_governance_pack_prep_only", _read_text(root, SOURCE_INPUTS["data_governance_pack_prep_only"], label="data_governance_pack_prep_only"))
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
        "schema_id": "kt.commercial_proof_plane.authoring.v1",
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
        "claim_compiler_commercial_language_gate_validated": True,
        "commercial_proof_plane_packet_authored": True,
        "commercial_proof_plane_authoring_complete": True,
        "commercial_proof_plane_validation_next": True,
        "commercial_proof_plane_validated": False,
        "commercial_proof_plane_active": False,
        "adversarial_proof_corridor_next": False,
        "adversarial_proof_corridor_validated": False,
        "commercial_claims_authorized": False,
        "commercial_activation_claim_authorized": False,
        "commercial_activation_claimed": False,
        "external_audit_completed": False,
        "external_audit_claimed_complete": False,
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


def _common_deliverables() -> list[str]:
    return [
        OUTPUTS["quickstart"],
        OUTPUTS["operator_runbook"],
        OUTPUTS["deployment_profiles"],
        OUTPUTS["support_sla"],
        OUTPUTS["data_governance_pack"],
        OUTPUTS["security_review_packet"],
        OUTPUTS["evidence_pack_manifest"],
        OUTPUTS["pilot_contract_rider"],
        OUTPUTS["pricing_license_options"],
        OUTPUTS["customer_safe_language"],
    ]


def _outputs(base: Dict[str, Any], payloads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    input_bindings = list(base["input_bindings"])
    validation_checks = [
        "recompute_h03_claim_gate_validation_bindings",
        "verify_commercial_proof_deliverables_exist",
        "verify_quickstart_operator_runbook_deployment_profile_support_sla",
        "verify_data_governance_security_review_evidence_pack",
        "verify_pilot_rider_pricing_language_are_claim_bounded",
        "reject_commercial_activation_claim_authorization",
        "reject_external_audit_completion_claim",
        "reject_7b_beyond_sota_s_tier_claims",
        "preserve_truth_and_trust_law",
    ]
    deliverables = _common_deliverables()
    return {
        "plane_contract": _artifact(
            base,
            role="plane_contract",
            schema_id="kt.commercial_proof_plane.superlane_contract.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_SUPERLANE_CONTRACT",
            deliverables=deliverables,
            validation_checks=validation_checks,
            plane_scope="commercial proof artifacts only; no commercial activation claim authority",
        ),
        "packet_contract": _artifact(
            base,
            role="packet_contract",
            schema_id="kt.commercial_proof_plane.packet_contract.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_PACKET_CONTRACT",
            deliverables=deliverables,
            validation_checks=validation_checks,
        ),
        "packet_receipt": _artifact(
            base,
            role="packet_receipt",
            schema_id="kt.commercial_proof_plane.packet_receipt.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_PACKET_RECEIPT",
            verdict="COMMERCIAL_PROOF_PLANE_PACKET_BOUND_VALIDATION_NEXT",
            deliverable_count=len(deliverables),
        ),
        "source_manifest": _artifact(
            base,
            role="source_manifest",
            schema_id="kt.commercial_proof_plane.source_manifest.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_SOURCE_MANIFEST",
            sources=_manifest_rows(input_bindings),
        ),
        "deployment_profiles": _artifact(
            base,
            role="deployment_profiles",
            schema_id="kt.commercial_proof_plane.deployment_profiles.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_DEPLOYMENT_PROFILES",
            profiles=[
                {"profile_id": "local_cleanroom_demo", "status": "DOCUMENTARY_READY", "commercial_activation_claims_authorized": False},
                {"profile_id": "managed_operator_pilot", "status": "DOCUMENTARY_READY", "commercial_activation_claims_authorized": False},
                {"profile_id": "external_verifier_review", "status": "DOCUMENTARY_READY", "commercial_activation_claims_authorized": False},
            ],
        ),
        "support_sla": _artifact(
            base,
            role="support_sla",
            schema_id="kt.commercial_proof_plane.support_sla.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_SUPPORT_SLA",
            support_scope="pilot and review support only",
            uptime_commitment_claim_authorized=False,
            compliance_claim_authorized=False,
        ),
        "security_review_packet": _artifact(
            base,
            role="security_review_packet",
            schema_id="kt.commercial_proof_plane.security_review_packet.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_SECURITY_REVIEW_PACKET",
            review_items=[
                "secrets excluded from evidence packs",
                "detached verifier inputs are read-only",
                "claim compiler gates public language",
                "rollback/freeze path remains separate from claim authority",
            ],
            external_audit_completed=False,
        ),
        "evidence_pack_manifest": _artifact(
            base,
            role="evidence_pack_manifest",
            schema_id="kt.commercial_proof_plane.evidence_pack_manifest.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_EVIDENCE_PACK_MANIFEST",
            evidence_pack_items=[
                predecessor.OUTPUTS["validation_receipt"],
                predecessor.OUTPUTS["commercial_proof_plane_gate_decision"],
                claim_gate.OUTPUTS["allowed_claims_current_state"],
                claim_gate.OUTPUTS["forbidden_claims_current_state"],
                SOURCE_INPUTS["public_verifier_manifest"],
            ],
            evidence_pack_authorizes_commercial_activation_claims=False,
        ),
        "pricing_license_options": _artifact(
            base,
            role="pricing_license_options",
            schema_id="kt.commercial_proof_plane.pricing_license_options.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_PRICING_LICENSE_OPTIONS",
            options=[
                {"option_id": "evaluation_only", "claim_scope": "documentary and verifier review only"},
                {"option_id": "pilot_support", "claim_scope": "bounded pilot support only"},
            ],
            production_commercial_live_claim_authorized=False,
        ),
        "claim_boundary_receipt": _artifact(
            base,
            role="claim_boundary_receipt",
            schema_id="kt.commercial_proof_plane.claim_boundary_receipt.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_RECEIPT",
            allowed_claims_reference=claim_gate.OUTPUTS["allowed_claims_current_state"],
            forbidden_claims_reference=claim_gate.OUTPUTS["forbidden_claims_current_state"],
            no_claim_expansion=True,
        ),
        "validation_plan": _artifact(
            base,
            role="validation_plan",
            schema_id="kt.commercial_proof_plane.validation_plan.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_PLAN",
            validation_checks=validation_checks,
            expected_validation_outcome=PREFERRED_VALIDATION_OUTCOME,
        ),
        "validation_reason_codes": _artifact(
            base,
            role="validation_reason_codes",
            schema_id="kt.commercial_proof_plane.validation_reason_codes.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_VALIDATION_REASON_CODES",
            reason_codes=list(REASON_CODES),
        ),
        "next_lawful_move": _artifact(
            base,
            role="next_lawful_move",
            schema_id="kt.commercial_proof_plane.next_lawful_move.v1",
            artifact_id="KT_COMMERCIAL_PROOF_PLANE_NEXT_LAWFUL_MOVE_RECEIPT",
            current_execution_lane=AUTHORITATIVE_LANE,
            current_execution_outcome=SELECTED_OUTCOME,
            next_lawful_move=NEXT_LAWFUL_MOVE,
        ),
        "quickstart": _quickstart(base),
        "operator_runbook": _operator_runbook(base),
        "data_governance_pack": _data_governance_pack(base),
        "pilot_contract_rider": _pilot_contract_rider(base),
        "customer_safe_language": _customer_safe_language(base),
        "packet_report": _packet_report(base),
    }


def _safe_doc_header(base: Dict[str, Any], title: str) -> list[str]:
    return [
        f"# {title}",
        "",
        "Documentary-only commercial proof surface.",
        f"Current main: {base['current_main_head']}",
        f"Lane: {AUTHORITATIVE_LANE}",
        "Commercial activation claims authorized: false",
        "External audit completed: false",
        "7B amplification proven: false",
        "Beyond-SOTA claimed: false",
        "S-tier claimed: false",
        "FP0 or highway promoted to authority: false",
        "",
    ]


def _quickstart(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Quickstart")
    lines.extend(
        [
            "Use this quickstart to assemble the bounded proof packet for review.",
            "Do not describe this packet as commercial activation, external audit completion, or unrestricted production readiness.",
            "Required first check: verify the claim boundary receipt and next-lawful-move receipt before using any customer-facing language.",
            "",
        ]
    )
    return "\n".join(lines)


def _operator_runbook(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Operator Runbook")
    lines.extend(
        [
            "Operators may present evidence, run verifier preparation, and collect reviewer questions.",
            "Operators may not expand claims beyond the bound allowed-claims state.",
            "Any support, incident, rollback, or data-governance statement must cite the evidence pack manifest.",
            "",
        ]
    )
    return "\n".join(lines)


def _data_governance_pack(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Data Governance Pack")
    lines.extend(
        [
            "Data handling statements are limited to documented pilot/review handling.",
            "This document does not make legal, medical, compliance, or regulatory certification claims.",
            "Retention/deletion language must be validated by a later commercial claim authorization lane before public activation.",
            "",
        ]
    )
    return "\n".join(lines)


def _pilot_contract_rider(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Pilot Contract Rider")
    lines.extend(
        [
            "The pilot rider is a draft support surface for bounded review and pilot conversations.",
            "It does not authorize production-commercial-live claims or external audit completion claims.",
            "All final contract language remains subject to separate legal and claim-authorization review.",
            "",
        ]
    )
    return "\n".join(lines)


def _customer_safe_language(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Customer-Safe Language")
    lines.extend(
        [
            "Allowed framing: KT has a governed evidence and verifier preparation packet for bounded review.",
            "Forbidden framing: KT has completed external audit, proved 7B amplification, or earned beyond-SOTA/S-tier claims.",
            "If a sentence sounds stronger than the receipts, downgrade it or block it.",
            "",
        ]
    )
    return "\n".join(lines)


def _packet_report(base: Dict[str, Any]) -> str:
    lines = _safe_doc_header(base, "KT Commercial Proof Plane Packet")
    lines.extend(
        [
            f"Outcome: {SELECTED_OUTCOME}",
            f"Next lawful move: {NEXT_LAWFUL_MOVE}",
            "Commercial proof plane validated: false",
            "Adversarial proof corridor next: false",
            "",
        ]
    )
    return "\n".join(lines)


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    branch = _ensure_branch_context(root)
    _ensure_workspace_scope(root)
    payloads = _load_json_inputs(root)
    _validate_predecessor(payloads)
    _validate_sources(root, payloads)
    trust_zone_validation = validate_trust_zones(root=root)
    if trust_zone_validation.get("status") != "PASS" or trust_zone_validation.get("failures"):
        _fail("RC_KT_COMMERCIAL_PROOF_PLANE_TRUST_ZONE_FAILED", "trust-zone validation failed")

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
    return argparse.ArgumentParser(description="Author the KT commercial proof plane packet.").parse_args()


def main() -> int:
    _parse_args()
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
