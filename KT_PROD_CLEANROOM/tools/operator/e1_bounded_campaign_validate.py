from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.benchmark_constitution_validate import (
    ROLE_BASELINE_SCORECARD,
    ROLE_BENCHMARK_RECEIPT,
    _consume_emitted_receipt_contract,
    _enforce_write_scope_post,
    _enforce_write_scope_pre,
    _maybe_write_json_output,
    _payloads,
    build_receipt as build_benchmark_receipt,
)
from tools.operator.public_verifier import manifest_supports_bounded_e1_verifier
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DOCS_COMMERCIAL_ROOT_REL = "KT_PROD_CLEANROOM/docs/commercial"
DOCS_OPERATOR_ROOT_REL = "KT_PROD_CLEANROOM/docs/operator"
PRODUCT_ROOT_REL = "KT_PROD_CLEANROOM/product"

COMMERCIAL_TRUTH_PACKET_REL = f"{REPORT_ROOT_REL}/commercial_truth_packet.json"
PUBLIC_VERIFIER_KIT_REL = f"{REPORT_ROOT_REL}/public_verifier_kit.json"
C006_SECOND_HOST_KIT_REL = f"{REPORT_ROOT_REL}/c006_second_host_kit.json"
EXTERNAL_AUDIT_PACKET_REL = f"{REPORT_ROOT_REL}/external_audit_packet_manifest.json"
E1_CAMPAIGN_RECEIPT_REL = f"{REPORT_ROOT_REL}/e1_bounded_campaign_receipt.json"
C006_DEFERRAL_STATUS_RECEIPT_REL = f"{REPORT_ROOT_REL}/c006_deferral_status_receipt.json"
SECOND_HOST_KIT_HARDENING_RECEIPT_REL = f"{REPORT_ROOT_REL}/second_host_kit_hardening_receipt.json"
PRODUCT_INSTALL_RECEIPT_REL = f"{REPORT_ROOT_REL}/product_install_15m_receipt.json"
OPERATOR_HANDOFF_RECEIPT_REL = f"{REPORT_ROOT_REL}/operator_handoff_receipt.json"
STANDARDS_MAPPING_RECEIPT_REL = f"{REPORT_ROOT_REL}/standards_mapping_receipt.json"

TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
DEFERRAL_HEARTBEAT_REL = f"{REPORT_ROOT_REL}/c006_deferral_heartbeat.json"
PRODUCT_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_product_truth_surface.json"
RELEASE_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_release_truth_surface.json"
DEPLOYMENT_PROFILES_REL = f"{REPORT_ROOT_REL}/deployment_profiles.json"
CAPABILITY_ATLAS_REL = f"{REPORT_ROOT_REL}/capability_atlas.json"
BASELINE_SCORECARD_REL = f"{REPORT_ROOT_REL}/baseline_vs_live_scorecard.json"
BENCHMARK_CONSTITUTION_RECEIPT_REL = f"{REPORT_ROOT_REL}/benchmark_constitution_receipt.json"
ALIAS_RETIREMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/scorecard_alias_retirement_receipt.json"
DETACHMENT_RECEIPT_REL = f"{REPORT_ROOT_REL}/competitive_scorecard_validator_detachment_receipt.json"
PUBLIC_VERIFIER_MANIFEST_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
DETACHED_VERIFIER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_detached_receipt.json"
DEFERRED_BLOCKERS_REL = f"{REPORT_ROOT_REL}/deferred_blockers.json"
C006_EXECUTION_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_execution_receipt.json"
C006_HANDOFF_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_friendly_host_handoff_pack.json"
C006_TEMPLATE_REL = f"{REPORT_ROOT_REL}/post_wave5_c006_second_host_submission_template.json"
REPLAY_RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"
BUYER_WEDGE_DOC_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/E1_BOUNDED_TRUST_WEDGE.md"
E1_DEMO_SCRIPT_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/E1_DEMO_SCRIPT.md"
PRESALES_DIAG_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/PRESALES_DIAGNOSTIC.md"
PROPOSAL_TEMPLATE_REL = f"{DOCS_COMMERCIAL_ROOT_REL}/PROPOSAL_TEMPLATE.md"
HAT_DEMO_DOC_REL = f"{DOCS_OPERATOR_ROOT_REL}/KT_HAT_DEMO.md"
OPERATOR_QUICKSTART_REL = f"{DOCS_OPERATOR_ROOT_REL}/RUN_KT_IN_30_MINUTES.md"
C006_RUNBOOK_REL = f"{DOCS_OPERATOR_ROOT_REL}/C006_SECOND_HOST_RUNBOOK.md"
C006_IMPORT_CHECKLIST_REL = f"{DOCS_OPERATOR_ROOT_REL}/C006_IMPORT_CHECKLIST.md"
C006_RERUN_CHECKLIST_REL = f"{DOCS_OPERATOR_ROOT_REL}/C006_VALIDATOR_RERUN_CHECKLIST.md"
C006_RETURN_PLACEMENT_REL = f"{DOCS_OPERATOR_ROOT_REL}/C006_RETURN_FILE_PLACEMENT_CHECKLIST.md"
C006_BUNDLE_BUILDER_REL = "KT_PROD_CLEANROOM/tools/operator/build_c006_second_host_bundle.py"
C006_BUNDLE_OUTPUT_DIR_REL = "KT_PROD_CLEANROOM/exports/c006_second_host_kit/current_head_bundle"
C006_BUNDLE_MANIFEST_REL = f"{C006_BUNDLE_OUTPUT_DIR_REL}/KT_PROD_CLEANROOM/reports/c006_second_host_bundle_manifest.json"
PRODUCT_DEPLOYMENT_PROFILES_REL = f"{PRODUCT_ROOT_REL}/deployment_profiles.json"
CLIENT_WRAPPER_SPEC_REL = f"{PRODUCT_ROOT_REL}/client_wrapper_spec.json"
PRODUCT_RUNBOOK_REL = f"{PRODUCT_ROOT_REL}/operator_runbook_v2.md"
SUPPORT_BOUNDARY_REL = f"{PRODUCT_ROOT_REL}/support_boundary.json"
ONE_PAGE_PRODUCT_TRUTH_REL = f"{PRODUCT_ROOT_REL}/one_page_product_truth_surface.md"
NIST_MAPPING_MATRIX_REL = f"{PRODUCT_ROOT_REL}/nist_mapping_matrix.json"
ISO_42001_MAPPING_MATRIX_REL = f"{PRODUCT_ROOT_REL}/iso_42001_mapping_matrix.json"
EU_AI_ACT_ALIGNMENT_MATRIX_REL = f"{PRODUCT_ROOT_REL}/eu_ai_act_alignment_matrix.json"
SIDE_READER_CONTRACT_RECEIPT_REL = f"{REPORT_ROOT_REL}/comparator_side_reader_contract_adoption_receipt.json"
T7_TRANCHE_ID = "B03_T7_COMPARATOR_SIDE_READER_CONTRACT_ADOPTION"
T7_RECEIPT_ROLE = "COUNTED_T7_SIDE_READER_CONTRACT_ADOPTION_ARTIFACT_ONLY"
ROLE_ALIAS_RETIREMENT = "ALIAS_RETIREMENT_PROOF"
ROLE_VALIDATOR_ALIAS_DETACHMENT = "VALIDATOR_ALIAS_DETACHMENT_PROOF"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _exists(root: Path, ref: str) -> bool:
    return (root / ref).exists()


def evaluate_comparator_side_reader_contract(*, root: Path) -> Dict[str, Any]:
    generated_utc = utc_now_iso_z()
    payloads = _payloads(root, generated_utc)
    current_head = str(payloads["current_head"]).strip()
    benchmark_receipt = build_benchmark_receipt(payloads, generated_utc)
    generated_receipts = [
        (BASELINE_SCORECARD_REL, payloads["scorecard"], [ROLE_BASELINE_SCORECARD]),
        (BENCHMARK_CONSTITUTION_RECEIPT_REL, benchmark_receipt, [ROLE_BENCHMARK_RECEIPT]),
        (ALIAS_RETIREMENT_RECEIPT_REL, payloads["alias_receipt"], [ROLE_ALIAS_RETIREMENT]),
        (DETACHMENT_RECEIPT_REL, payloads["detachment_receipt"], [ROLE_VALIDATOR_ALIAS_DETACHMENT]),
    ]
    generated_checks = []
    for ref, payload, allowed_roles in generated_receipts:
        result = _consume_emitted_receipt_contract(
            receipt_ref=ref,
            payload=payload,
            allowed_roles=allowed_roles,
            requested_head=current_head,
        )
        generated_checks.append(
            {
                "check_id": f"generated_contract::{Path(ref).name}",
                "receipt_ref": ref,
                **result,
            }
        )
    baseline_scorecard = payloads["scorecard"]
    malformed_attempts = [
        {
            "attempt_id": "missing_receipt_role",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={k: v for k, v in baseline_scorecard.items() if k != "receipt_role"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "missing_subject_head",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={k: v for k, v in baseline_scorecard.items() if k != "subject_head"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_receipt_role",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={**baseline_scorecard, "receipt_role": T7_RECEIPT_ROLE},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_subject_head",
            **_consume_emitted_receipt_contract(
                receipt_ref=BASELINE_SCORECARD_REL,
                payload={**baseline_scorecard, "subject_head": "0000000000000000000000000000000000000000"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
    ]
    source_text = Path(__file__).read_text(encoding="utf-8")
    legacy_parse_removed = (
        re.search(
            r"load_json\(\s*root\s*/\s*(BASELINE_SCORECARD_REL|BENCHMARK_CONSTITUTION_RECEIPT_REL|ALIAS_RETIREMENT_RECEIPT_REL|DETACHMENT_RECEIPT_REL)\s*\)",
            source_text,
        )
        is None
    )
    status = (
        "PASS"
        if all(bool(check["pass"]) for check in generated_checks)
        and malformed_attempts[0]["blocked"]
        and malformed_attempts[0]["failure_reason"] == "RECEIPT_ROLE_MISSING"
        and malformed_attempts[1]["blocked"]
        and malformed_attempts[1]["failure_reason"] == "SUBJECT_HEAD_MISSING"
        and malformed_attempts[2]["blocked"]
        and malformed_attempts[2]["failure_reason"] == "RECEIPT_ROLE_MISMATCH"
        and malformed_attempts[3]["blocked"]
        and malformed_attempts[3]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"
        and legacy_parse_removed
        else "FAIL"
    )
    return {
        "reader_id": "e1_bounded_campaign_validate",
        "status": status,
        "requested_head": current_head,
        "baseline_scorecard": payloads["scorecard"],
        "benchmark_constitution_receipt": benchmark_receipt,
        "alias_retirement_receipt": payloads["alias_receipt"],
        "detachment_receipt": payloads["detachment_receipt"],
        "generated_contract_checks": generated_checks,
        "malformed_attempts": malformed_attempts,
        "legacy_parse_removed": legacy_parse_removed,
    }


def build_comparator_side_reader_contract_adoption_receipt(*, root: Path) -> Dict[str, Any]:
    from tools.operator.final_current_head_adjudication_validate import evaluate_comparator_side_reader_contract as evaluate_final_contract
    from tools.operator.w3_externality_and_comparative_proof_validate import evaluate_comparator_side_reader_contract as evaluate_w3_contract

    e1_contract = evaluate_comparator_side_reader_contract(root=root)
    final_contract = evaluate_final_contract(root=root)
    w3_contract = evaluate_w3_contract(root=root)
    checks = [
        {"check_id": "e1_side_reader_contract_passes", "pass": e1_contract["status"] == "PASS"},
        {"check_id": "final_current_head_side_reader_contract_passes", "pass": final_contract["status"] == "PASS"},
        {"check_id": "w3_side_reader_contract_passes", "pass": w3_contract["status"] == "PASS"},
        {
            "check_id": "all_side_readers_remove_legacy_parse_fallback",
            "pass": all(bool(result.get("legacy_parse_removed")) for result in (e1_contract, final_contract, w3_contract)),
        },
    ]
    current_head = str(e1_contract["requested_head"]).strip()
    return {
        "schema_id": "kt.gate_c_t7.comparator_side_reader_contract_adoption_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": T7_RECEIPT_ROLE,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tranche_id": T7_TRANCHE_ID,
        "canonical_scorecard_id": str(e1_contract["baseline_scorecard"].get("canonical_scorecard_id", "")).strip(),
        "claim_boundary": "B03 tranche 7 adopts the already-earned comparator receipt contract in side-reader validator paths only. It does not widen comparator semantics or exit Gate C.",
        "checks": checks,
        "reader_results": [e1_contract, final_contract, w3_contract],
    }


def build_commercial_truth_packet(*, root: Path) -> Dict[str, Any]:
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    heartbeat = load_json(root / DEFERRAL_HEARTBEAT_REL)
    product_truth = load_json(root / PRODUCT_TRUTH_REL)
    release_truth = load_json(root / RELEASE_TRUTH_REL)
    deployment_profiles = load_json(root / DEPLOYMENT_PROFILES_REL)
    capability_atlas = load_json(root / CAPABILITY_ATLAS_REL)
    comparator_contract = evaluate_comparator_side_reader_contract(root=root)
    if comparator_contract["status"] != "PASS":
        raise RuntimeError("FAIL_CLOSED: E1 comparator side-reader contract adoption failed")
    baseline_scorecard = comparator_contract["baseline_scorecard"]
    benchmark_constitution_receipt = comparator_contract["benchmark_constitution_receipt"]
    alias_retirement_receipt = comparator_contract["alias_retirement_receipt"]
    detachment_receipt = comparator_contract["detachment_receipt"]
    product_install_receipt = load_json(root / PRODUCT_INSTALL_RECEIPT_REL)
    operator_handoff_receipt = load_json(root / OPERATOR_HANDOFF_RECEIPT_REL)
    standards_mapping_receipt = load_json(root / STANDARDS_MAPPING_RECEIPT_REL)

    required_docs = [
        BUYER_WEDGE_DOC_REL,
        E1_DEMO_SCRIPT_REL,
        PRESALES_DIAG_REL,
        PROPOSAL_TEMPLATE_REL,
        HAT_DEMO_DOC_REL,
        OPERATOR_QUICKSTART_REL,
        ONE_PAGE_PRODUCT_TRUTH_REL,
        PRODUCT_RUNBOOK_REL,
    ]
    status = (
        "PASS"
        if _status_is(truth_lock.get("status"), "PASS")
        and _status_is(heartbeat.get("status"), "PASS")
        and _status_is(product_truth.get("status"), "PASS")
        and _status_is(release_truth.get("status"), "PASS")
        and _status_is(deployment_profiles.get("status"), "ACTIVE")
        and _status_is(capability_atlas.get("status"), "PASS")
        and _status_is(baseline_scorecard.get("status"), "PASS")
        and _status_is(benchmark_constitution_receipt.get("status"), "PASS")
        and _status_is(alias_retirement_receipt.get("status"), "PASS")
        and _status_is(detachment_receipt.get("status"), "PASS")
        and _status_is(product_install_receipt.get("status"), "PASS")
        and _status_is(operator_handoff_receipt.get("status"), "PASS")
        and _status_is(standards_mapping_receipt.get("status"), "PASS")
        and comparator_contract["status"] == "PASS"
        and baseline_scorecard.get("canonical_scorecard_id") == "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
        and all(_exists(root, ref) for ref in required_docs)
        else "FAIL"
    )
    return {
        "schema_id": "kt.e1.commercial_truth_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "offer_surface": [
            "governed_execution",
            "admissibility",
            "replay",
            "bounded_runtime_trust",
            "verifier_kit",
            "external_audit_packet",
            "buyer_simple_product_plane",
        ],
        "externality_class_max": truth_lock.get("claim_ceiling_enforcements", {}).get("externality_class_max", "E1_SAME_HOST_DETACHED_REPLAY"),
        "comparative_widening": truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "FORBIDDEN"),
        "commercial_widening": truth_lock.get("claim_ceiling_enforcements", {}).get("commercial_widening", "FORBIDDEN"),
        "c006_status": heartbeat.get("deferral_status", ""),
        "buyer_safe_material_refs": required_docs,
        "demo_flow": [
            "State the bounded problem and E1 claim ceiling.",
            "Run KT on the declared bounded path.",
            "Show the emitted receipt and packet refs.",
            "Hand over the verifier kit.",
            "Run the verifier entrypoint.",
            "Show the same bounded result and PASS/FAIL surface.",
            "Restate what the packet proves and what it does not prove.",
        ],
        "presales_flow": [
            "Diagnostic",
            "Demo",
            "Verifier handoff",
            "Proposal",
            "Bounded pilot",
        ],
        "source_refs": [
            TRUTH_LOCK_REL,
            DEFERRAL_HEARTBEAT_REL,
            PRODUCT_TRUTH_REL,
            RELEASE_TRUTH_REL,
            DEPLOYMENT_PROFILES_REL,
            CAPABILITY_ATLAS_REL,
            BASELINE_SCORECARD_REL,
            BENCHMARK_CONSTITUTION_RECEIPT_REL,
            ALIAS_RETIREMENT_RECEIPT_REL,
            DETACHMENT_RECEIPT_REL,
            PRODUCT_INSTALL_RECEIPT_REL,
            OPERATOR_HANDOFF_RECEIPT_REL,
            STANDARDS_MAPPING_RECEIPT_REL,
        ],
        "comparator_contract_status": comparator_contract["status"],
        "claim_boundary": (
            "This packet is a bounded E1 trust wedge only. It does not unlock E2+, comparative superiority, enterprise readiness, or broad commercial widening."
        ),
        "forbidden_claims": [
            "Do not claim E2, E3, or E4.",
            "Do not claim cross-host reproducibility.",
            "Do not claim comparative or category-leading superiority.",
            "Do not claim enterprise readiness beyond the bounded trust wedge.",
        ],
    }


def build_public_verifier_kit(*, root: Path) -> Dict[str, Any]:
    manifest = load_json(root / PUBLIC_VERIFIER_MANIFEST_REL)
    detached = load_json(root / DETACHED_VERIFIER_RECEIPT_REL)
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    heartbeat = load_json(root / DEFERRAL_HEARTBEAT_REL)
    deployment_profiles = load_json(root / DEPLOYMENT_PROFILES_REL)
    product_install_receipt = load_json(root / PRODUCT_INSTALL_RECEIPT_REL)
    status = (
        "PASS"
        if manifest_supports_bounded_e1_verifier(manifest)
        and _status_is(detached.get("status"), "PASS")
        and _status_is(truth_lock.get("status"), "PASS")
        and _status_is(heartbeat.get("status"), "PASS")
        and _status_is(deployment_profiles.get("status"), "ACTIVE")
        and _status_is(product_install_receipt.get("status"), "PASS")
        and _exists(root, CLIENT_WRAPPER_SPEC_REL)
        and _exists(root, SUPPORT_BOUNDARY_REL)
        and _exists(root, OPERATOR_QUICKSTART_REL)
        else "FAIL"
    )
    return {
        "schema_id": "kt.e1.public_verifier_kit.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "kit_status": "BOUNDED_E1_READY",
        "entrypoints": [
            "python -m tools.operator.public_verifier",
            "python -m tools.operator.public_verifier_detached_validate",
        ],
        "manifest_ref": PUBLIC_VERIFIER_MANIFEST_REL,
        "detached_receipt_ref": DETACHED_VERIFIER_RECEIPT_REL,
        "deployment_profiles_ref": DEPLOYMENT_PROFILES_REL,
        "replay_recipe_ref": REPLAY_RECIPE_REL,
        "operator_quickstart_ref": OPERATOR_QUICKSTART_REL,
        "client_wrapper_spec_ref": CLIENT_WRAPPER_SPEC_REL,
        "support_boundary_ref": SUPPORT_BOUNDARY_REL,
        "expected_operator_time_budget_minutes": 15,
        "pass_fail_surface": "CLEAR_PASS_FAIL_BOUNDARY",
        "externality_class_max": truth_lock.get("claim_ceiling_enforcements", {}).get("externality_class_max", "E1_SAME_HOST_DETACHED_REPLAY"),
        "claim_boundary": "The verifier kit is real and usable, but bounded at E1 while C006 remains deferred and open.",
        "forbidden_claims": [
            "Do not claim the verifier kit proves cross-host runtime capability.",
            "Do not claim the verifier kit alone closes C006.",
        ],
    }


def build_c006_second_host_kit(*, root: Path) -> Dict[str, Any]:
    heartbeat = load_json(root / DEFERRAL_HEARTBEAT_REL)
    execution = load_json(root / C006_EXECUTION_REL)
    required_refs = [
        C006_HANDOFF_REL,
        C006_TEMPLATE_REL,
        REPLAY_RECIPE_REL,
        C006_RUNBOOK_REL,
        C006_IMPORT_CHECKLIST_REL,
        C006_RERUN_CHECKLIST_REL,
        C006_RETURN_PLACEMENT_REL,
        C006_BUNDLE_BUILDER_REL,
        DEFERRED_BLOCKERS_REL,
        DEFERRAL_HEARTBEAT_REL,
        C006_DEFERRAL_STATUS_RECEIPT_REL,
        SECOND_HOST_KIT_HARDENING_RECEIPT_REL,
    ]
    bundle_manifest_present = _exists(root, C006_BUNDLE_MANIFEST_REL)
    status = (
        "PASS"
        if _status_is(heartbeat.get("status"), "PASS")
        and _status_is(execution.get("status"), "PASS")
        and all(_exists(root, ref) for ref in required_refs)
        else "FAIL"
    )
    return {
        "schema_id": "kt.c006.second_host_kit.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "kit_status": "READY_STAGED_PENDING_HARDWARE" if bundle_manifest_present else "READY_PENDING_HARDWARE",
        "bundle_builder_command": "python -m tools.operator.build_c006_second_host_bundle",
        "bundle_output_dir_hint": C006_BUNDLE_OUTPUT_DIR_REL,
        "bundle_manifest_ref": C006_BUNDLE_MANIFEST_REL if bundle_manifest_present else "",
        "deferral_status_receipt_ref": C006_DEFERRAL_STATUS_RECEIPT_REL,
        "second_host_kit_hardening_receipt_ref": SECOND_HOST_KIT_HARDENING_RECEIPT_REL,
        "return_import_path": "KT_PROD_CLEANROOM/reports/imports/post_wave5_c006_second_host_return.json",
        "runbook_refs": [
            C006_RUNBOOK_REL,
            C006_IMPORT_CHECKLIST_REL,
            C006_RERUN_CHECKLIST_REL,
            C006_RETURN_PLACEMENT_REL,
        ],
        "input_refs": [
            C006_HANDOFF_REL,
            C006_TEMPLATE_REL,
            REPLAY_RECIPE_REL,
            DEFERRED_BLOCKERS_REL,
            DEFERRAL_HEARTBEAT_REL,
            C006_DEFERRAL_STATUS_RECEIPT_REL,
            SECOND_HOST_KIT_HARDENING_RECEIPT_REL,
        ],
        "validator_commands": [
            "python -m tools.operator.post_wave5_c006_second_host_execute_validate",
            "python -m tools.operator.w3_externality_and_comparative_proof_validate",
            "python -m tools.operator.c006_deferral_law_validate",
            "python -m tools.operator.omega_gate",
        ],
        "claim_boundary": "This kit is preparation only. It keeps C006 reentry instant when hardware appears, but does not earn E2 by itself.",
    }


def build_external_audit_packet_manifest(
    *,
    root: Path,
    commercial_truth_packet: Dict[str, Any],
    public_verifier_kit: Dict[str, Any],
    c006_second_host_kit: Dict[str, Any],
) -> Dict[str, Any]:
    existing = load_json(root / EXTERNAL_AUDIT_PACKET_REL) if _exists(root, EXTERNAL_AUDIT_PACKET_REL) else {}
    legacy_packet_refs = list(existing.get("packet_refs", [])) if isinstance(existing.get("packet_refs", []), list) else []
    return {
        "schema_id": str(existing.get("schema_id", "kt.external_audit_packet_manifest.v2")).strip() or "kt.external_audit_packet_manifest.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS"
        if all(item.get("status") == "PASS" for item in (commercial_truth_packet, public_verifier_kit, c006_second_host_kit))
        else "FAIL",
        "validated_head_sha": _git_head(root),
        "packet_refs": [
            COMMERCIAL_TRUTH_PACKET_REL,
            PUBLIC_VERIFIER_KIT_REL,
            C006_SECOND_HOST_KIT_REL,
            C006_DEFERRAL_STATUS_RECEIPT_REL,
            SECOND_HOST_KIT_HARDENING_RECEIPT_REL,
            PRODUCT_INSTALL_RECEIPT_REL,
            OPERATOR_HANDOFF_RECEIPT_REL,
            STANDARDS_MAPPING_RECEIPT_REL,
            TRUTH_LOCK_REL,
            DEFERRAL_HEARTBEAT_REL,
            PRODUCT_TRUTH_REL,
            RELEASE_TRUTH_REL,
            DEPLOYMENT_PROFILES_REL,
            PRODUCT_DEPLOYMENT_PROFILES_REL,
            CLIENT_WRAPPER_SPEC_REL,
            PRODUCT_RUNBOOK_REL,
            SUPPORT_BOUNDARY_REL,
            ONE_PAGE_PRODUCT_TRUTH_REL,
            NIST_MAPPING_MATRIX_REL,
            ISO_42001_MAPPING_MATRIX_REL,
            EU_AI_ACT_ALIGNMENT_MATRIX_REL,
            BUYER_WEDGE_DOC_REL,
            E1_DEMO_SCRIPT_REL,
            PRESALES_DIAG_REL,
            PROPOSAL_TEMPLATE_REL,
            HAT_DEMO_DOC_REL,
            OPERATOR_QUICKSTART_REL,
        ],
        "legacy_packet_refs": legacy_packet_refs,
        "claim_boundary": "This audit packet is current-head and E1-bounded. It preserves the deferred C006 ceiling and does not overread the verifier or product surfaces.",
    }


def build_e1_campaign_receipt(
    *,
    root: Path,
    commercial_truth_packet: Dict[str, Any],
    public_verifier_kit: Dict[str, Any],
    c006_second_host_kit: Dict[str, Any],
    external_audit_packet: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.e1.bounded_campaign_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS"
        if all(item.get("status") == "PASS" for item in (commercial_truth_packet, public_verifier_kit, c006_second_host_kit, external_audit_packet))
        else "FAIL",
        "bounded_campaign_outputs": [
            COMMERCIAL_TRUTH_PACKET_REL,
            PUBLIC_VERIFIER_KIT_REL,
            C006_SECOND_HOST_KIT_REL,
            EXTERNAL_AUDIT_PACKET_REL,
        ],
        "claim_boundary": "This receipt certifies bounded E1 campaign completion work only. It does not close C006 or unlock comparative/commercial widening above the current ceiling.",
        "next_lawful_move": "Continue bounded E1 engineering and keep the second-host kit ready for immediate execution when hardware appears.",
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile the bounded E1 campaign-completion pack without widening claims.")
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    parser.add_argument("--allow-side-reader-contract-receipt-refresh", action="store_true")
    parser.add_argument("--commercial-truth-output", default=COMMERCIAL_TRUTH_PACKET_REL)
    parser.add_argument("--public-verifier-kit-output", default=PUBLIC_VERIFIER_KIT_REL)
    parser.add_argument("--second-host-kit-output", default=C006_SECOND_HOST_KIT_REL)
    parser.add_argument("--external-audit-output", default=EXTERNAL_AUDIT_PACKET_REL)
    parser.add_argument("--receipt-output", default=E1_CAMPAIGN_RECEIPT_REL)
    parser.add_argument("--side-reader-contract-receipt-output", default=SIDE_READER_CONTRACT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    prewrite_dirty = _enforce_write_scope_pre(root)
    commercial_truth_packet = build_commercial_truth_packet(root=root)
    public_verifier_kit = build_public_verifier_kit(root=root)
    c006_second_host_kit = build_c006_second_host_kit(root=root)
    external_audit_packet = build_external_audit_packet_manifest(
        root=root,
        commercial_truth_packet=commercial_truth_packet,
        public_verifier_kit=public_verifier_kit,
        c006_second_host_kit=c006_second_host_kit,
    )
    receipt = build_e1_campaign_receipt(
        root=root,
        commercial_truth_packet=commercial_truth_packet,
        public_verifier_kit=public_verifier_kit,
        c006_second_host_kit=c006_second_host_kit,
        external_audit_packet=external_audit_packet,
    )
    side_reader_contract_receipt = build_comparator_side_reader_contract_adoption_receipt(root=root)

    allowed_repo_writes: list[str] = []
    for target, payload, default_rel in [
        (_resolve(root, str(args.commercial_truth_output)), commercial_truth_packet, COMMERCIAL_TRUTH_PACKET_REL),
        (_resolve(root, str(args.public_verifier_kit_output)), public_verifier_kit, PUBLIC_VERIFIER_KIT_REL),
        (_resolve(root, str(args.second_host_kit_output)), c006_second_host_kit, C006_SECOND_HOST_KIT_REL),
        (_resolve(root, str(args.external_audit_output)), external_audit_packet, EXTERNAL_AUDIT_PACKET_REL),
        (_resolve(root, str(args.receipt_output)), receipt, E1_CAMPAIGN_RECEIPT_REL),
    ]:
        written = _maybe_write_json_output(
            root=root,
            target=target,
            payload=payload,
            default_rel=default_rel,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)
    written = _maybe_write_json_output(
        root=root,
        target=_resolve(root, str(args.side_reader_contract_receipt_output)),
        payload=side_reader_contract_receipt,
        default_rel=SIDE_READER_CONTRACT_RECEIPT_REL,
        allow_default_repo_write=args.allow_side_reader_contract_receipt_refresh,
    )
    if written:
        allowed_repo_writes.append(written)
    _enforce_write_scope_post(root, prewrite_dirty=prewrite_dirty, allowed_repo_writes=allowed_repo_writes)

    summary = {
        "status": receipt["status"],
        "externality_class_max": commercial_truth_packet["externality_class_max"],
        "comparative_widening": commercial_truth_packet["comparative_widening"],
        "commercial_widening": commercial_truth_packet["commercial_widening"],
        "second_host_kit_status": c006_second_host_kit["kit_status"],
        "comparator_contract_status": side_reader_contract_receipt["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
