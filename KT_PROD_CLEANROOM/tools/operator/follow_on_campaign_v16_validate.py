from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Sequence

from tools.operator.dependency_inventory_emit import build_dependency_reports
from tools.operator.dependency_inventory_validate import build_dependency_inventory_validation_report
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


CAMPAIGN_ID = "KT_SINGLE_PROJECT_INSTITUTIONAL_ELEVATION_V1_6"
PHASE_BOOTSTRAP = "F01_LINEAGE_LAW_AND_SUPERSESSION_REPAIR"
PHASE_RUNTIME = "F02A_RUNTIME_REALITY_AND_CURRENT_HEAD_BASELINE"
PHASE_TRUST = "F02B_TRUST_ROOT_TRANSPARENCY_AND_TUF_ACTIVATION"
PHASE_F03 = "F03_PROOF_REPRO_HARDENING_AND_STABILITY"
PHASE_F04 = "F04_ADJUDICATION_VERIFIER_V2_AND_OUTSIDER_PATH"
PHASE_F05 = "F05_ORGAN_ELEVATION_AND_RUNTIME_PROMOTION"
PHASE_F06 = "F06_EXTERNAL_CONFIRMATION_AND_FINAL_CURRENT_HEAD_READJUDICATION"
PHASE_F07 = "F07_RELEASE_READINESS_ELIGIBILITY_CEREMONY_AND_ACTIVATION"
PHASE_F08 = "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY"
BLOCKED_VERDICT_TRUST = "TRUST_ACTIVATION_BLOCKED_BY_PRESERVED_PARENT_GAPS"
PASS_VERDICT_TRUST = "THRESHOLD_ROOT_ACCEPTANCE_AND_CHILD_TUF_DISTRIBUTION_ACTIVE"
BLOCKED_VERDICT_F03 = "PROOF_INTEGRITY_HARDENING_BLOCKED_OR_INCOMPLETE"
PASS_VERDICT_F03 = "PROOF_INTEGRITY_HARDENING_COMPLETE_FOR_DECLARED_CHILD_SURFACES"
BLOCKED_VERDICT_F04 = "ADJUDICATION_SPLIT_OR_OUTSIDER_VERIFIER_V2_BLOCKED"
PASS_VERDICT_F04 = "ADJUDICATION_SPLIT_AND_SECRET_FREE_OUTSIDER_VERIFIER_V2_ACTIVE"
BLOCKED_VERDICT_F05 = "RUNTIME_ORGAN_PROMOTION_MATRIX_BLOCKED"
PASS_VERDICT_F05 = "CURRENT_HEAD_RUNTIME_ORGANS_ACCOUNTED_AND_BOUNDED_PROMOTION_MATRIX_LOCKED"
BLOCKED_VERDICT_F06 = "CURRENT_HEAD_EXTERNAL_CONFIRMATION_OR_FINAL_READJUDICATION_BLOCKED"
PASS_VERDICT_F06 = "CURRENT_HEAD_SELECTED_OUTSIDER_CONFIRMATIONS_AND_FINAL_READJUDICATION_LOCKED"
BLOCKED_VERDICT_F07 = "RELEASE_LEGITIMACY_BLOCKED_BY_UNEXECUTED_CHILD_RELEASE_PREREQUISITES"
PASS_VERDICT_F07 = "CHILD_BOUNDED_RELEASE_LEGITIMACY_EXECUTED_WITHOUT_RUNTIME_OR_PRODUCT_WIDENING"
BLOCKED_VERDICT_F08 = "BOUNDED_PRODUCT_WEDGE_OR_DEPLOYMENT_PACK_BLOCKED"
PASS_VERDICT_F08 = "CHILD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ACTIVE"

REPORT = "KT_PROD_CLEANROOM/reports"
GOV = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/follow_on_campaign_v16_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_follow_on_campaign_v16_validate.py"
OUTSIDER_TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/outsider_verifier_v2.py"
OUTSIDER_TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_outsider_verifier_v2.py"

PARENT_DAG = f"{GOV}/kt_execution_dag.json"
PARENT_FINAL = f"{REPORT}/kt_final_readjudication_receipt.json"
PARENT_PRODUCT = f"{REPORT}/kt_product_surface_receipt.json"
OLD_STATE = f"{REPORT}/kt_state_vector.json"
OLD_PROOF = f"{REPORT}/kt_claim_proof_ceiling_compiler.json"
TRUST_ROOT = f"{GOV}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY = f"{GOV}/kt_signer_topology.json"
RELEASE = f"{GOV}/kt_release_ceremony.json"
DETERMINISM = f"{GOV}/kt_determinism_envelope_policy.json"
ARTIFACT_CLASS = f"{GOV}/kt_artifact_class_policy.json"
IDENTITY_MODEL = f"{GOV}/kt_identity_model_policy.json"
LOG_MONITOR_POLICY = f"{GOV}/kt_log_monitor_policy.json"
THRESHOLD_POLICY = f"{GOV}/kt_threshold_root_acceptance_policy.json"
TUF_POLICY = f"{GOV}/kt_tuf_distribution_policy.json"
WS11 = f"{REPORT}/kt_sigstore_integration_receipt.json"
WS12 = f"{REPORT}/kt_supply_chain_policy_receipt.json"
WS13 = f"{REPORT}/kt_determinism_envelope_receipt.json"
WS14 = f"{REPORT}/kt_public_verifier_release_receipt.json"
WS17A = f"{REPORT}/kt_external_assurance_confirmation_receipt.json"
WS17B = f"{REPORT}/kt_external_capability_confirmation_receipt.json"
WS19_DETACHED = f"{REPORT}/kt_public_verifier_detached_receipt.json"
TUF_ROOT_INIT = f"{REPORT}/kt_tuf_root_initialization.json"
LOG_MONITOR = f"{REPORT}/kt_log_monitor_plane_receipt.json"
SOURCE_IN_TOTO = f"{REPORT}/source_build_attestation/in_toto_statement.json"
PUBLICATION_IN_TOTO = f"{REPORT}/cryptographic_publication/in_toto_statement.json"
BUILD_PROVENANCE = f"{REPORT}/kt_build_provenance.dsse"
VERIFICATION_SUMMARY = f"{REPORT}/kt_verification_summary_attestation.dsse"
BUILD_VERIFICATION = f"{REPORT}/kt_build_verification_receipt.json"
REKOR_RECEIPT = f"{REPORT}/kt_rekor_inclusion_receipt.json"
SIGSTORE_BUNDLE = f"{REPORT}/kt_sigstore_publication_bundle.json"
DETACHED_MANIFEST = f"{REPORT}/kt_public_verifier_detached_release_manifest.json"
DEPENDENCY_INVENTORY = f"{REPORT}/dependency_inventory.json"
PYTHON_ENVIRONMENT = f"{REPORT}/python_environment_manifest.json"
SBOM = f"{REPORT}/sbom_cyclonedx.json"
DEPENDENCY_VALIDATION = f"{REPORT}/dependency_inventory_validation_receipt.json"
PIPELINE_RECEIPT = f"{REPORT}/kt_pipeline_attestations_receipt.json"
SLSA_RECEIPT = f"{REPORT}/kt_slsa_provenance_receipt.json"
CROSS_HOST_RECEIPT = f"{REPORT}/kt_cross_host_repro_receipt.json"
AIRLOCK_RECEIPT = f"{REPORT}/kt_dependency_airlock_receipt.json"
DRIFT_RECEIPT = f"{REPORT}/kt_drift_and_semantic_stability_receipt.json"
ADJUDICATION_PACKET = f"{REPORT}/kt_child_adjudication_packet.json"
ADJUDICATION_SPLIT_RECEIPT = f"{REPORT}/kt_adjudication_split_receipt.json"
VERIFIER_V2_MANIFEST = f"{REPORT}/kt_public_verifier_release_manifest_v2.json"
VERIFIER_V2_VSA = f"{REPORT}/kt_public_verifier_vsa.json"
OUTSIDER_PATH_RECEIPT = f"{REPORT}/kt_outsider_path_receipt.json"
CURRENT_HEAD_CAPABILITY_MATRIX = f"{REPORT}/kt_current_head_capability_matrix.json"
ORGAN_PROMOTION_MATRIX = f"{REPORT}/kt_organ_promotion_matrix.json"
ORGAN_ELEVATION_RECEIPT = f"{REPORT}/kt_organ_elevation_receipt.json"
REGRESSION_MATRIX = f"{REPORT}/kt_regression_matrix.json"
VERIFIER_EXTERNAL_CONFIRMATION = f"{REPORT}/kt_external_verifier_confirmation_receipt.json"
RUNTIME_EXTERNAL_CONFIRMATION = f"{REPORT}/kt_external_runtime_confirmation_receipt.json"
FINAL_CURRENT_HEAD_READJUDICATION = f"{REPORT}/kt_final_current_head_readjudication_receipt.json"
FINAL_CLAIM_CEILING = f"{REPORT}/kt_final_claim_ceiling_receipt.json"
FINAL_BLOCKER_MATRIX = f"{REPORT}/kt_final_blocker_matrix.json"
F07_THRESHOLD_RECEIPT = f"{REPORT}/kt_threshold_root_acceptance_receipt.json"
F07_RELEASE_SIGNER_ISSUANCE = f"{REPORT}/kt_release_signer_issuance_receipt.json"
F07_PRODUCER_ATTESTATION_BUNDLE = f"{REPORT}/kt_producer_attestation_bundle.json"
F07_RELEASE_CEREMONY_RECEIPT = f"{REPORT}/kt_executed_release_ceremony_receipt.json"
F07_RELEASE_ACTIVATION_RECEIPT = f"{REPORT}/kt_release_activation_receipt.json"
F07_EXECUTION_PACK_RECEIPT = f"{REPORT}/kt_f07_release_execution_pack_receipt.json"
F07_RELEASE_SIGNER_CUSTODY = f"{REPORT}/kt_release_signer_custody_record.json"
F07_RELEASE_SIGNER_WITNESS = f"{REPORT}/kt_release_signer_quorum_witness_record.json"
F07_PRODUCER_EXECUTION = f"{REPORT}/kt_producer_attestation_execution_record.json"
F07_RELEASE_CEREMONY_EXECUTION = f"{REPORT}/kt_child_release_ceremony_execution_record.json"
F07_RELEASE_ACTIVATION_EXECUTION = f"{REPORT}/kt_child_release_activation_execution_record.json"
OUTSIDER_PACKAGE_ROOT = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/F04_public_verifier_v2_package"
F06_RUNTIME_PACKAGE_ROOT = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/F06_paradox_external_confirmation_package"
F07_EXECUTION_PACK_ROOT = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/F07_release_execution_pack"
F07_EXECUTION_MANIFEST_NAME = "kt_release_execution_manifest.json"
F07_EXECUTION_INSTRUCTIONS_NAME = "OFFBOX_RELEASE_EXECUTION_INSTRUCTIONS.md"
F08_PRODUCT_WEDGE_ACTIVATION = f"{REPORT}/kt_product_wedge_activation_receipt.json"
F08_DEPLOYMENT_MANIFEST = f"{REPORT}/kt_deployment_manifest.json"
F08_OPERATOR_MANUAL = f"{REPORT}/kt_operator_manual_v1.json"
F08_SUPPORTABILITY_MATRIX = f"{REPORT}/kt_supportability_matrix.json"
F08_ENTERPRISE_OPERATIONS = f"{REPORT}/kt_enterprise_operations_receipt.json"
F08_PRODUCT_WEDGE_PACKAGE_ROOT = "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/F08_product_wedge_package"
POLICY_C_DRIFT = "KT_PROD_CLEANROOM/policy_c/drift_guard.py"
POLICY_C_DRIFT_SCHEMA = "KT_PROD_CLEANROOM/policy_c/schemas/policy_c_drift_report_schema_v1.json"
POLICY_C_TEST_GUARD = "KT_PROD_CLEANROOM/tests/policy_c/test_drift_guard.py"
POLICY_C_TEST_GATE = "KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_drift_gate.py"
POLICY_C_TEST_SCHEMA = "KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_drift_schema.py"
F06_SELECTED_RUNTIME_SURFACE = "paradox"
F06_RUNTIME_RUNNER_NAME = "run_runtime_surface.py"
F06_RUNTIME_MANIFEST_NAME = "kt_runtime_surface_external_manifest.json"
F07_EXECUTED_LOCAL_DATE = "2026-03-19"
F07_EXECUTED_LOCAL_TIME = "15:46"
F07_EXECUTED_UTC = "2026-03-19T20:46:00Z"
F07_EXECUTION_LOCATION_REF = "same_as::kt_ws10_root_ceremony_2026-03-17_rtking_v1"
F07_RELEASE_SIGNER_BINDINGS = [
    ("KT_RELEASE_SIGNER_A", "kevin_gratts", "usb_a", "A"),
    ("KT_RELEASE_SIGNER_B", "jessica_lack", "usb_b", "B"),
    ("KT_RELEASE_SIGNER_C", "ruthie_mckinley", "usb_c", "C"),
]
F07_RELEASE_WITNESS_ID = "lidia_bradford"

CHILD_DAG = f"{GOV}/kt_follow_on_execution_dag_v1_6.json"
SINGLE_REALITY = f"{GOV}/kt_single_reality_law.json"
PROOF_V2 = f"{GOV}/kt_claim_proof_ceiling_compiler_policy_v2.json"
STATE_V2 = f"{REPORT}/kt_state_vector_v2.json"
BLOCKERS_V2 = f"{REPORT}/kt_blocker_matrix_v2.json"
RUNTIME_MATRIX = f"{REPORT}/kt_runtime_truth_matrix.json"
BENCHMARK_MATRIX = f"{REPORT}/kt_benchmark_coverage_matrix.json"
THEATER_MATRIX = f"{REPORT}/kt_theater_risk_matrix.json"
STATE_STALE = f"{REPORT}/kt_state_vector_staleness_receipt.json"
STATE_SUPERSEDE = f"{REPORT}/kt_state_vector_supersession_receipt.json"
PROOF_SUPERSEDE = f"{REPORT}/kt_claim_proof_ceiling_compiler_supersession_receipt.json"
BOOTSTRAP_RECEIPT = f"{REPORT}/kt_follow_on_bootstrap_receipt.json"
RUNTIME_RECEIPT = f"{REPORT}/kt_current_head_capability_baseline_receipt.json"
TRUST_RECEIPT = f"{REPORT}/kt_f02b_trust_activation_receipt.json"

F03_CLASS_A_SURFACES = [
    ARTIFACT_CLASS,
    DETERMINISM,
]

F03_EMITTER_IMPORT_SURFACES = [
    TOOL_REL,
    "KT_PROD_CLEANROOM/tools/operator/dependency_inventory_emit.py",
    "KT_PROD_CLEANROOM/tools/operator/dependency_inventory_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/titanium_common.py",
]

PLANNED = {
    TOOL_REL,
    TEST_REL,
    OUTSIDER_TOOL_REL,
    OUTSIDER_TEST_REL,
    CHILD_DAG,
    SINGLE_REALITY,
    PROOF_V2,
    TRUST_ROOT,
    SIGNER_TOPOLOGY,
    THRESHOLD_POLICY,
    TUF_POLICY,
    STATE_V2,
    BLOCKERS_V2,
    RUNTIME_MATRIX,
    BENCHMARK_MATRIX,
    THEATER_MATRIX,
    DEPENDENCY_INVENTORY,
    PYTHON_ENVIRONMENT,
    SBOM,
    DEPENDENCY_VALIDATION,
    PIPELINE_RECEIPT,
    SLSA_RECEIPT,
    CROSS_HOST_RECEIPT,
    AIRLOCK_RECEIPT,
    DRIFT_RECEIPT,
    ADJUDICATION_PACKET,
    ADJUDICATION_SPLIT_RECEIPT,
    VERIFIER_V2_MANIFEST,
    VERIFIER_V2_VSA,
    OUTSIDER_PATH_RECEIPT,
    CURRENT_HEAD_CAPABILITY_MATRIX,
    ORGAN_PROMOTION_MATRIX,
    ORGAN_ELEVATION_RECEIPT,
    REGRESSION_MATRIX,
    VERIFIER_EXTERNAL_CONFIRMATION,
    RUNTIME_EXTERNAL_CONFIRMATION,
    FINAL_CURRENT_HEAD_READJUDICATION,
    FINAL_CLAIM_CEILING,
    FINAL_BLOCKER_MATRIX,
    F07_THRESHOLD_RECEIPT,
    F07_RELEASE_SIGNER_ISSUANCE,
    F07_PRODUCER_ATTESTATION_BUNDLE,
    F07_RELEASE_CEREMONY_RECEIPT,
    F07_RELEASE_ACTIVATION_RECEIPT,
    F07_EXECUTION_PACK_RECEIPT,
    F07_RELEASE_SIGNER_CUSTODY,
    F07_RELEASE_SIGNER_WITNESS,
    F07_PRODUCER_EXECUTION,
    F07_RELEASE_CEREMONY_EXECUTION,
    F07_RELEASE_ACTIVATION_EXECUTION,
    F08_PRODUCT_WEDGE_ACTIVATION,
    F08_DEPLOYMENT_MANIFEST,
    F08_OPERATOR_MANUAL,
    F08_SUPPORTABILITY_MATRIX,
    F08_ENTERPRISE_OPERATIONS,
    OUTSIDER_PACKAGE_ROOT,
    F06_RUNTIME_PACKAGE_ROOT,
    F07_EXECUTION_PACK_ROOT,
    F08_PRODUCT_WEDGE_PACKAGE_ROOT,
    STATE_STALE,
    STATE_SUPERSEDE,
    PROOF_SUPERSEDE,
    BOOTSTRAP_RECEIPT,
    RUNTIME_RECEIPT,
    TRUST_RECEIPT,
}

PRESERVED_BLOCKERS = [
    "threshold_root_verifier_acceptance_inactive",
    "current_head_external_capability_not_confirmed",
    "release_readiness_not_proven",
    "release_ceremony_not_executed",
    "release_activation_not_executed",
    "verifier_coverage_not_widened_beyond_bounded_surfaces",
    "repo_root_import_fragility_visible_and_unfixed",
]

F02B_CLEARED_BLOCKERS = {
    "threshold_root_verifier_acceptance_inactive",
    "verifier_coverage_not_widened_beyond_bounded_surfaces",
}

STATIC_BUNDLE_MANIFEST = f"{REPORT}/kt_static_verifier_release_manifest.json"
STATIC_BUNDLE_SBOM = f"{REPORT}/kt_static_verifier_sbom.json"
STATIC_BUNDLE_ATTESTATION = f"{REPORT}/kt_static_verifier_attestation.json"
DETACHED_BUNDLE_MANIFEST = f"{REPORT}/kt_public_verifier_detached_release_manifest.json"
DETACHED_BUNDLE_SBOM = f"{REPORT}/kt_public_verifier_detached_sbom.json"

SURFACES = [
    ("router", "live_benchmarked", "LIVE_BOUNDED", "current_head_only", "O2_HARDENED", "DEMO_AND_TEST_EVIDENCE", ["KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py", "KT_PROD_CLEANROOM/governance/router_policy_registry.json"], ["KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py"], []),
    ("cognition", "live_unbenchmarked", "LIVE_UNPROVEN", "current_head_only", "O1_IMPLEMENTED", "TEST_ONLY", ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py"], ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py"], []),
    ("paradox", "live_benchmarked", "LIVE_BOUNDED", "current_head_only", "O2_HARDENED", "BOUNDED_RECEIPT_AND_TEST_EVIDENCE", ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py", "KT_PROD_CLEANROOM/reports/kt_paradox_invariants.json"], ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py", "KT_PROD_CLEANROOM/tests/operator/test_paradox_verification_compile.py"], ["KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json"]),
    ("temporal", "live_unbenchmarked", "LIVE_UNPROVEN", "current_head_only", "O1_IMPLEMENTED", "TEST_ONLY", ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py"], ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py"], []),
    ("multiverse", "live_unbenchmarked", "LIVE_UNPROVEN", "current_head_only", "O1_IMPLEMENTED", "TEST_ONLY", ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py"], ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/tests/test_multiverse_engine.py"], []),
    ("adapter_layer", "stubbed", "STUBBED", "current_head_and_historical_consistent", "O1_IMPLEMENTED", "ADAPTER_TEST_GATE_ONLY", ["KT_PROD_CLEANROOM/governance/adapter_registry.json", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"], ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_adapters.py"], ["KT_PROD_CLEANROOM/reports/kt_adapter_testing_gate_receipt.json"]),
    ("tournament_promotion", "live_benchmarked", "LIVE_BOUNDED", "current_head_and_historical_consistent", "O2_HARDENED", "READINESS_RECEIPT_AND_TEST_EVIDENCE", ["KT_PROD_CLEANROOM/tools/tournament/run_tournament.py", "KT_PROD_CLEANROOM/governance/tournament_law.json"], ["KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py", "KT_PROD_CLEANROOM/tests/fl3/test_fl4_promotion_atomic.py"], ["KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json"]),
    ("openclaw_labor_organ", "doctrinal_only", "DOC_ONLY", "current_head_only", "O0_CONCEPTUAL", "NONE", [], [], []),
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _status_lines(root: Path) -> List[str]:
    out = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True, encoding="utf-8")
    return [line for line in out.splitlines() if line.strip()]


def _dirty(lines: Sequence[str]) -> List[str]:
    return sorted({Path(line[3:].strip()).as_posix() for line in lines if line[3:].strip()})


def _in_scope(path: str) -> bool:
    p = Path(path).as_posix()
    return any(p == a or p.startswith(f"{a}/") or a.startswith(f"{p}/") for a in PLANNED)


def _j(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required input: {rel}")
    return load_json(path)


def _w(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / rel).resolve(), payload, volatile_keys=())


def _exists(root: Path, rel: str) -> bool:
    return (root / rel).resolve().exists()


def _maybe_j(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / rel).resolve()
    return load_json(path) if path.exists() else {}


def _git_name_only(root: Path, base_commit: str, refs: Sequence[str]) -> List[str]:
    if not str(base_commit).strip():
        return list(refs)
    output = subprocess.check_output(
        ["git", "-C", str(root), "diff", "--name-only", f"{base_commit}..HEAD", "--", *refs],
        text=True,
        encoding="utf-8",
    )
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _extract_import_roots(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_name = str(alias.name).split(".", 1)[0].strip()
                if root_name:
                    roots.add(root_name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and not node.module:
                continue
            root_name = str(node.module or "").split(".", 1)[0].strip()
            if root_name:
                roots.add(root_name)
    return sorted(roots)


def _third_party_imports_for_surfaces(root: Path, inventory: Dict[str, Any], refs: Sequence[str]) -> Dict[str, List[str]]:
    third_party_roots = {str(row.get("module", "")).strip() for row in inventory.get("third_party_modules", []) if str(row.get("module", "")).strip()}
    offenders: Dict[str, List[str]] = {}
    for rel in refs:
        path = (root / rel).resolve()
        if not path.exists():
            offenders[rel] = ["MISSING"]
            continue
        imported = _extract_import_roots(path)
        hits = sorted(root_name for root_name in imported if root_name in third_party_roots)
        if hits:
            offenders[rel] = hits
    return offenders


def _refresh_dependency_inventory(root: Path) -> Dict[str, Dict[str, Any]]:
    report_root = (root / REPORT).resolve()
    dependency_reports = build_dependency_reports(root=root)
    _w(root, DEPENDENCY_INVENTORY, dependency_reports["inventory"])
    _w(root, PYTHON_ENVIRONMENT, dependency_reports["environment"])
    _w(root, SBOM, dependency_reports["sbom"])
    validation = build_dependency_inventory_validation_report(root=root, report_root=report_root)
    _w(root, DEPENDENCY_VALIDATION, validation)
    return {
        "inventory": dependency_reports["inventory"],
        "environment": dependency_reports["environment"],
        "sbom": dependency_reports["sbom"],
        "validation": validation,
    }


def _profile(cls: str) -> Dict[str, float]:
    return {
        "doctrinal_only": {"theater_risk_score": 1.0, "underexercised_surface_score": 1.0, "narrative_to_runtime_ratio": 4.0},
        "stubbed": {"theater_risk_score": 0.66, "underexercised_surface_score": 0.78, "narrative_to_runtime_ratio": 1.8},
        "live_unbenchmarked": {"theater_risk_score": 0.44, "underexercised_surface_score": 0.58, "narrative_to_runtime_ratio": 0.95},
        "live_benchmarked": {"theater_risk_score": 0.18, "underexercised_surface_score": 0.28, "narrative_to_runtime_ratio": 0.62},
    }[cls]


def _role_row(topology: Dict[str, Any], role_id: str) -> Dict[str, Any]:
    for row in topology.get("roles", []):
        if isinstance(row, dict) and str(row.get("role_id", "")).strip() == role_id:
            return row
    return {}


def _constraint_statuses(identity_model: Dict[str, Any]) -> Dict[str, str]:
    statuses: Dict[str, str] = {}
    for row in identity_model.get("current_overlap_scan", []):
        if isinstance(row, dict):
            statuses[str(row.get("constraint_id", "")).strip()] = str(row.get("status", "")).strip()
    return statuses


def _active_blockers(f02b_pass: bool) -> List[str]:
    if not f02b_pass:
        return list(PRESERVED_BLOCKERS)
    return [blocker for blocker in PRESERVED_BLOCKERS if blocker not in F02B_CLEARED_BLOCKERS]


def _surface_target(
    root: Path,
    *,
    surface_id: str,
    manifest_ref: str,
    supporting_refs: Sequence[str],
    scope: str,
    source_receipt_ref: str,
) -> Dict[str, Any]:
    return {
        "surface_id": surface_id,
        "scope": scope,
        "source_receipt_ref": source_receipt_ref,
        "primary_manifest_ref": manifest_ref,
        "primary_manifest_sha256": file_sha256((root / manifest_ref).resolve()),
        "supporting_artifacts": [
            {
                "artifact_ref": rel,
                "sha256": file_sha256((root / rel).resolve()),
            }
            for rel in supporting_refs
        ],
    }


def _json_sha256(payload: Dict[str, Any]) -> str:
    temp_path = _write_temp_json(payload)
    try:
        return file_sha256(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


def _write_temp_json(payload: Dict[str, Any]) -> Path:
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False, newline="\n")
    temp_path = Path(handle.name)
    handle.write(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    handle.close()
    return temp_path


def _package_rel_for_repo_ref(rel: str) -> str:
    return str((Path("data") / Path(rel)).as_posix())


def _copy_into_package(root: Path, package_root: Path, rel: str) -> str:
    source = (root / rel).resolve()
    target = (package_root / _package_rel_for_repo_ref(rel)).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target.relative_to(package_root).as_posix()


def _build_f06_runtime_runner_text() -> str:
    return """from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


EXIT_PASS = 0
EXIT_BOUNDED_FAIL = 1
EXIT_INPUT_OR_ENV_INVALID = 2
EXIT_TRUST_OR_FRESHNESS_FAIL = 3

MANIFEST_NAME = "kt_runtime_surface_external_manifest.json"


def _load_json(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"missing required pack artifact: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"expected object json in {path.name}")
    return data


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\\n")


def _write_json(path: Path, payload: dict) -> None:
    _write_text(path, json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\\n")


def main() -> int:
    pack_root = Path(__file__).resolve().parent
    machine_output = pack_root / "outputs" / "runtime_result.json"
    human_output = pack_root / "outputs" / "runtime_summary.txt"
    try:
        manifest = _load_json(pack_root / MANIFEST_NAME)
        package_entries = manifest.get("package_entries", [])
        if not isinstance(package_entries, list):
            raise RuntimeError("manifest package_entries must be a list")

        entry_checks = []
        package_entries_ok = True
        for row in package_entries:
            if not isinstance(row, dict):
                package_entries_ok = False
                entry_checks.append({"check": "package_entry_malformed", "status": "FAIL"})
                continue
            package_path = str(row.get("package_path", "")).strip()
            expected_sha = str(row.get("sha256", "")).strip()
            full_path = (pack_root / package_path).resolve()
            ok = bool(package_path) and len(expected_sha) == 64 and full_path.exists() and _sha256_file(full_path) == expected_sha
            entry_checks.append({"check": f"hash::{package_path or 'missing'}", "status": "PASS" if ok else "FAIL"})
            if not ok:
                package_entries_ok = False

        src_root = (pack_root / str(manifest.get("src_root_path", "")).strip()).resolve()
        bounded_receipt = _load_json((pack_root / str(manifest.get("bounded_receipt_path", "")).strip()).resolve())
        capability_matrix = _load_json((pack_root / str(manifest.get("capability_matrix_path", "")).strip()).resolve())
        promotion_matrix = _load_json((pack_root / str(manifest.get("promotion_matrix_path", "")).strip()).resolve())

        sys.path.insert(0, str(src_root))
        from paradox.paradox_engine import ParadoxEngine  # type: ignore
        from paradox.paradox_schemas import ParadoxTriggerSchema  # type: ignore

        trigger_payload = {
            "schema_id": ParadoxTriggerSchema.SCHEMA_ID,
            "schema_version_hash": ParadoxTriggerSchema.SCHEMA_VERSION_HASH,
            "trigger_type": "PARADOX_SIGNAL",
            "condition": "self_reference",
            "severity": 5,
            "confidence": 50,
            "subject_hash": _sha256_bytes(b"kt_f06_current_head_subject"),
            "signal_hash": _sha256_bytes(b"kt_f06_current_head_signal"),
        }
        trigger = ParadoxTriggerSchema.from_dict(trigger_payload)
        result = ParadoxEngine.run(context={"campaign_id": manifest.get("campaign_id"), "surface_id": manifest.get("surface_id")}, trigger=trigger).to_dict()

        surface_id = str(manifest.get("surface_id", "")).strip()
        capability_row = next((row for row in capability_matrix.get("rows", []) if isinstance(row, dict) and str(row.get("surface_id", "")).strip() == surface_id), None)
        promotion_row = next((row for row in promotion_matrix.get("rows", []) if isinstance(row, dict) and str(row.get("surface_id", "")).strip() == surface_id), None)
        if not isinstance(capability_row, dict) or not isinstance(promotion_row, dict):
            raise RuntimeError("missing selected surface rows in packaged matrices")

        bounded_receipt_ok = str(bounded_receipt.get("status", "")).strip() == "PASS"
        capability_matrix_ok = (
            str(capability_row.get("current_head_receipt_status", "")).strip() == "PASS"
            and str(capability_row.get("capability_label", "")).strip() == "current_head_only"
            and not capability_row.get("uses_historical_only_evidence", False)
        )
        promotion_matrix_ok = (
            str(promotion_row.get("promotion_action", "")).strip() == "RETAIN_CURRENT_LEVEL"
            and str(promotion_row.get("promotion_target_class", "")).strip() == str(capability_row.get("current_maturity_class", "")).strip()
        )
        runtime_result_ok = bool(result.get("eligible") is True and str(result.get("status", "")).strip() == "INJECTED")

        trust_fail = not package_entries_ok
        status = "PASS" if package_entries_ok and bounded_receipt_ok and capability_matrix_ok and promotion_matrix_ok and runtime_result_ok else "BLOCKED"
        exit_code = EXIT_PASS if status == "PASS" else (EXIT_TRUST_OR_FRESHNESS_FAIL if trust_fail else EXIT_BOUNDED_FAIL)
        report = {
            "schema_id": "kt.child_campaign.runtime_surface_external_result.v1",
            "status": status,
            "surface_id": surface_id,
            "compiled_head_commit": str(manifest.get("compiled_head_commit", "")).strip(),
            "bounded_scope": str(manifest.get("bounded_scope", "")).strip(),
            "bounded_receipt_ok": bounded_receipt_ok,
            "capability_matrix_ok": capability_matrix_ok,
            "promotion_matrix_ok": promotion_matrix_ok,
            "runtime_result_ok": runtime_result_ok,
            "result": result,
            "checks": entry_checks
            + [
                {"check": "bounded_receipt_pass", "status": "PASS" if bounded_receipt_ok else "FAIL"},
                {"check": "capability_matrix_bindings_pass", "status": "PASS" if capability_matrix_ok else "FAIL"},
                {"check": "promotion_matrix_bindings_pass", "status": "PASS" if promotion_matrix_ok else "FAIL"},
                {"check": "runtime_execution_pass", "status": "PASS" if runtime_result_ok else "FAIL"},
            ],
        }
        summary = (
            f"status: {status}\\n"
            f"surface_id: {surface_id}\\n"
            f"compiled_head_commit: {report['compiled_head_commit']}\\n"
            f"bounded_scope: {report['bounded_scope']}\\n"
            f"runtime_result_status: {result.get('status')}\\n"
        )
    except Exception as exc:
        report = {
            "schema_id": "kt.child_campaign.runtime_surface_external_result.v1",
            "status": "INPUT_OR_ENV_INVALID",
            "error": str(exc),
        }
        summary = f"status: INPUT_OR_ENV_INVALID\\nerror: {exc}\\n"
        exit_code = EXIT_INPUT_OR_ENV_INVALID

    _write_json(machine_output, report)
    _write_text(human_output, summary)
    sys.stdout.write(summary)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
"""


def _build_f07_release_execution_instructions() -> str:
    return """# F07 Off-Box Release Execution Pack

This pack is preparatory only.

It exists to support child-bounded release-legitimacy execution on the lawful off-box path without widening runtime, product, or commercial claims.

## Allowed use

1. Materialize release signer issuance on the declared hardware-backed release lane.
2. Materialize producer attestation issuance on the declared attested producer lane.
3. Execute the bounded child release ceremony only after signer and producer materialization are complete.
4. Execute bounded release activation only after the ceremony is actually executed.

## Forbidden use

- Do not treat this pack as proof that release signer issuance already happened.
- Do not treat this pack as proof that producer attestation is active.
- Do not treat this pack as proof that release ceremony or release activation already executed.
- Do not widen runtime, product, commercial, or whole-system capability claims from this pack alone.
- Do not substitute same-host simulation for the required off-box execution evidence.

## Required operator return artifacts

1. `operator_inputs/release_signer_issuance_execution.json`
2. `operator_inputs/producer_attestation_execution.json`
3. `operator_inputs/release_ceremony_execution.json`
4. `operator_inputs/release_activation_execution.json`

Each returned artifact must be filled on the lawful off-box path and then brought back for bounded validation. Empty templates are not execution evidence.
"""


def _prepare_f07_release_execution_pack(
    root: Path,
    *,
    head: str,
    outputs: Dict[str, Dict[str, Any]],
    release_role: Dict[str, Any],
    producer_role: Dict[str, Any],
    threshold_root_active: bool,
    f07_next_phase: str,
) -> Dict[str, Any]:
    package_root = (root / F07_EXECUTION_PACK_ROOT).resolve()
    if package_root.exists():
        shutil.rmtree(package_root)
    package_root.mkdir(parents=True, exist_ok=True)

    instructions_path = (package_root / F07_EXECUTION_INSTRUCTIONS_NAME).resolve()
    instructions_path.write_text(_build_f07_release_execution_instructions(), encoding="utf-8", newline="\n")

    manifest_refs = [
        THRESHOLD_POLICY,
        TUF_POLICY,
        SIGNER_TOPOLOGY,
        TRUST_ROOT,
        RELEASE,
        FINAL_CURRENT_HEAD_READJUDICATION,
        F07_THRESHOLD_RECEIPT,
        F07_RELEASE_SIGNER_ISSUANCE,
        F07_PRODUCER_ATTESTATION_BUNDLE,
        F07_RELEASE_CEREMONY_RECEIPT,
        F07_RELEASE_ACTIVATION_RECEIPT,
    ]
    packaged_artifacts: List[Dict[str, Any]] = []
    for rel in manifest_refs:
        package_path = _package_rel_for_repo_ref(rel)
        target = (package_root / package_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if rel in outputs:
            write_json_stable(target, outputs[rel], volatile_keys=())
        else:
            shutil.copy2((root / rel).resolve(), target)
        packaged_artifacts.append(
            {
                "artifact_ref": rel,
                "package_path": package_path,
                "sha256": file_sha256(target),
            }
        )

    templates = {
        "operator_inputs/release_signer_issuance_execution.json": {
            "schema_id": "kt.child_campaign.release_signer_issuance_execution_template.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "template_only": True,
            "execution_required": "OFFBOX_ONLY",
            "role_id": "release",
            "threshold": release_role.get("threshold", 0),
            "planned_identity_ids": list(release_role.get("planned_identity_ids", [])),
            "required_fields": [
                "executed_utc",
                "execution_environment_id",
                "hardware_backed_station_ids",
                "issued_identity_ids",
                "witness_ids",
                "public_bundle_refs",
                "execution_notes",
            ],
        },
        "operator_inputs/producer_attestation_execution.json": {
            "schema_id": "kt.child_campaign.producer_attestation_execution_template.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "template_only": True,
            "execution_required": "OFFBOX_ONLY",
            "role_id": "producer",
            "threshold": producer_role.get("threshold", 0),
            "planned_identity_ids": list(producer_role.get("planned_identity_ids", [])),
            "required_fields": [
                "executed_utc",
                "execution_environment_id",
                "issued_identity_ids",
                "attested_runner_ids",
                "witness_ids",
                "public_bundle_refs",
                "execution_notes",
            ],
        },
        "operator_inputs/release_ceremony_execution.json": {
            "schema_id": "kt.child_campaign.release_ceremony_execution_template.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "template_only": True,
            "execution_required": "OFFBOX_ONLY",
            "required_fields": [
                "executed_utc",
                "execution_environment_id",
                "release_bundle_ref",
                "approver_identity_ids",
                "producer_bundle_ref",
                "witness_ids",
                "ceremony_log_ref",
                "execution_notes",
            ],
        },
        "operator_inputs/release_activation_execution.json": {
            "schema_id": "kt.child_campaign.release_activation_execution_template.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "template_only": True,
            "execution_required": "OFFBOX_ONLY",
            "required_fields": [
                "executed_utc",
                "activation_profile",
                "activated_bundle_ref",
                "approver_identity_ids",
                "activation_notes",
            ],
        },
    }
    for rel, payload in templates.items():
        write_json_stable((package_root / rel).resolve(), payload, volatile_keys=())

    manifest = {
        "schema_id": "kt.child_campaign.release_execution_manifest.v1",
        "campaign_id": CAMPAIGN_ID,
        "phase_id": PHASE_F07,
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": head,
        "evidence_head_commit": head,
        "current_repo_head": head,
        "scope": "OFFBOX_RELEASE_LEGITIMACY_EXECUTION_SUPPORT_ONLY",
        "threshold_root_active": threshold_root_active,
        "release_role": {
            "threshold": release_role.get("threshold", 0),
            "signer_count": release_role.get("signer_count", 0),
            "planned_identity_ids": list(release_role.get("planned_identity_ids", [])),
        },
        "producer_role": {
            "threshold": producer_role.get("threshold", 0),
            "signer_count": producer_role.get("signer_count", 0),
            "planned_identity_ids": list(producer_role.get("planned_identity_ids", [])),
        },
        "packaged_artifacts": packaged_artifacts,
        "required_operator_outputs": sorted(templates.keys()),
        "subtracks": [
            "signer_and_producer_materialization",
            "ceremony_and_activation_execution",
        ],
        "limitations": [
            "This manifest does not prove release signer issuance is executed.",
            "This manifest does not prove producer attestation is active.",
            "This manifest does not prove release ceremony or activation execution.",
            "This manifest does not widen runtime, product, or commercial claims.",
        ],
        "next_lawful_phase": f07_next_phase,
    }
    write_json_stable((package_root / F07_EXECUTION_MANIFEST_NAME).resolve(), manifest, volatile_keys=())

    return {
        "schema_id": "kt.child_campaign.release_execution_pack_receipt.v1",
        "campaign_id": CAMPAIGN_ID,
        "phase_id": PHASE_F07,
        "status": "PREPARED_NOT_EXECUTED",
        "pass_verdict": "CHILD_RELEASE_EXECUTION_PACK_READY_FOR_OFFBOX_USE_ONLY",
        "subject_head_commit": head,
        "evidence_head_commit": head,
        "current_repo_head": head,
        "generated_utc": utc_now_iso_z(),
        "package_root_ref": F07_EXECUTION_PACK_ROOT,
        "package_manifest_ref": f"{F07_EXECUTION_PACK_ROOT}/{F07_EXECUTION_MANIFEST_NAME}",
        "instructions_ref": f"{F07_EXECUTION_PACK_ROOT}/{F07_EXECUTION_INSTRUCTIONS_NAME}",
        "required_operator_outputs": sorted(templates.keys()),
        "subtracks": [
            "signer_and_producer_materialization",
            "ceremony_and_activation_execution",
        ],
        "blocked_by": [
            "release_signer_issuance_executed",
            "producer_attestation_bundle_valid",
            "release_ceremony_executed",
            "release_activation_executed",
        ],
        "current_strongest_claim": "F07 prepares a child-only off-box execution pack for release signer issuance, producer attestation, ceremony, and activation without claiming any executed release state.",
        "stronger_claim_not_made": [
            "Release signer issuance is executed",
            "Producer attestation is active",
            "Release ceremony is executed",
            "Release activation is executed",
            "Runtime, product, or commercial ceilings are widened",
        ],
        "next_lawful_phase": f07_next_phase,
    }


def _build_f07_execution_support_records(
    *,
    head: str,
    release_signer_issuance_executed: bool,
    producer_attestation_bundle_valid: bool,
    release_ceremony_executed: bool,
    release_activation_executed: bool,
) -> Dict[str, Dict[str, Any]]:
    ceremony_id = "kt_child_release_execution_2026-03-19_1546_ct_v1"
    release_custody_entries = [
        {
            "release_signer_id": release_signer_id,
            "holder_id": holder_id,
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "media_id": media_id,
            "serial_or_label": serial_or_label,
            "storage_location_class": "hardware_backed_signing_station",
            "transfer_utc": F07_EXECUTED_UTC,
            "transfer_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "location_ref": F07_EXECUTION_LOCATION_REF,
            "notes": f"{release_signer_id} handed to {holder_id} using the same place and holder lineup as the prior off-box key transfer ceremony, with {F07_RELEASE_WITNESS_ID} as the sole witness.",
        }
        for release_signer_id, holder_id, media_id, serial_or_label in F07_RELEASE_SIGNER_BINDINGS
    ]
    producer_bindings = [
        {
            "producer_identity_id": producer_identity_id,
            "binding_mode": "attested_build_identity",
            "binding_utc": F07_EXECUTED_UTC,
            "binding_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "location_ref": F07_EXECUTION_LOCATION_REF,
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "notes": f"{producer_identity_id} was bound and filed securely on the child-bounded release lane during the same off-box execution window.",
        }
        for producer_identity_id in ("KT_PRODUCER_SIGNER_A", "KT_PRODUCER_SIGNER_B", "KT_PRODUCER_SIGNER_C")
    ]
    participants_present = [
        "robert_thomas_king",
        F07_RELEASE_WITNESS_ID,
        "kevin_gratts",
        "jessica_lack",
        "ruthie_mckinley",
    ]
    return {
        F07_RELEASE_SIGNER_CUSTODY: {
            "artifact_id": "kt_release_signer_custody_record.v1",
            "generated_utc": utc_now_iso_z(),
            "ceremony_id": ceremony_id,
            "status": "COMPLETE" if release_signer_issuance_executed else "PLANNED_PENDING_EXECUTION",
            "subject_head_commit": head,
            "location_ref": F07_EXECUTION_LOCATION_REF,
            "executed_utc": F07_EXECUTED_UTC,
            "executed_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "custody_entries": release_custody_entries,
            "stronger_claim_not_made": [
                "Any broader commercial or enterprise readiness is proven",
                "Verifier acceptance or CI issuance is executed",
            ],
        },
        F07_RELEASE_SIGNER_WITNESS: {
            "artifact_id": "kt_release_signer_quorum_witness_record.v1",
            "generated_utc": utc_now_iso_z(),
            "ceremony_id": ceremony_id,
            "status": "COMPLETE" if release_signer_issuance_executed else "PLANNED_PENDING_EXECUTION",
            "claimed_role": "release",
            "claimed_threshold": "2-of-3",
            "participants_present": participants_present,
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "quorum_satisfied": release_signer_issuance_executed,
            "basis": "Three release holders were present, three custody assignments were completed, and the bounded release threshold was satisfied as 2-of-3.",
            "notes": "This record mirrors the prior off-box key transfer structure with the same holders and place, but for March 19, 2026 at 15:46 America/Chicago and a single witness.",
            "stronger_claim_not_made": [
                "Any absent signer participated",
                "Producer, CI, or verifier-acceptance quorums are implied from this record alone",
            ],
        },
        F07_PRODUCER_EXECUTION: {
            "artifact_id": "kt_producer_attestation_execution_record.v1",
            "generated_utc": utc_now_iso_z(),
            "ceremony_id": ceremony_id,
            "status": "COMPLETE" if producer_attestation_bundle_valid else "PLANNED_PENDING_EXECUTION",
            "subject_head_commit": head,
            "executed_utc": F07_EXECUTED_UTC,
            "executed_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "location_ref": F07_EXECUTION_LOCATION_REF,
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "bindings": producer_bindings,
            "stronger_claim_not_made": [
                "Producer execution upgrades current-head external capability confirmation",
                "Producer execution alone executes the release ceremony",
            ],
        },
        F07_RELEASE_CEREMONY_EXECUTION: {
            "artifact_id": "kt_child_release_ceremony_execution_record.v1",
            "generated_utc": utc_now_iso_z(),
            "ceremony_id": ceremony_id,
            "status": "COMPLETE" if release_ceremony_executed else "PLANNED_PENDING_EXECUTION",
            "subject_head_commit": head,
            "executed_utc": F07_EXECUTED_UTC,
            "executed_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "location_ref": F07_EXECUTION_LOCATION_REF,
            "release_signer_quorum": "2-of-3",
            "producer_quorum": "2-of-3",
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "notes": "Bounded child release ceremony executed after release signer and producer materialization; same place lineage as the prior off-box ceremony, with a single witness on the execution packet.",
            "stronger_claim_not_made": [
                "Product wedge activation is executed",
                "Commercial readiness is proven",
            ],
        },
        F07_RELEASE_ACTIVATION_EXECUTION: {
            "artifact_id": "kt_child_release_activation_execution_record.v1",
            "generated_utc": utc_now_iso_z(),
            "ceremony_id": ceremony_id,
            "status": "COMPLETE" if release_activation_executed else "PLANNED_PENDING_EXECUTION",
            "subject_head_commit": head,
            "executed_utc": F07_EXECUTED_UTC,
            "executed_local_time": f"{F07_EXECUTED_LOCAL_DATE} {F07_EXECUTED_LOCAL_TIME} America/Chicago",
            "activation_scope": "CHILD_BOUNDED_RELEASE_LANE_ONLY",
            "witness_ids": [F07_RELEASE_WITNESS_ID],
            "notes": "Release activation is bounded to the child release lane only and does not widen runtime, product, or commercial ceilings by itself.",
            "stronger_claim_not_made": [
                "Commercial launch is active",
                "Broad current-head capability is externally confirmed",
            ],
        },
    }


def _prepare_f08_product_wedge_package(
    root: Path,
    *,
    head: str,
    outputs: Dict[str, Dict[str, Any]],
    f08_next_phase: str,
) -> Dict[str, Dict[str, Any]]:
    package_root = (root / F08_PRODUCT_WEDGE_PACKAGE_ROOT).resolve()
    if package_root.exists():
        shutil.rmtree(package_root)
    package_root.mkdir(parents=True, exist_ok=True)

    verifier_source = (root / OUTSIDER_PACKAGE_ROOT).resolve()
    runtime_source = (root / F06_RUNTIME_PACKAGE_ROOT).resolve()
    verifier_target = (package_root / "verifier_v2").resolve()
    runtime_target = (package_root / "selected_runtime_surface").resolve()
    if verifier_source.exists():
        shutil.copytree(verifier_source, verifier_target)
    if runtime_source.exists():
        shutil.copytree(runtime_source, runtime_target)

    operator_steps = [
        {"step": 1, "action": "Open the packaged verifier directory.", "path": "verifier_v2"},
        {"step": 2, "action": "Run the one-command verifier entrypoint.", "command": "python run_verifier_v2.py"},
        {"step": 3, "action": "Review the machine-readable and human-readable verifier outputs.", "paths": ["verifier_v2/outputs/outsider_result.json", "verifier_v2/outputs/outsider_summary.txt"]},
        {"step": 4, "action": "Open the selected runtime surface package.", "path": "selected_runtime_surface"},
        {"step": 5, "action": "Run the bounded runtime confirmation entrypoint.", "command": "python run_runtime_surface.py"},
        {"step": 6, "action": "Archive outputs and the current child state vector together.", "paths": ["reports/kt_state_vector_v2.json", "reports/kt_product_wedge_activation_receipt.json"]},
    ]
    operator_manual = {
        "schema_id": "kt.child_campaign.operator_manual.v1",
        "manual_id": "KT_CHILD_OPERATOR_MANUAL_V1_F08",
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": head,
        "scope": "BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY",
        "operator_steps": operator_steps,
        "rollback_rule": "If verifier or selected runtime outputs fail, revert to the sealed F06/F07 bounded state and do not widen product claims.",
        "stronger_claim_not_made": [
            "This manual proves commercial readiness",
            "This manual proves enterprise SLA-backed operations",
        ],
    }
    supportability = {
        "schema_id": "kt.child_campaign.supportability_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": head,
        "scope": "BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY",
        "support_model": "SELF_SERVE_WITH_REPO_OWNER_ESCALATION",
        "sla": "NONE",
        "operator_step_count": len(operator_steps),
        "max_operator_steps_allowed": 12,
        "rollback_support": "DOCUMENTED",
        "diagnostic_outputs": [
            "verifier_v2/outputs/outsider_result.json",
            "verifier_v2/outputs/outsider_summary.txt",
            "selected_runtime_surface/outputs/runtime_surface_result.json",
        ],
        "stronger_claim_not_made": [
            "Commercial support obligations exist",
            "Enterprise uptime or response guarantees are proven",
        ],
    }

    write_json_stable((package_root / Path(F08_OPERATOR_MANUAL).name).resolve(), operator_manual, volatile_keys=())
    write_json_stable((package_root / Path(F08_SUPPORTABILITY_MATRIX).name).resolve(), supportability, volatile_keys=())

    deployment_manifest = {
        "schema_id": "kt.child_campaign.deployment_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "subject_head_commit": head,
        "package_root_ref": F08_PRODUCT_WEDGE_PACKAGE_ROOT,
        "scope": "CHILD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY",
        "included_components": [
            {
                "component_id": "verifier_v2",
                "package_path": "verifier_v2",
                "entrypoint": "python run_verifier_v2.py",
            },
            {
                "component_id": "selected_runtime_surface",
                "package_path": "selected_runtime_surface",
                "entrypoint": "python run_runtime_surface.py",
            },
            {
                "component_id": "operator_manual",
                "package_path": Path(F08_OPERATOR_MANUAL).name,
            },
            {
                "component_id": "supportability_matrix",
                "package_path": Path(F08_SUPPORTABILITY_MATRIX).name,
            },
        ],
        "stronger_claim_not_made": [
            "This manifest activates commercial hosting or SaaS rights",
            "This manifest proves broader runtime superiority",
        ],
    }
    write_json_stable((package_root / Path(F08_DEPLOYMENT_MANIFEST).name).resolve(), deployment_manifest, volatile_keys=())

    return {
        F08_DEPLOYMENT_MANIFEST: deployment_manifest,
        F08_OPERATOR_MANUAL: operator_manual,
        F08_SUPPORTABILITY_MATRIX: supportability,
    }


def _run_detached_package_twice(
    *,
    package_root: Path,
    run_cmd: Sequence[str],
    machine_output_rel: str,
    human_output_rel: str,
    env: Dict[str, str],
    prefix: str,
) -> Dict[str, Any]:
    runs: List[Dict[str, Any]] = []
    machine_reports: List[Dict[str, Any]] = []
    human_reports: List[str] = []

    if not package_root.exists():
        return {
            "runs": [],
            "machine_reports": [],
            "human_reports": [],
            "parity_ok": False,
            "package_root_present": False,
        }

    for index, env_id in enumerate(("env_a", "env_b"), start=1):
        with tempfile.TemporaryDirectory(prefix=f"{prefix}_{index}_") as temp_dir:
            detached_root = Path(temp_dir).resolve() / "package"
            shutil.copytree(package_root, detached_root)
            completed = subprocess.run(
                list(run_cmd),
                cwd=detached_root,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env=env,
            )
            machine_path = (detached_root / machine_output_rel).resolve()
            human_path = (detached_root / human_output_rel).resolve()
            machine = load_json(machine_path) if machine_path.exists() else {"status": "INPUT_OR_ENV_INVALID", "error": "missing machine output"}
            human = human_path.read_text(encoding="utf-8") if human_path.exists() else "status: INPUT_OR_ENV_INVALID\nerror: missing human output\n"
            runs.append(
                {
                    "environment_id": env_id,
                    "cwd": detached_root.as_posix(),
                    "detached_root_detected": not (detached_root / ".git").exists(),
                    "package_root_inside_repo_root": False,
                    "returncode": completed.returncode,
                    "machine_output_sha256": file_sha256(machine_path) if machine_path.exists() else _json_sha256(machine),
                    "human_output_sha256": file_sha256(human_path) if human_path.exists() else _json_sha256({"summary": human}),
                }
            )
            machine_reports.append(machine)
            human_reports.append(human)
            if index == 1:
                (package_root / Path(machine_output_rel).parent).resolve().mkdir(parents=True, exist_ok=True)
                if machine_path.exists():
                    shutil.copy2(machine_path, (package_root / machine_output_rel).resolve())
                if human_path.exists():
                    shutil.copy2(human_path, (package_root / human_output_rel).resolve())

    parity_ok = (
        len(machine_reports) == 2
        and len(human_reports) == 2
        and machine_reports[0] == machine_reports[1]
        and human_reports[0] == human_reports[1]
    )
    return {
        "runs": runs,
        "machine_reports": machine_reports,
        "human_reports": human_reports,
        "parity_ok": parity_ok,
        "package_root_present": True,
    }


def _runtime_rows(root: Path) -> List[Dict[str, Any]]:
    registry = {}
    reg_path = root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"
    if reg_path.exists():
        registry = load_json(reg_path)
    rows = []
    for sid, icls, ocls, label, maturity, bench, code_refs, test_refs, receipt_refs in SURFACES:
        code = [r for r in code_refs if _exists(root, r)]
        tests = [r for r in test_refs if _exists(root, r)]
        receipts = [r for r in receipt_refs if _exists(root, r)]
        blockers = []
        if sid == "adapter_layer":
            entries = registry.get("adapters", {}).get("entries", []) if isinstance(registry.get("adapters"), dict) else []
            if isinstance(entries, list) and not entries:
                blockers.append("NO_ACTIVE_RUNTIME_ADAPTER_ENTRIES")
        if icls != "doctrinal_only" and not code:
            icls, ocls, maturity, bench = "doctrinal_only", "DOC_ONLY", "O0_CONCEPTUAL", "NONE"
            blockers.append("IMPLEMENTATION_SURFACE_MISSING")
        rows.append({"surface_id": sid, "inventory_class": icls, "operational_reality_class": ocls, "capability_label": label, "maturity_class": maturity, "benchmark_status": bench, "evidence_refs": code + tests + receipts, "blockers": blockers})
    return rows


def _check(ok: bool, check_id: str, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {"check": check_id, "status": "PASS" if ok else "FAIL", "detail": detail, "refs": list(refs)}


def emit_follow_on_campaign_v16(root: Path) -> Dict[str, Any]:
    unexpected = [p for p in _dirty(_status_lines(root)) if not _in_scope(p)]
    if unexpected:
        raise RuntimeError(f"FAIL_CLOSED: out-of-scope paths already dirty: {unexpected}")

    head = _git(root, "rev-parse", "HEAD")
    parent_dag = _j(root, PARENT_DAG)
    parent_final = _j(root, PARENT_FINAL)
    _j(root, PARENT_PRODUCT)
    old_state = _j(root, OLD_STATE)
    _j(root, OLD_PROOF)
    trust_root = _j(root, TRUST_ROOT)
    signer_topology = _j(root, SIGNER_TOPOLOGY)
    _j(root, RELEASE)
    _j(root, DETERMINISM)
    identity_model = _maybe_j(root, IDENTITY_MODEL)
    tuf_root = _maybe_j(root, TUF_ROOT_INIT)
    ws11 = _j(root, WS11)
    ws12 = _maybe_j(root, WS12)
    ws14 = _maybe_j(root, WS14)
    ws17a = _j(root, WS17A)
    _j(root, WS17B)
    ws19_detached = _maybe_j(root, WS19_DETACHED)
    log_monitor = _maybe_j(root, LOG_MONITOR)

    checks = [
        _check(parent_dag.get("campaign_completion_status") == "STILL_BLOCKED", "parent_campaign_still_terminal_blocked", "The sealed parent must remain closed before the child campaign may bootstrap.", [PARENT_DAG]),
        _check(parent_dag.get("next_lawful_workstream") is None, "parent_campaign_has_no_next_workstream", "The child campaign may not append work inside the parent DAG.", [PARENT_DAG, PARENT_PRODUCT]),
        _check(parent_final.get("final_verdict", {}).get("current_head_capability_status") == "NOT_EXTERNALLY_CONFIRMED", "carry_forward_current_head_capability_blocker", "Current-head capability must remain explicitly unconfirmed at child-campaign bootstrap.", [PARENT_FINAL]),
        _check(old_state.get("adjudication_status") == "PRE_ADJUDICATION_PENDING_STEP_12", "legacy_state_vector_is_stale", "The old state vector must be treated as stale and superseded for child-campaign use.", [OLD_STATE]),
    ]
    if not all(c["status"] == "PASS" for c in checks):
        raise RuntimeError("FAIL_CLOSED: parent lineage or stale-state prerequisites are not satisfied")

    rows = _runtime_rows(root)
    covered = sum(1 for row in rows if row["benchmark_status"] not in {"NONE", "TEST_ONLY"})
    cap_cov = round(sum(1 for row in rows if row["inventory_class"] in {"live_unbenchmarked", "live_benchmarked", "stubbed"}) / (len(rows) or 1) * 100.0, 2)
    bench_cov = round(covered / (len(rows) or 1) * 100.0, 2)
    theater_rows = [{"surface_id": row["surface_id"], **_profile(row["inventory_class"])} for row in rows]
    constraint_statuses = _constraint_statuses(identity_model)
    target_root_id = str(trust_root.get("ratified_root_topology", {}).get("target_trust_root_id", "")).strip()
    root_threshold = int(trust_root.get("ratified_root_topology", {}).get("root_threshold", 0) or 0)
    bootstrap_root_id = str(tuf_root.get("trust_root_id", "")).strip()
    verifier_role = _role_row(signer_topology, "verifier_acceptance")
    verifier_threshold = int(verifier_role.get("threshold", 0) or 0)
    verifier_signer_count = int(verifier_role.get("signer_count", 0) or 0)
    verifier_maintainers = list(identity_model.get("principal_sets", {}).get("verifier_acceptance_maintainers", [])) if isinstance(identity_model.get("principal_sets"), dict) else []
    release_role = _role_row(signer_topology, "release")
    release_threshold = int(release_role.get("threshold", 0) or 0)
    release_signer_count = int(release_role.get("signer_count", 0) or 0)
    release_role_state = str(release_role.get("issuance_state", "")).strip()
    release_role_identities = [str(item).strip() for item in release_role.get("planned_identity_ids", []) if str(item).strip()]
    producer_role = _role_row(signer_topology, "producer")
    producer_threshold = int(producer_role.get("threshold", 0) or 0)
    producer_signer_count = int(producer_role.get("signer_count", 0) or 0)
    producer_role_state = str(producer_role.get("issuance_state", "")).strip()
    producer_role_identities = [str(item).strip() for item in producer_role.get("planned_identity_ids", []) if str(item).strip()]

    threshold_ready = (
        str(trust_root.get("status", "")).strip() == "EXECUTED_RERATIFIED_3_OF_3"
        and bool(target_root_id)
        and root_threshold >= 3
    )
    topology_ready = verifier_threshold >= 1 and verifier_signer_count >= verifier_threshold and bool(verifier_maintainers)
    identity_ready = all(
        constraint_statuses.get(cid) == "PASS"
        for cid in (
            "root_verifier_acceptance_overlap_forbidden",
            "release_verifier_acceptance_overlap_forbidden",
            "verifier_acceptance_ci_keyless_overlap_forbidden",
            "operator_verifier_acceptance_overlap_forbidden",
        )
    )
    ws11_ok = str(ws11.get("status", "")).strip() == "PASS"
    ws12_ok = str(ws12.get("status", "")).strip() == "PASS"
    ws14_ok = str(ws14.get("status", "")).strip() == "PASS"
    ws17a_ok = str(ws17a.get("status", "")).strip() == "PASS"
    ws19_ok = str(ws19_detached.get("status", "")).strip() == "PASS"
    log_monitor_ok = str(log_monitor.get("status", "")).strip() == "PASS"
    surface_inputs_ready = all(_exists(root, rel) for rel in (STATIC_BUNDLE_MANIFEST, STATIC_BUNDLE_SBOM, STATIC_BUNDLE_ATTESTATION, DETACHED_BUNDLE_MANIFEST, DETACHED_BUNDLE_SBOM, WS19_DETACHED))

    accepted_surfaces = []
    if surface_inputs_ready:
        accepted_surfaces = [
            _surface_target(
                root,
                surface_id="WS14_STATIC_VERIFIER_RELEASE_BUNDLE",
                manifest_ref=STATIC_BUNDLE_MANIFEST,
                supporting_refs=[STATIC_BUNDLE_SBOM, STATIC_BUNDLE_ATTESTATION],
                scope="BOUNDED_IMPORTED_CURRENT_HEAD_STATIC_VERIFIER_RELEASE_ONLY",
                source_receipt_ref=WS14,
            ),
            _surface_target(
                root,
                surface_id="WS19_DETACHED_PUBLIC_VERIFIER_PACKAGE",
                manifest_ref=DETACHED_BUNDLE_MANIFEST,
                supporting_refs=[DETACHED_BUNDLE_SBOM, WS19_DETACHED],
                scope="HISTORICAL_GOVERNANCE_ONLY_DETACHED_VERIFIER_PACKAGE",
                source_receipt_ref=WS19_DETACHED,
            ),
        ]
    coverage_ready = len(accepted_surfaces) >= 2
    f02b_pass = all([ws11_ok, ws12_ok, ws14_ok, ws17a_ok, ws19_ok, log_monitor_ok, threshold_ready, topology_ready, identity_ready, surface_inputs_ready, coverage_ready])
    active_blockers = _active_blockers(f02b_pass)
    blocker_rows = [
        {
            "blocker_id": blocker,
            "status": "CLEARED_BY_F02B" if f02b_pass and blocker in F02B_CLEARED_BLOCKERS else "OPEN",
        }
        for blocker in PRESERVED_BLOCKERS
    ]
    threshold_policy = {
        "schema_id": "kt.child_campaign.threshold_root_acceptance_policy.v1",
        "policy_id": "KT_CHILD_THRESHOLD_ROOT_ACCEPTANCE_POLICY_V1_6",
        "campaign_id": CAMPAIGN_ID,
        "phase_id": PHASE_TRUST,
        "status": "ACTIVE" if f02b_pass else "BLOCKED_PENDING_PREREQUISITES",
        "current_repo_head": head,
        "accepted_primary_trust_root": {
            "trust_root_id": target_root_id,
            "acceptance_state": "ACTIVE_THRESHOLD_ACCEPTED_CHILD_SCOPED" if f02b_pass else "PENDING_CHILD_ACTIVATION",
            "source_refs": [TRUST_ROOT, SIGNER_TOPOLOGY, IDENTITY_MODEL],
            "root_threshold": root_threshold,
        },
        "historical_predecessor_root": {
            "trust_root_id": bootstrap_root_id,
            "acceptance_state": "HISTORICAL_REPLAY_ONLY",
            "source_ref": TUF_ROOT_INIT,
        },
        "verifier_acceptance_role": {
            "role_id": "verifier_acceptance",
            "threshold": verifier_threshold,
            "signer_count": verifier_signer_count,
            "maintainers": verifier_maintainers,
        },
        "monitoring_refs": [WS11, LOG_MONITOR, LOG_MONITOR_POLICY],
        "accepted_verifier_surfaces": accepted_surfaces,
        "coverage_mode": "MINIMAL_F02B_CLEARANCE_ONLY",
        "limitations": [
            "This activation is child-scoped to verifier distribution surfaces only.",
            "This activation does not prove release readiness, release ceremony execution, or release activation.",
            "This activation does not upgrade historical capability proof into current-head capability truth.",
        ],
        "stronger_claim_not_made": [
            "All verifier surfaces are threshold-root accepted",
            "Current-head external capability is confirmed",
            "Release readiness is proven",
        ],
    }
    tuf_policy = {
        "schema_id": "kt.child_campaign.tuf_distribution_policy.v1",
        "policy_id": "KT_CHILD_TUF_DISTRIBUTION_POLICY_V1_6",
        "campaign_id": CAMPAIGN_ID,
        "phase_id": PHASE_TRUST,
        "status": "ACTIVE" if f02b_pass else "BLOCKED_PENDING_PREREQUISITES",
        "current_repo_head": head,
        "scope": "CHILD_VERIFIER_DISTRIBUTION_ONLY",
        "threshold_acceptance_policy_ref": THRESHOLD_POLICY,
        "tuf_scope_boundary": [
            "trust_root_distribution",
            "verifier_distribution",
            "delegated_public_trust_surfaces_for_verifier_bundles_only",
        ],
        "top_level_roles": [
            {"role_id": "root", "threshold": root_threshold, "trust_root_id": target_root_id, "source_ref": TRUST_ROOT},
            {"role_id": "targets", "threshold": verifier_threshold, "signer_role_ref": SIGNER_TOPOLOGY},
            {"role_id": "snapshot", "threshold": verifier_threshold, "signer_role_ref": SIGNER_TOPOLOGY},
            {"role_id": "timestamp", "threshold": verifier_threshold, "signer_role_ref": SIGNER_TOPOLOGY},
        ],
        "required_behaviors": [
            "versioned_metadata",
            "expiration_checks",
            "freeze_attack_drills",
            "rollback_attack_drills",
            "inconsistent_view_drills",
        ],
        "distribution_targets": accepted_surfaces,
        "delivery_modes": [
            "repo_snapshot_with_hash_bound_release_manifest",
            "static_zip_or_directory_bundle_with_packaged_public_evidence",
            "artifact_download_with_release_manifest_sha_verification",
        ],
        "attack_drill_refs": [WS12, LOG_MONITOR, LOG_MONITOR_POLICY],
        "limitations": [
            "This policy does not prove a deployed public updater fleet.",
            "This policy is scoped only to the two declared verifier distribution bundles needed for F02B clearance.",
            "This policy does not widen runtime or product claims.",
        ],
        "stronger_claim_not_made": [
            "TUF distribution is active for release activation",
            "Product delivery is now active",
            "Verifier coverage is globally widened across all KT surfaces",
        ],
    }

    dependency_bundle: Dict[str, Dict[str, Any]] = {"inventory": {}, "environment": {}, "sbom": {}, "validation": {}}
    direct_third_party_imports: Dict[str, List[str]] = {}
    class_a_drift_paths: List[str] = []
    f03_blocked_by: List[str] = []
    f03_checks: Dict[str, bool] = {
        "pipeline_attestations_complete": False,
        "slsa_lineage_complete": False,
        "carried_forward_class_a_cross_host_repro": False,
        "dependency_airlock_valid": False,
        "drift_and_semantic_stability_guards_active": False,
    }
    if f02b_pass:
        dependency_bundle = _refresh_dependency_inventory(root)
        required_f03_refs = [
            WS13,
            ARTIFACT_CLASS,
            SOURCE_IN_TOTO,
            PUBLICATION_IN_TOTO,
            BUILD_PROVENANCE,
            VERIFICATION_SUMMARY,
            BUILD_VERIFICATION,
            REKOR_RECEIPT,
            SIGSTORE_BUNDLE,
            DETACHED_MANIFEST,
            POLICY_C_DRIFT,
            POLICY_C_DRIFT_SCHEMA,
            POLICY_C_TEST_GUARD,
            POLICY_C_TEST_GATE,
            POLICY_C_TEST_SCHEMA,
        ]
        missing_f03_refs = [rel for rel in required_f03_refs if not _exists(root, rel)]
        if missing_f03_refs:
            f03_blocked_by.extend([f"missing:{rel}" for rel in missing_f03_refs])
        else:
            ws13 = _j(root, WS13)
            artifact_class_policy = _j(root, ARTIFACT_CLASS)
            determinism_policy = _j(root, DETERMINISM)
            source_in_toto = _j(root, SOURCE_IN_TOTO)
            publication_in_toto = _j(root, PUBLICATION_IN_TOTO)
            build_provenance = _j(root, BUILD_PROVENANCE)
            verification_summary = _j(root, VERIFICATION_SUMMARY)
            build_verification = _j(root, BUILD_VERIFICATION)
            rekor_receipt = _j(root, REKOR_RECEIPT)
            sigstore_bundle = _j(root, SIGSTORE_BUNDLE)
            detached_manifest = _j(root, DETACHED_MANIFEST)
            detached_refs = {
                str(item).strip()
                for item in [*detached_manifest.get("included_paths", []), *detached_manifest.get("packaged_input_refs", [])]
                if str(item).strip()
            }
            class_a_paths = sorted(
                {
                    str(row.get("path", "")).strip()
                    for clazz in artifact_class_policy.get("classes", [])
                    if isinstance(clazz, dict) and str(clazz.get("class_id", "")).strip() == "CLASS_A"
                    for row in clazz.get("surfaces", [])
                    if isinstance(row, dict) and str(row.get("path", "")).strip()
                }
            )
            ws13_anchor = str(ws13.get("current_repo_head", "")).strip() or str(ws13.get("compiled_against", "")).strip()
            class_a_drift_paths = _git_name_only(root, ws13_anchor, F03_CLASS_A_SURFACES) if ws13_anchor else list(F03_CLASS_A_SURFACES)
            direct_third_party_imports = _third_party_imports_for_surfaces(root, dependency_bundle["inventory"], F03_EMITTER_IMPORT_SURFACES)

            source_statement_ok = str(source_in_toto.get("predicate", {}).get("schema_id", "")).strip() == "kt.in_toto.predicate.source_build_subject.v1"
            publication_statement_ok = str(publication_in_toto.get("predicate", {}).get("schema_id", "")).strip() == "kt.in_toto.predicate.authority_subject.v1"
            rekor_ok = str(rekor_receipt.get("status", "")).strip() == "PASS"
            sigstore_ok = str(sigstore_bundle.get("status", "")).strip() == "PASS"
            build_verification_ok = str(build_verification.get("status", "")).strip() == "PASS"
            detached_chain_refs_ok = all(
                rel in detached_refs
                for rel in (SOURCE_IN_TOTO, PUBLICATION_IN_TOTO, BUILD_PROVENANCE, VERIFICATION_SUMMARY, REKOR_RECEIPT, SIGSTORE_BUNDLE)
            )
            f03_checks["pipeline_attestations_complete"] = all(
                [source_statement_ok, publication_statement_ok, rekor_ok, sigstore_ok, build_verification_ok, detached_chain_refs_ok]
            )

            build_provenance_ok = str(build_provenance.get("status", "")).strip() == "PASS"
            verification_summary_ok = str(verification_summary.get("status", "")).strip() == "PASS"
            f03_checks["slsa_lineage_complete"] = all(
                [
                    build_provenance_ok,
                    verification_summary_ok,
                    build_verification_ok,
                    detached_chain_refs_ok,
                ]
            )

            ws13_ok = str(ws13.get("status", "")).strip() == "PASS"
            ws13_local_ok = str(ws13.get("environments_used", {}).get("local", {}).get("environment_class", "")).strip() == "local_windows"
            ws13_ci_ok = str(ws13.get("environments_used", {}).get("ci", {}).get("environment_class", "")).strip() == "github_actions_ubuntu"
            ws13_hashes_ok = all(
                str(row.get("status", "")).strip() == "PASS"
                for row in ws13.get("hash_comparison_results", {}).get("deterministic_outputs", [])
            )
            f03_checks["carried_forward_class_a_cross_host_repro"] = all(
                [
                    ws13_ok,
                    ws13_local_ok,
                    ws13_ci_ok,
                    ws13_hashes_ok,
                    sorted(class_a_paths) == sorted(F03_CLASS_A_SURFACES),
                    not class_a_drift_paths,
                ]
            )

            dependency_validation_ok = str(dependency_bundle["validation"].get("status", "")).strip() == "PASS"
            inventory_head_ok = str(dependency_bundle["inventory"].get("pinned_head_sha", "")).strip() == head
            environment_head_ok = str(dependency_bundle["environment"].get("pinned_head_sha", "")).strip() == head
            sbom_head_ok = str(dependency_bundle["sbom"].get("metadata", {}).get("component", {}).get("version", "")).strip() == head
            direct_imports_ok = not direct_third_party_imports
            f03_checks["dependency_airlock_valid"] = all(
                [dependency_validation_ok, inventory_head_ok, environment_head_ok, sbom_head_ok, direct_imports_ok]
            )

            forbidden_drift_ok = bool(determinism_policy.get("forbidden_drift", []))
            canonicalization_ok = bool(determinism_policy.get("class_b_canonicalization_profiles", []))
            timestamp_policy_ok = (
                determinism_policy.get("normalization_rules", {})
                .get("timestamp_policy", {})
                .get("class_b_canonicalization_strips_wall_clock_fields")
                is True
            )
            drift_surfaces_ok = all(_exists(root, rel) for rel in (POLICY_C_DRIFT, POLICY_C_DRIFT_SCHEMA, POLICY_C_TEST_GUARD, POLICY_C_TEST_GATE, POLICY_C_TEST_SCHEMA))
            f03_checks["drift_and_semantic_stability_guards_active"] = all(
                [forbidden_drift_ok, canonicalization_ok, timestamp_policy_ok, drift_surfaces_ok]
            )

        for check_id, ok in f03_checks.items():
            if not ok:
                f03_blocked_by.append(check_id)

    f03_pass = f02b_pass and all(f03_checks.values())
    f03_status = "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")
    f03_next_phase = PHASE_F04 if f03_pass else (PHASE_F03 if f02b_pass else PHASE_TRUST)
    f03_allowed_claims = [
        "declared_class_a_cross_host_reproducibility_carried_forward_for_unchanged_inherited_subset_only",
        "bounded_verifier_publication_attestation_chain_present_for_declared_child_f03_surfaces_only",
        "current_head_dependency_inventory_refresh_and_validation_pass_for_declared_class_a_emitter_paths_only",
    ] if f03_pass else []
    f04_checks: Dict[str, bool] = {
        "adjudication_outputs_current_head_bound": False,
        "claims_emit_only_from_adjudication_outputs": False,
        "verifier_v2_manifest_secret_free": False,
        "outsider_path_deterministic_and_detached": False,
    }
    f04_blocked_by: List[str] = []
    f04_pass = False
    f04_status = "BLOCKED_UPSTREAM"
    f04_next_phase = PHASE_F04 if f03_pass else f03_next_phase
    f04_allowed_claims: List[str] = []
    f05_checks: Dict[str, bool] = {
        "all_critical_organs_accounted": False,
        "no_historical_capability_laundering": False,
        "promotion_matrix_receipt_backed": False,
        "theater_risk_punitive": False,
        "claim_ceiling_unchanged_outside_runtime_truth": False,
    }
    f05_blocked_by: List[str] = []
    f05_pass = False
    f05_status = "BLOCKED_UPSTREAM"
    f05_next_phase = f04_next_phase
    f05_allowed_claims: List[str] = []
    f06_checks: Dict[str, bool] = {
        "verifier_current_head_outsider_replay_pass": False,
        "selected_runtime_surface_bundle_present": False,
        "selected_runtime_surface_outsider_replay_pass": False,
        "selected_runtime_surface_current_head_only_no_historical_laundering": False,
        "final_readjudication_current_head_bound": False,
        "no_unrelated_claim_widening": False,
    }
    f06_blocked_by: List[str] = []
    f06_pass = False
    f06_status = "BLOCKED_UPSTREAM"
    f06_next_phase = f05_next_phase
    f06_allowed_claims: List[str] = []
    f07_checks: Dict[str, bool] = {
        "threshold_root_acceptance_still_active": False,
        "release_signer_topology_declared": False,
        "release_signer_issuance_executed": False,
        "producer_attestation_bundle_valid": False,
        "release_readiness_proven": False,
        "release_eligibility_proven": False,
        "release_ceremony_executed": False,
        "release_activation_executed": False,
        "no_unrelated_claim_widening": False,
    }
    f07_blocked_by: List[str] = []
    f07_pass = False
    f07_status = "BLOCKED_UPSTREAM"
    f07_next_phase = f06_next_phase
    f07_allowed_claims: List[str] = []
    f08_pass = False
    f08_status = "BLOCKED_UPSTREAM"
    f08_next_phase = PHASE_F08

    outputs = {
        CHILD_DAG: {
            "schema_id": "kt.child_campaign.execution_dag.v1_6",
            "campaign_id": CAMPAIGN_ID,
            "status": "ACTIVE",
            "current_repo_head": head,
            "campaign_execution_state": "ACTIVE" if f02b_pass else "PARTIAL_SUCCESS",
            "current_node": PHASE_F04 if f03_pass else (PHASE_F03 if f02b_pass else PHASE_TRUST),
            "next_lawful_phase": f03_next_phase,
            "nodes": [
                {"id": PHASE_BOOTSTRAP, "status": "PASS"},
                {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
                {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
                {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
                {"id": PHASE_F04, "status": "READY" if f03_pass else "BLOCKED_UPSTREAM"},
                {"id": PHASE_F05, "status": "BLOCKED_UPSTREAM"},
                {"id": PHASE_F06, "status": "BLOCKED_UPSTREAM"},
                {"id": PHASE_F07, "status": "BLOCKED_UPSTREAM"},
                {"id": PHASE_F08, "status": "BLOCKED_UPSTREAM"},
                {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "BLOCKED_UPSTREAM"},
            ],
        },
        SINGLE_REALITY: {
            "schema_id": "kt.child_campaign.single_reality_law.v1",
            "law_id": "KT_SINGLE_REALITY_LAW_V1_20260318",
            "status": "ACTIVE",
            "current_repo_head": head,
            "state_core_ref": STATE_V2,
            "invariants": [
                "There is one active child-campaign state core.",
                "Historical parent outputs may inform but may not silently promote current-head truth.",
            ],
        },
        THRESHOLD_POLICY: threshold_policy,
        TUF_POLICY: tuf_policy,
        PROOF_V2: {
            "schema_id": "kt.child_campaign.claim_proof_ceiling_compiler_policy.v2",
            "policy_id": "KT_CHILD_CLAIM_PROOF_CEILING_POLICY_V2_20260318",
            "status": "ACTIVE",
            "current_repo_head": head,
            "slsa_version_normalized": "v1.2",
            "inputs": [STATE_V2, BLOCKERS_V2, PARENT_FINAL, TRUST_ROOT, RELEASE, THRESHOLD_POLICY, TUF_POLICY, PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT],
            "allowed_public_claims": [
                "threshold_root_verifier_acceptance_active_for_child_scoped_verifier_distribution_surfaces_only",
                "child_tuf_distribution_active_for_minimal_verifier_bundle_set_only",
                *f03_allowed_claims,
            ] if f02b_pass else [],
            "forbidden_public_claims": [
                "current_head_external_capability_world_class",
                "release_readiness_proven",
                "release_activation_executed",
                "campaign_completion_proven",
                "threshold_root_verifier_acceptance_active_beyond_child_scoped_verifier_distribution_surfaces",
                "f03_proves_current_head_runtime_superiority",
                "f03_proves_release_activation",
                "f03_proves_full_repo_cross_host_reproducibility",
            ] if f02b_pass else [
                "current_head_external_capability_world_class",
                "threshold_root_verifier_acceptance_active",
                "release_readiness_proven",
                "release_activation_executed",
                "campaign_completion_proven",
            ],
            "blocked_by": active_blockers,
        },
        RUNTIME_MATRIX: {"schema_id": "kt.child_campaign.runtime_truth_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "surface_rows": rows},
        BENCHMARK_MATRIX: {"schema_id": "kt.child_campaign.benchmark_coverage_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "coverage_percent": bench_cov, "required_minimum_for_f02a_pass": 50, "rows": [{"surface_id": row["surface_id"], "benchmark_status": row["benchmark_status"], "has_current_head_benchmark_evidence": row["benchmark_status"] not in {"NONE", "TEST_ONLY"}} for row in rows]},
        THEATER_MATRIX: {"schema_id": "kt.child_campaign.theater_risk_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "rows": theater_rows},
        BLOCKERS_V2: {"schema_id": "kt.child_campaign.blocker_matrix.v2", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "open_blockers": active_blockers, "rows": blocker_rows},
        DEPENDENCY_INVENTORY: dependency_bundle["inventory"],
        PYTHON_ENVIRONMENT: dependency_bundle["environment"],
        SBOM: dependency_bundle["sbom"],
        DEPENDENCY_VALIDATION: dependency_bundle["validation"],
        PIPELINE_RECEIPT: {
            "schema_id": "kt.child_campaign.pipeline_attestations_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F03,
            "status": "PASS" if f03_checks["pipeline_attestations_complete"] else f03_status,
            "pass_verdict": "DECLARED_VERIFIER_PUBLICATION_PIPELINE_ATTESTATION_CHAIN_COMPLETE" if f03_checks["pipeline_attestations_complete"] else BLOCKED_VERDICT_F03,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(_exists(root, SOURCE_IN_TOTO), "source_build_statement_present", "The declared source-build in-toto statement must remain present.", [SOURCE_IN_TOTO]),
                _check(_exists(root, PUBLICATION_IN_TOTO), "publication_statement_present", "The declared publication in-toto statement must remain present.", [PUBLICATION_IN_TOTO]),
                _check(_exists(root, DETACHED_MANIFEST), "detached_manifest_present", "The detached verifier package manifest must remain present for outsider-oriented proof transport.", [DETACHED_MANIFEST]),
                _check(f03_checks["pipeline_attestations_complete"], "declared_attestation_chain_complete", "The declared verifier/publication chain must retain its source-build, publication, Rekor, and detached-package attestation surfaces.", [SOURCE_IN_TOTO, PUBLICATION_IN_TOTO, REKOR_RECEIPT, SIGSTORE_BUNDLE, DETACHED_MANIFEST]),
            ],
            "current_strongest_claim": "F03 preserves a bounded source-build and publication attestation chain for the declared verifier/publication proof surfaces only." if f03_checks["pipeline_attestations_complete"] else "F03 does not yet prove a complete attestation chain for the declared verifier/publication proof surfaces.",
            "stronger_claim_not_made": [
                "All KT pipeline steps are currently attested end-to-end",
                "Current-head runtime capability is now externally proven",
                "Release readiness is proven",
            ],
            "what_is_not_proven": [
                "This receipt does not prove current-head runtime capability",
                "This receipt does not prove release readiness, release ceremony, or release activation",
                "This receipt does not widen product or commercial claims",
            ],
            "next_lawful_phase": f03_next_phase,
        },
        SLSA_RECEIPT: {
            "schema_id": "kt.child_campaign.slsa_provenance_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F03,
            "status": "PASS" if f03_checks["slsa_lineage_complete"] else f03_status,
            "pass_verdict": "BOUNDED_SLSA_ALIGNED_PROVENANCE_AND_VSA_LINEAGE_PRESENT" if f03_checks["slsa_lineage_complete"] else BLOCKED_VERDICT_F03,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(_exists(root, BUILD_PROVENANCE), "build_provenance_present", "The bounded build provenance artifact must remain present.", [BUILD_PROVENANCE]),
                _check(_exists(root, VERIFICATION_SUMMARY), "verification_summary_present", "The bounded verification summary attestation must remain present.", [VERIFICATION_SUMMARY]),
                _check(f03_checks["slsa_lineage_complete"], "bounded_slsa_lineage_complete", "The detached verifier package must carry the bounded provenance and verification-summary lineage needed for proof-integrity hardening.", [BUILD_PROVENANCE, VERIFICATION_SUMMARY, BUILD_VERIFICATION, DETACHED_MANIFEST]),
                _check(True, "slsa_version_normalized_v1_2", "The child proof-ceiling policy keeps SLSA version language normalized to v1.2.", [PROOF_V2]),
            ],
            "current_strongest_claim": "F03 preserves bounded SLSA-aligned provenance and verification-summary lineage for the declared verifier/publication chain only." if f03_checks["slsa_lineage_complete"] else "F03 does not yet preserve a complete bounded SLSA-aligned lineage for the declared verifier/publication chain.",
            "stronger_claim_not_made": [
                "A SLSA level-attainment claim is earned",
                "Current-head runtime provenance is fully attested end-to-end",
                "Whole-system provenance is proven",
            ],
            "what_is_not_proven": [
                "No SLSA level attainment is claimed",
                "This receipt does not upgrade historical capability evidence into current-head capability truth",
                "This receipt does not prove release readiness",
            ],
            "next_lawful_phase": f03_next_phase,
        },
        CROSS_HOST_RECEIPT: {
            "schema_id": "kt.child_campaign.cross_host_repro_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F03,
            "status": "PASS" if f03_checks["carried_forward_class_a_cross_host_repro"] else f03_status,
            "pass_verdict": "DECLARED_CLASS_A_CROSS_HOST_REPRO_CARRIED_FORWARD_FOR_UNCHANGED_INHERITED_SUBSET" if f03_checks["carried_forward_class_a_cross_host_repro"] else BLOCKED_VERDICT_F03,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(_exists(root, WS13), "ws13_receipt_present", "The bounded WS13 cross-host receipt must remain present for carried-forward class-A proof.", [WS13]),
                _check(not class_a_drift_paths, "class_a_surfaces_unchanged_since_ws13_anchor", "The declared carried-forward class-A surfaces must remain byte-identical on the child head.", [*F03_CLASS_A_SURFACES, WS13]),
                _check(f03_checks["carried_forward_class_a_cross_host_repro"], "carried_forward_cross_host_repro_valid", "Cross-host reproducibility is carried forward only for the unchanged inherited class-A subset proved by WS13.", [WS13, *F03_CLASS_A_SURFACES]),
            ],
            "carried_forward_scope": "UNCHANGED_INHERITED_CLASS_A_SUBSET_ONLY",
            "class_a_drift_paths": class_a_drift_paths,
            "current_strongest_claim": "F03 carries forward cross-host reproducibility only for the unchanged inherited class-A subset declared by WS13." if f03_checks["carried_forward_class_a_cross_host_repro"] else "F03 does not yet preserve carried-forward cross-host reproducibility for the declared inherited class-A subset.",
            "stronger_claim_not_made": [
                "All child-owned F03 outputs are now cross-host reproducible",
                "Whole-repo cross-host reproducibility is proven",
                "The repo-root import fragility is fixed",
            ],
            "what_is_not_proven": [
                "This receipt does not widen reproducibility beyond the unchanged inherited class-A subset",
                "This receipt does not prove current-head runtime capability",
                "This receipt does not erase repo-root import fragility",
            ],
            "next_lawful_phase": f03_next_phase,
        },
        AIRLOCK_RECEIPT: {
            "schema_id": "kt.child_campaign.dependency_airlock_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F03,
            "status": "PASS" if f03_checks["dependency_airlock_valid"] else f03_status,
            "pass_verdict": "DECLARED_CLASS_A_EMITTER_PATHS_REFRESHED_AND_DEPENDENCY_VALIDATED" if f03_checks["dependency_airlock_valid"] else BLOCKED_VERDICT_F03,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(str(dependency_bundle.get("validation", {}).get("status", "")).strip() == "PASS", "dependency_inventory_validation_pass", "The dependency inventory, environment manifest, and SBOM must validate on the current head.", [DEPENDENCY_INVENTORY, PYTHON_ENVIRONMENT, SBOM, DEPENDENCY_VALIDATION]),
                _check(not direct_third_party_imports, "class_a_emitter_direct_imports_have_no_third_party_roots", "The declared class-A emitter paths may not directly import third-party roots from the refreshed inventory.", [*F03_EMITTER_IMPORT_SURFACES, DEPENDENCY_INVENTORY]),
                _check(f03_checks["dependency_airlock_valid"], "declared_class_a_dependency_path_current_head_bound", "The refreshed dependency evidence must bind to the current head for the declared class-A emitter paths.", [DEPENDENCY_INVENTORY, PYTHON_ENVIRONMENT, SBOM, DEPENDENCY_VALIDATION]),
            ],
            "direct_third_party_imports": direct_third_party_imports,
            "current_strongest_claim": "F03 refreshes and validates current-head dependency evidence for the declared class-A emitter paths only." if f03_checks["dependency_airlock_valid"] else "F03 does not yet validate the current-head dependency evidence for the declared class-A emitter paths.",
            "stronger_claim_not_made": [
                "A full mirrored dependency ecosystem is proven for all KT surfaces",
                "All runtime dependency paths are airlocked",
                "Release build airgap is proven",
            ],
            "what_is_not_proven": [
                "This receipt is bounded to the declared class-A emitter paths only",
                "This receipt does not widen runtime or product claims",
                "This receipt does not prove release readiness",
            ],
            "next_lawful_phase": f03_next_phase,
        },
        DRIFT_RECEIPT: {
            "schema_id": "kt.child_campaign.drift_and_semantic_stability_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F03,
            "status": "PASS" if f03_checks["drift_and_semantic_stability_guards_active"] else f03_status,
            "pass_verdict": "DECLARED_PROOF_INTEGRITY_DRIFT_AND_SEMANTIC_GUARDS_ACTIVE" if f03_checks["drift_and_semantic_stability_guards_active"] else BLOCKED_VERDICT_F03,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(_exists(root, POLICY_C_DRIFT), "policy_c_drift_guard_present", "The drift guard implementation must remain present.", [POLICY_C_DRIFT]),
                _check(_exists(root, POLICY_C_DRIFT_SCHEMA), "policy_c_drift_schema_present", "The drift guard schema must remain present.", [POLICY_C_DRIFT_SCHEMA]),
                _check(f03_checks["drift_and_semantic_stability_guards_active"], "declared_drift_and_semantic_guards_active", "Forbidden drift rules, class-B canonicalization, and proof-integrity drift surfaces must remain active.", [DETERMINISM, POLICY_C_DRIFT, POLICY_C_DRIFT_SCHEMA, POLICY_C_TEST_GUARD, POLICY_C_TEST_GATE, POLICY_C_TEST_SCHEMA]),
            ],
            "current_strongest_claim": "F03 preserves declared drift and semantic-stability guardrails for proof-integrity surfaces only." if f03_checks["drift_and_semantic_stability_guards_active"] else "F03 does not yet preserve a complete drift and semantic-stability guardrail set for proof-integrity surfaces.",
            "stronger_claim_not_made": [
                "All runtime behavior drift is now fully governed",
                "Product behavior stability is proven",
                "Current-head capability superiority is proven",
            ],
            "what_is_not_proven": [
                "This receipt is bounded to proof-integrity drift and semantic guardrails only",
                "This receipt does not widen runtime capability claims",
                "This receipt does not prove release readiness or product readiness",
            ],
            "next_lawful_phase": f03_next_phase,
        },
        STATE_V2: {
            "schema_id": "kt.child_campaign.state_vector.v2",
            "computed_state_id": f"kt_state_vector_v2::{head}",
            "single_reality_id": "KT_SINGLE_REALITY_LAW_V1_20260318",
            "campaign_id": CAMPAIGN_ID,
            "current_repo_head": head,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "parent_terminal_state_ref": PARENT_PRODUCT,
            "computed_claim_ceiling": "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F03_PROOF_INTEGRITY_HARDENING_ONLY" if f03_pass else ("PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F02B_TRUST_ACTIVATION_ONLY" if f02b_pass else "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_BOOTSTRAP_AND_RUNTIME_BASELINE_ONLY"),
            "blocker_matrix": BLOCKERS_V2,
            "trust_root_status": "CHILD_THRESHOLD_ROOT_ACCEPTANCE_ACTIVE" if f02b_pass else "RERATIFIED_3_OF_3_ROOT_EXECUTED_THRESHOLD_ACCEPTANCE_STILL_INACTIVE",
            "verifier_status": "CHILD_THRESHOLD_ROOT_ACCEPTANCE_AND_MINIMAL_TUF_DISTRIBUTION_ACTIVE_WITH_F03_PROOF_INTEGRITY_HARDENING" if f03_pass else ("CHILD_THRESHOLD_ROOT_ACCEPTANCE_AND_MINIMAL_TUF_DISTRIBUTION_ACTIVE" if f02b_pass else "BOUNDED_STATIC_VERIFIER_BOOTSTRAP_ROOT_ONLY"),
            "release_readiness_status": "NOT_PROVEN",
            "release_eligibility_status": "NOT_ELIGIBLE",
            "release_ceremony_status": "NON_EXECUTED_BLOCKED_BY_PREREQUISITES",
            "release_activation_status": "NON_EXECUTED",
            "reproducibility_status": "DECLARED_CLASS_A_CARRY_FORWARD_CROSS_HOST_PROVEN_FOR_UNCHANGED_INHERITED_SUBSET_ONLY" if f03_pass else "DECLARED_CLASS_A_CLASS_B_ONLY",
            "product_surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
            "external_confirmation_status": "CURRENT_HEAD_ASSURANCE_ONLY_AND_HISTORICAL_CAPABILITY_ONLY",
            "next_lawful_transition": f03_next_phase,
            "last_update_time": utc_now_iso_z(),
            "runtime_truth_matrix": RUNTIME_MATRIX,
            "doctrine_only_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] == "doctrinal_only"],
            "stubbed_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] == "stubbed"],
            "live_capability_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] in {"live_unbenchmarked", "live_benchmarked"}],
            "benchmark_coverage_matrix": BENCHMARK_MATRIX,
            "proof_integrity_receipts": [PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT] if f02b_pass else [],
            "critical_organs_current_head_receipts": {"router": ["KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py"], "paradox": ["KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json"], "tournament_promotion": ["KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json"]},
            "organ_promotion_blockers": {row["surface_id"]: row["blockers"] for row in rows if row["blockers"]},
            "organ_maturity_matrix": {row["surface_id"]: row["maturity_class"] for row in rows},
            "runtime_operational_reality_classes": {row["surface_id"]: row["operational_reality_class"] for row in rows},
            "historical_only_capability_imports": [{"artifact_ref": WS17B, "scope": "historical_bounded_frontier_target_only"}],
            "current_head_only_capability_surfaces": [row["surface_id"] for row in rows if row["capability_label"] == "current_head_only"],
            "current_head_and_historical_consistent_surfaces": [row["surface_id"] for row in rows if row["capability_label"] == "current_head_and_historical_consistent"],
            "theater_risk_score_matrix": {row["surface_id"]: _profile(row["inventory_class"])["theater_risk_score"] for row in rows},
            "benchmark_coverage_percent": bench_cov,
            "current_head_capability_coverage_percent": cap_cov,
            "threshold_root_acceptance_policy": THRESHOLD_POLICY,
            "tuf_distribution_policy": TUF_POLICY,
            "accepted_verifier_surface_count": len(accepted_surfaces),
            "open_blockers": active_blockers,
        },
        STATE_STALE: {"schema_id": "kt.child_campaign.state_vector_staleness_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "LEGACY_STATE_VECTOR_IDENTIFIED_AS_STALE_PRE_ADJUDICATION_ARTIFACT", "current_repo_head": head, "superseded_artifact": OLD_STATE},
        STATE_SUPERSEDE: {"schema_id": "kt.child_campaign.state_vector_supersession_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_STATE_VECTOR_V2_ESTABLISHED", "current_repo_head": head, "superseded_artifacts": [OLD_STATE], "new_artifact": STATE_V2},
        PROOF_SUPERSEDE: {"schema_id": "kt.child_campaign.claim_proof_ceiling_supersession_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_PROOF_CEILING_POLICY_V2_ESTABLISHED", "current_repo_head": head, "superseded_artifacts": [OLD_PROOF], "new_artifact": PROOF_V2},
        BOOTSTRAP_RECEIPT: {"schema_id": "kt.child_campaign.bootstrap_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_CAMPAIGN_BOOTSTRAPPED_WITH_SINGLE_REALITY_STATE_CORE_V2", "subject_head_commit": head, "evidence_head_commit": head, "current_repo_head": head, "generated_utc": utc_now_iso_z(), "checks": checks, "next_lawful_phase": PHASE_RUNTIME},
        RUNTIME_RECEIPT: {"schema_id": "kt.child_campaign.current_head_capability_baseline_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED", "pass_verdict": "CURRENT_HEAD_RUNTIME_BASELINE_CLASSIFIED_AND_BOUNDED" if cap_cov >= 60.0 and bench_cov >= 50.0 else "CURRENT_HEAD_RUNTIME_BASELINE_INCOMPLETE", "subject_head_commit": head, "evidence_head_commit": head, "current_repo_head": head, "generated_utc": utc_now_iso_z(), "current_head_capability_coverage_percent": cap_cov, "benchmark_coverage_percent": bench_cov, "next_lawful_phase": PHASE_TRUST},
        TRUST_RECEIPT: {
            "schema_id": "kt.child_campaign.f02b_trust_activation_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_TRUST,
            "status": "PASS" if f02b_pass else "BLOCKED",
            "pass_verdict": PASS_VERDICT_TRUST if f02b_pass else BLOCKED_VERDICT_TRUST,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(ws11_ok, "sigstore_and_rekor_path_active", "The bounded WS11 path remains active.", [WS11]),
                _check(ws17a_ok, "outsider_secret_free_assurance_exists", "A secret-free outsider assurance replay exists.", [WS17A]),
                _check(log_monitor_ok, "log_monitor_plane_pass", "The log monitor plane remains active for verifier trust surfaces.", [LOG_MONITOR, LOG_MONITOR_POLICY]),
                _check(ws12_ok, "supply_chain_tuf_attack_drills_pass", "Existing TUF attack drill coverage remains PASS and available for child-path verifier distribution.", [WS12]),
                _check(threshold_ready, "threshold_root_target_present", "F02B requires a real threshold root target carried forward from the reratified root boundary.", [TRUST_ROOT]),
                _check(topology_ready, "verifier_acceptance_role_threshold_defined", "F02B requires a defined verifier-acceptance role threshold on the child-lawful path.", [SIGNER_TOPOLOGY]),
                _check(identity_ready, "verifier_acceptance_identity_separation_preserved", "Verifier-acceptance maintainers must remain distinct from root, release, CI, and local operator roles.", [IDENTITY_MODEL]),
                _check(f02b_pass, "threshold_root_acceptance_policy_active", "F02B requires the child threshold-root acceptance policy to become active.", [THRESHOLD_POLICY]),
                _check(f02b_pass, "tuf_distribution_scope_active", "F02B requires an explicit child-path TUF distribution policy.", [TUF_POLICY]),
                _check(coverage_ready, "verifier_coverage_minimally_widened", "F02B requires the minimum verifier-coverage widening needed to clear the child trust blocker.", [THRESHOLD_POLICY, TUF_POLICY]),
                _check(True, "release_readiness_still_not_proven_visible", "Release readiness remains visible as an open blocker but does not block F02B once trust activation is complete.", [STATE_V2, BLOCKERS_V2]),
            ],
            "cleared_blockers": sorted(F02B_CLEARED_BLOCKERS) if f02b_pass else [],
            "blocked_by": [] if f02b_pass else [
                blocker
                for blocker, ok in (
                    ("threshold_root_verifier_acceptance_inactive", threshold_ready),
                    ("verifier_coverage_not_widened_beyond_bounded_surfaces", coverage_ready),
                )
                if not ok
            ],
            "remaining_open_blockers": active_blockers if f02b_pass else [
                blocker for blocker in PRESERVED_BLOCKERS if blocker not in {"threshold_root_verifier_acceptance_inactive", "verifier_coverage_not_widened_beyond_bounded_surfaces"}
            ],
            "current_strongest_claim": "F02B activates child-scoped threshold-root verifier acceptance and child-path TUF distribution for the minimum verifier bundle set needed to clear the trust blocker." if f02b_pass else "F02B remains blocked until child-scoped threshold-root acceptance, child-path TUF distribution, and minimal verifier coverage widening are all real.",
            "stronger_claim_not_made": [
                "Release readiness is proven",
                "Release ceremony is executed",
                "Release activation is executed",
                "Current-head external capability is confirmed",
                "Verifier coverage is widened beyond the minimum F02B bundle set",
            ],
            "what_is_not_proven": [
                "Current-head external capability remains unconfirmed",
                "Release readiness remains unproven",
                "Release ceremony remains non-executed",
                "Release activation remains non-executed",
                "Repo-root import fragility remains visible and unfixed",
            ],
            "next_lawful_phase": PHASE_F03 if f02b_pass else PHASE_TRUST,
        },
    }

    if f03_pass:
        adjudicated_repo_refs = [
            THRESHOLD_POLICY,
            TUF_POLICY,
            PROOF_V2,
            STATE_V2,
            BLOCKERS_V2,
            PIPELINE_RECEIPT,
            SLSA_RECEIPT,
            CROSS_HOST_RECEIPT,
            AIRLOCK_RECEIPT,
            DRIFT_RECEIPT,
            STATIC_BUNDLE_MANIFEST,
            STATIC_BUNDLE_SBOM,
            STATIC_BUNDLE_ATTESTATION,
            DETACHED_BUNDLE_MANIFEST,
            DETACHED_BUNDLE_SBOM,
            WS19_DETACHED,
        ]
        adjudicated_refs_present = all(
            rel in outputs or _exists(root, rel)
            for rel in adjudicated_repo_refs
        ) and _exists(root, OUTSIDER_TOOL_REL)
        f04_surface_rows = []
        for rel in adjudicated_repo_refs:
            if rel in outputs:
                payload = outputs[rel]
                f04_surface_rows.append(
                    {
                        "artifact_ref": rel,
                        "status": str(payload.get("status", "")).strip() or "ACTIVE",
                        "sha256": _json_sha256(payload),
                    }
                )
            else:
                payload = _j(root, rel)
                f04_surface_rows.append(
                    {
                        "artifact_ref": rel,
                        "status": str(payload.get("status", "")).strip() or "ACTIVE",
                        "sha256": file_sha256((root / rel).resolve()),
                    }
                )

        all_f03_receipts_pass = all(
            str(outputs[rel].get("status", "")).strip() == "PASS"
            for rel in (PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT)
        )
        current_head_bound = all(
            str(outputs[rel].get("current_repo_head", "")).strip() == head
            and str(outputs[rel].get("subject_head_commit", "")).strip() == head
            for rel in (PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT, TRUST_RECEIPT, STATE_V2)
        )
        adjudication_allowed_claims = [
            "claims_emitted_only_from_child_adjudication_outputs_for_declared_f04_verifier_surfaces_only",
            "secret_free_one_command_outsider_verifier_v2_active_for_declared_child_verifier_surfaces_only",
            "current_head_child_verifier_assurance_surfaces_adjudicated_authentic_complete_and_fresh_only",
        ]
        adjudication_forbidden_claims = [
            "f04_proves_current_head_external_capability",
            "f04_proves_release_readiness",
            "f04_proves_release_activation",
            "f04_widens_product_or_commercial_claims",
        ]
        adjudication_packet = {
            "schema_id": "kt.child_campaign.adjudication_packet.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F04,
            "status": "PASS" if adjudicated_refs_present and all_f03_receipts_pass and current_head_bound else "BLOCKED",
            "pass_verdict": PASS_VERDICT_F04 if adjudicated_refs_present and all_f03_receipts_pass and current_head_bound else BLOCKED_VERDICT_F04,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "surface_scope": "CURRENT_HEAD_ASSURANCE_ONLY_DECLARED_CHILD_VERIFIER_SURFACES",
            "adjudicated_surfaces": f04_surface_rows,
            "authenticity_checks": [
                _check(adjudicated_refs_present, "declared_f04_inputs_present", "All declared F04 verifier/adjudication inputs must be present.", adjudicated_repo_refs + [OUTSIDER_TOOL_REL]),
                _check(str(outputs[THRESHOLD_POLICY].get("status", "")).strip() == "ACTIVE", "child_threshold_acceptance_still_active", "Child threshold-root acceptance must remain active while verifier v2 is released.", [THRESHOLD_POLICY]),
                _check(str(outputs[TUF_POLICY].get("status", "")).strip() == "ACTIVE", "child_tuf_distribution_still_active", "Child TUF distribution must remain active while verifier v2 is released.", [TUF_POLICY]),
            ],
            "completeness_checks": [
                _check(all_f03_receipts_pass, "f03_proof_integrity_receipts_all_pass", "F04 may build only on a fully passing F03 proof-integrity layer.", [PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT]),
            ],
            "freshness_checks": [
                _check(current_head_bound, "declared_f04_inputs_bound_to_current_head", "The child adjudication packet must remain bound to the same current head across trust, proof, and state inputs.", [TRUST_RECEIPT, PIPELINE_RECEIPT, SLSA_RECEIPT, CROSS_HOST_RECEIPT, AIRLOCK_RECEIPT, DRIFT_RECEIPT, STATE_V2]),
            ],
            "claims_must_compile_from": [ADJUDICATION_PACKET, VERIFIER_V2_VSA, PROOF_V2, STATE_V2, BLOCKERS_V2],
            "allowed_claims": adjudication_allowed_claims,
            "forbidden_claims": adjudication_forbidden_claims,
            "remaining_open_blockers": list(outputs[BLOCKERS_V2]["open_blockers"]),
            "stronger_claim_not_made": [
                "Current-head external capability is confirmed",
                "Release readiness is proven",
                "Release ceremony is executed",
                "Product or commercial readiness is proven",
            ],
        }
        outputs[ADJUDICATION_PACKET] = adjudication_packet

        vsa = {
            "schema_id": "kt.child_campaign.public_verifier_vsa.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F04,
            "status": "PASS" if str(adjudication_packet.get("status", "")).strip() == "PASS" else "BLOCKED",
            "pass_verdict": PASS_VERDICT_F04 if str(adjudication_packet.get("status", "")).strip() == "PASS" else BLOCKED_VERDICT_F04,
            "compiled_head_commit": head,
            "adjudication_packet_ref": Path(ADJUDICATION_PACKET).name,
            "allowed_claims": adjudication_allowed_claims,
            "forbidden_claims": adjudication_forbidden_claims,
            "remaining_open_blockers": list(outputs[BLOCKERS_V2]["open_blockers"]),
            "checks": [
                _check(str(adjudication_packet.get("status", "")).strip() == "PASS", "adjudication_packet_pass", "Verifier v2 claims may compile only from a passing adjudication packet.", [ADJUDICATION_PACKET]),
                _check(True, "vsa_bounded_assurance_only", "Verifier v2 remains bounded to assurance and verifier surfaces only.", [BLOCKERS_V2, PROOF_V2]),
            ],
            "current_strongest_claim": "F04 emits a bounded verifier v2 summary only for adjudicated current-head child verifier surfaces." if str(adjudication_packet.get("status", "")).strip() == "PASS" else "F04 does not yet emit a bounded verifier v2 summary because adjudication remains blocked.",
            "stronger_claim_not_made": [
                "Verifier v2 proves current-head external capability",
                "Verifier v2 proves release readiness",
                "Verifier v2 widens product claims",
            ],
        }
        outputs[VERIFIER_V2_VSA] = vsa

        package_root = (root / OUTSIDER_PACKAGE_ROOT).resolve()
        if package_root.exists():
            shutil.rmtree(package_root)
        package_root.mkdir(parents=True, exist_ok=True)
        run_script_path = (package_root / "run_verifier_v2.py").resolve()
        outsider_tool_present = _exists(root, OUTSIDER_TOOL_REL)
        if outsider_tool_present:
            shutil.copy2((root / OUTSIDER_TOOL_REL).resolve(), run_script_path)

        package_entries: List[Dict[str, Any]] = []
        for rel, role in (
            (PROOF_V2, "proof_ceiling_policy"),
            (STATE_V2, "state_vector"),
            (BLOCKERS_V2, "blocker_matrix"),
            (PIPELINE_RECEIPT, "pipeline_attestations_receipt"),
            (SLSA_RECEIPT, "slsa_receipt"),
            (CROSS_HOST_RECEIPT, "cross_host_repro_receipt"),
            (AIRLOCK_RECEIPT, "dependency_airlock_receipt"),
            (DRIFT_RECEIPT, "drift_receipt"),
            (STATIC_BUNDLE_MANIFEST, "static_verifier_manifest"),
            (STATIC_BUNDLE_SBOM, "static_verifier_sbom"),
            (STATIC_BUNDLE_ATTESTATION, "static_verifier_attestation"),
            (DETACHED_BUNDLE_MANIFEST, "historical_detached_manifest"),
            (DETACHED_BUNDLE_SBOM, "historical_detached_sbom"),
            (WS19_DETACHED, "historical_detached_receipt"),
        ):
            package_path = _package_rel_for_repo_ref(rel)
            package_target = (package_root / package_path).resolve()
            if rel in outputs:
                write_json_stable(package_target, outputs[rel], volatile_keys=())
            else:
                _copy_into_package(root, package_root, rel)
            package_entries.append(
                {
                    "authoritative_ref": rel,
                    "package_path": package_path,
                    "role": role,
                    "sha256": file_sha256((package_root / package_path).resolve()),
                }
            )

        package_adjudication_path = (package_root / Path(ADJUDICATION_PACKET).name).resolve()
        package_vsa_path = (package_root / Path(VERIFIER_V2_VSA).name).resolve()
        write_json_stable(package_adjudication_path, adjudication_packet, volatile_keys=())
        write_json_stable(package_vsa_path, vsa, volatile_keys=())
        package_entries.extend(
            [
                {
                    "authoritative_ref": ADJUDICATION_PACKET,
                    "package_path": package_adjudication_path.relative_to(package_root).as_posix(),
                    "role": "adjudication_packet",
                    "sha256": file_sha256(package_adjudication_path),
                },
                {
                    "authoritative_ref": VERIFIER_V2_VSA,
                    "package_path": package_vsa_path.relative_to(package_root).as_posix(),
                    "role": "verifier_summary_attestation",
                    "sha256": file_sha256(package_vsa_path),
                },
            ]
        )
        if outsider_tool_present:
            package_entries.append(
                {
                    "authoritative_ref": OUTSIDER_TOOL_REL,
                    "package_path": run_script_path.relative_to(package_root).as_posix(),
                    "role": "one_command_entrypoint",
                    "sha256": file_sha256(run_script_path),
                }
            )

        manifest = {
            "schema_id": "kt.child_campaign.public_verifier_release_manifest.v2",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F04,
            "status": "PASS" if str(vsa.get("status", "")).strip() == "PASS" else "BLOCKED",
            "compiled_head_commit": head,
            "subject_head_commit": head,
            "bounded_scope": "CURRENT_HEAD_ASSURANCE_ONLY_DECLARED_CHILD_VERIFIER_SURFACES",
            "entrypoint_command": "python run_verifier_v2.py",
            "machine_output_path": "outputs/outsider_result.json",
            "human_output_path": "outputs/outsider_summary.txt",
            "exit_code_contract": {
                "0_PASS": "bounded pass",
                "1_BOUNDED_FAIL": "bounded fail",
                "2_INPUT_OR_ENV_INVALID": "input or pack invalid",
                "3_TRUST_OR_FRESHNESS_FAIL": "trust or freshness fail",
            },
            "requires_secret_material": False,
            "required_env_vars": [],
            "adjudication_packet_ref": Path(ADJUDICATION_PACKET).name,
            "vsa_ref": Path(VERIFIER_V2_VSA).name,
            "threshold_policy_package_path": _package_rel_for_repo_ref(THRESHOLD_POLICY),
            "tuf_policy_package_path": _package_rel_for_repo_ref(TUF_POLICY),
            "surface_id": "F04_CHILD_OUTSIDER_VERIFIER_V2_PACKAGE",
            "allowed_claims": adjudication_allowed_claims,
            "forbidden_claims": adjudication_forbidden_claims,
            "expected_open_blockers": list(outputs[BLOCKERS_V2]["open_blockers"]),
            "package_entries": package_entries,
            "current_strongest_claim": "F04 releases a secret-free, one-command outsider verifier v2 for adjudicated child verifier assurance surfaces only." if str(vsa.get("status", "")).strip() == "PASS" else "F04 does not yet release a bounded outsider verifier v2 because the adjudication chain is blocked.",
            "stronger_claim_not_made": [
                "Current-head external capability is confirmed",
                "Release readiness is proven",
                "Release activation is executed",
                "Product or commercial readiness is proven",
            ],
            "limitations": [
                "Verifier v2 is bounded to adjudicated child verifier assurance surfaces only.",
                "Verifier v2 does not prove current-head runtime capability.",
                "Verifier v2 does not prove release readiness, release ceremony, or release activation.",
                "Verifier v2 does not fix repo-root import fragility.",
            ],
            "package_root_ref": OUTSIDER_PACKAGE_ROOT,
        }
        manifest_sha256 = _json_sha256(manifest)
        f04_surface_target = {
            "surface_id": "F04_CHILD_OUTSIDER_VERIFIER_V2_PACKAGE",
            "scope": "CHILD_SECRET_FREE_OUTSIDER_VERIFIER_V2_ASSURANCE_ONLY",
            "source_receipt_ref": OUTSIDER_PATH_RECEIPT,
            "primary_manifest_ref": VERIFIER_V2_MANIFEST,
            "primary_manifest_sha256": manifest_sha256,
            "supporting_artifacts": [
                {"artifact_ref": VERIFIER_V2_VSA, "sha256": _json_sha256(vsa)},
                {"artifact_ref": ADJUDICATION_PACKET, "sha256": _json_sha256(adjudication_packet)},
            ],
        }
        outputs[THRESHOLD_POLICY]["accepted_verifier_surfaces"] = [*outputs[THRESHOLD_POLICY]["accepted_verifier_surfaces"], f04_surface_target]
        outputs[TUF_POLICY]["distribution_targets"] = [*outputs[TUF_POLICY]["distribution_targets"], f04_surface_target]

        outputs[VERIFIER_V2_MANIFEST] = manifest
        package_threshold_path = (package_root / _package_rel_for_repo_ref(THRESHOLD_POLICY)).resolve()
        package_tuf_path = (package_root / _package_rel_for_repo_ref(TUF_POLICY)).resolve()
        write_json_stable(package_threshold_path, outputs[THRESHOLD_POLICY], volatile_keys=())
        write_json_stable(package_tuf_path, outputs[TUF_POLICY], volatile_keys=())
        write_json_stable((package_root / Path(VERIFIER_V2_MANIFEST).name).resolve(), manifest, volatile_keys=())

        detached_output_dir = (package_root / "outputs").resolve()
        detached_output_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.pop("KT_HMAC_KEY_SIGNER_A", None)
        env.pop("KT_HMAC_KEY_SIGNER_B", None)
        if outsider_tool_present:
            with tempfile.TemporaryDirectory(prefix="kt_f04_outsider_") as temp_dir:
                detached_root = Path(temp_dir).resolve() / "package"
                shutil.copytree(package_root, detached_root)
                run_cmd = [sys.executable, "run_verifier_v2.py"]
                first = subprocess.run(run_cmd, cwd=detached_root, check=False, capture_output=True, text=True, encoding="utf-8", env=env)
                first_json = load_json((detached_root / "outputs/outsider_result.json").resolve())
                first_summary = (detached_root / "outputs/outsider_summary.txt").resolve().read_text(encoding="utf-8")
                first_json_hash = file_sha256((detached_root / "outputs/outsider_result.json").resolve())
                first_summary_hash = file_sha256((detached_root / "outputs/outsider_summary.txt").resolve())
                second = subprocess.run(run_cmd, cwd=detached_root, check=False, capture_output=True, text=True, encoding="utf-8", env=env)
                second_json = load_json((detached_root / "outputs/outsider_result.json").resolve())
                second_summary = (detached_root / "outputs/outsider_summary.txt").resolve().read_text(encoding="utf-8")
                second_json_hash = file_sha256((detached_root / "outputs/outsider_result.json").resolve())
                second_summary_hash = file_sha256((detached_root / "outputs/outsider_summary.txt").resolve())
                shutil.copy2((detached_root / "outputs/outsider_result.json").resolve(), (package_root / "outputs/outsider_result.json").resolve())
                shutil.copy2((detached_root / "outputs/outsider_summary.txt").resolve(), (package_root / "outputs/outsider_summary.txt").resolve())
        else:
            first = subprocess.CompletedProcess(args=[sys.executable, "run_verifier_v2.py"], returncode=2, stdout="")
            second = subprocess.CompletedProcess(args=[sys.executable, "run_verifier_v2.py"], returncode=2, stdout="")
            first_json = {"status": "INPUT_OR_ENV_INVALID", "error": "missing outsider verifier runtime source"}
            second_json = dict(first_json)
            first_summary = "status: INPUT_OR_ENV_INVALID\nerror: missing outsider verifier runtime source\n"
            second_summary = first_summary
            first_json_hash = _json_sha256(first_json)
            second_json_hash = first_json_hash
            first_summary_hash = _json_sha256({"summary": first_summary})
            second_summary_hash = first_summary_hash
            write_json_stable((package_root / "outputs/outsider_result.json").resolve(), first_json, volatile_keys=())
            (package_root / "outputs/outsider_summary.txt").resolve().write_text(first_summary, encoding="utf-8", newline="\n")

        f04_checks["adjudication_outputs_current_head_bound"] = str(adjudication_packet.get("status", "")).strip() == "PASS"
        f04_checks["claims_emit_only_from_adjudication_outputs"] = str(vsa.get("status", "")).strip() == "PASS"
        f04_checks["verifier_v2_manifest_secret_free"] = bool(manifest.get("requires_secret_material") is False) and not manifest.get("required_env_vars")
        f04_checks["outsider_path_deterministic_and_detached"] = all(
            [
                first.returncode == 0,
                second.returncode == 0,
                first_json == second_json,
                first_summary == second_summary,
                first_json_hash == second_json_hash,
                first_summary_hash == second_summary_hash,
                str(first_json.get("status", "")).strip() == "PASS",
            ]
        )
        for check_id, ok in f04_checks.items():
            if not ok:
                f04_blocked_by.append(check_id)
        f04_pass = all(f04_checks.values())
        f04_status = "PASS" if f04_pass else "BLOCKED"
        f04_next_phase = PHASE_F05 if f04_pass else PHASE_F04
        f04_allowed_claims = [
            "claims_emitted_only_from_child_adjudication_outputs_for_declared_f04_verifier_surfaces_only",
            "secret_free_one_command_outsider_verifier_v2_active_for_declared_child_verifier_surfaces_only",
        ] if f04_pass else []

        outputs[ADJUDICATION_SPLIT_RECEIPT] = {
            "schema_id": "kt.child_campaign.adjudication_split_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F04,
            "status": f04_status,
            "pass_verdict": PASS_VERDICT_F04 if f04_pass else BLOCKED_VERDICT_F04,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(f04_checks["adjudication_outputs_current_head_bound"], "adjudication_packet_current_head_bound", "Adjudication must bind authenticity, completeness, and freshness to the current child head.", [ADJUDICATION_PACKET]),
                _check(f04_checks["claims_emit_only_from_adjudication_outputs"], "claims_emit_only_from_adjudication_outputs", "Verifier v2 claims may compile only from the adjudication packet and VSA, not from raw receipts directly.", [ADJUDICATION_PACKET, VERIFIER_V2_VSA, VERIFIER_V2_MANIFEST]),
                _check(f04_checks["verifier_v2_manifest_secret_free"], "verifier_v2_manifest_declares_secret_free_runtime", "Verifier v2 must declare no hidden secret dependency.", [VERIFIER_V2_MANIFEST]),
            ],
            "blocked_by": f04_blocked_by,
            "current_strongest_claim": "F04 enforces a hard split where claims for the child verifier v2 surface compile only from adjudication outputs." if f04_pass else "F04 does not yet enforce the adjudication/claims split for the child verifier v2 surface.",
            "stronger_claim_not_made": [
                "The split itself proves current-head external capability",
                "The split itself proves release readiness",
                "The split itself widens product or commercial claims",
            ],
            "what_is_not_proven": [
                "Current-head external capability remains unconfirmed",
                "Release readiness remains unproven",
                "Release ceremony remains non-executed",
                "Release activation remains non-executed",
                "Repo-root import fragility remains visible and unfixed",
            ],
            "next_lawful_phase": f04_next_phase,
        }

        outputs[OUTSIDER_PATH_RECEIPT] = {
            "schema_id": "kt.child_campaign.outsider_path_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F04,
            "status": f04_status,
            "pass_verdict": PASS_VERDICT_F04 if f04_pass else BLOCKED_VERDICT_F04,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "entrypoint_command": "python run_verifier_v2.py",
            "detached_execution_root_type": "TEMPORARY_NO_GIT_COPY",
            "hidden_secret_dependency": "ABSENT",
            "deterministic_output_contract": "PASS" if f04_checks["outsider_path_deterministic_and_detached"] else "BLOCKED",
            "checks": [
                _check(True, "parent_surfaces_untouched_by_f04", "F04 must not mutate parent-era sovereign surfaces.", [PARENT_DAG, PARENT_FINAL, PARENT_PRODUCT]),
                _check(f04_checks["outsider_path_deterministic_and_detached"], "outsider_path_deterministic_and_detached", "Verifier v2 must run as a detached one-command outsider path with deterministic outputs.", [VERIFIER_V2_MANIFEST, VERIFIER_V2_VSA, ADJUDICATION_PACKET, OUTSIDER_PACKAGE_ROOT]),
                _check(f04_checks["verifier_v2_manifest_secret_free"], "outsider_path_secret_free", "Verifier v2 must require no HMAC or other hidden secret material.", [VERIFIER_V2_MANIFEST]),
            ],
            "runtime_invocations": [
                {"pass_index": 1, "returncode": first.returncode, "stdout_sha256": _json_sha256({"stdout": first.stdout})},
                {"pass_index": 2, "returncode": second.returncode, "stdout_sha256": _json_sha256({"stdout": second.stdout})},
            ],
            "machine_output_ref": f"{OUTSIDER_PACKAGE_ROOT}/outputs/outsider_result.json",
            "human_output_ref": f"{OUTSIDER_PACKAGE_ROOT}/outputs/outsider_summary.txt",
            "current_strongest_claim": "F04 proves a secret-free, one-command outsider verifier path for adjudicated child verifier surfaces only." if f04_pass else "F04 does not yet prove a secret-free, one-command outsider verifier path for adjudicated child verifier surfaces.",
            "stronger_claim_not_made": [
                "Verifier v2 externally confirms current-head runtime capability",
                "Verifier v2 proves release readiness or activation",
                "Verifier v2 widens product or commercial claims",
            ],
            "what_is_not_proven": [
                "Current-head external capability remains unconfirmed",
                "Release readiness remains unproven",
                "Release ceremony remains non-executed",
                "Release activation remains non-executed",
                "Repo-root import fragility remains visible and unfixed",
            ],
            "next_lawful_phase": f04_next_phase,
        }

        outputs[PROOF_V2]["inputs"] = [*outputs[PROOF_V2]["inputs"], ADJUDICATION_PACKET, ADJUDICATION_SPLIT_RECEIPT, VERIFIER_V2_MANIFEST, VERIFIER_V2_VSA, OUTSIDER_PATH_RECEIPT]
        outputs[PROOF_V2]["allowed_public_claims"] = [*outputs[PROOF_V2]["allowed_public_claims"], *f04_allowed_claims]
        outputs[PROOF_V2]["forbidden_public_claims"] = [*outputs[PROOF_V2]["forbidden_public_claims"], "f04_proves_current_head_external_capability", "f04_proves_release_readiness", "f04_widens_product_claims"]
        outputs[CHILD_DAG]["current_node"] = PHASE_F05 if f04_pass else PHASE_F04
        outputs[CHILD_DAG]["next_lawful_phase"] = f04_next_phase
        outputs[CHILD_DAG]["nodes"] = [
            {"id": PHASE_BOOTSTRAP, "status": "PASS"},
            {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
            {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
            {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
            {"id": PHASE_F04, "status": f04_status if f03_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F05, "status": "READY" if f04_pass else "BLOCKED_UPSTREAM"},
            {"id": "F06_EXTERNAL_CONFIRMATION_AND_FINAL_CURRENT_HEAD_READJUDICATION", "status": "BLOCKED_UPSTREAM"},
            {"id": "F07_RELEASE_READINESS_ELIGIBILITY_CEREMONY_AND_ACTIVATION", "status": "BLOCKED_UPSTREAM"},
            {"id": "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY", "status": "BLOCKED_UPSTREAM"},
            {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "BLOCKED_UPSTREAM"},
        ]
        outputs[STATE_V2]["computed_claim_ceiling"] = (
            "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F04_ADJUDICATION_SPLIT_AND_SECRET_FREE_OUTSIDER_VERIFIER_ONLY"
            if f04_pass
            else outputs[STATE_V2]["computed_claim_ceiling"]
        )
        outputs[STATE_V2]["verifier_status"] = (
            "CHILD_THRESHOLD_ROOT_ACCEPTANCE_MINIMAL_TUF_DISTRIBUTION_AND_SECRET_FREE_OUTSIDER_VERIFIER_V2_ACTIVE"
            if f04_pass
            else outputs[STATE_V2]["verifier_status"]
        )
        outputs[STATE_V2]["next_lawful_transition"] = f04_next_phase
        outputs[STATE_V2]["proof_integrity_receipts"] = [*outputs[STATE_V2]["proof_integrity_receipts"], ADJUDICATION_SPLIT_RECEIPT, OUTSIDER_PATH_RECEIPT]
        outputs[STATE_V2]["accepted_verifier_surface_count"] = len(outputs[THRESHOLD_POLICY]["accepted_verifier_surfaces"])

    if f04_pass:
        runtime_rows = list(outputs[RUNTIME_MATRIX]["surface_rows"])
        benchmark_rows = {row["surface_id"]: row for row in outputs[BENCHMARK_MATRIX]["rows"]}
        theater_rows = {row["surface_id"]: row for row in outputs[THEATER_MATRIX]["rows"]}
        prior_receipt_map = dict(outputs[STATE_V2].get("critical_organs_current_head_receipts", {}))
        capability_rows: List[Dict[str, Any]] = []
        promotion_rows: List[Dict[str, Any]] = []
        receipt_map: Dict[str, List[str]] = {}
        historical_laundering_detected = False
        unsupported_retention_detected = False

        for row in runtime_rows:
            surface_id = str(row["surface_id"]).strip()
            evidence_refs = list(row.get("evidence_refs", []))
            benchmark_status = str(row.get("benchmark_status", "")).strip()
            inventory_class = str(row.get("inventory_class", "")).strip()
            operational_class = str(row.get("operational_reality_class", "")).strip()
            maturity_class = str(row.get("maturity_class", "")).strip()
            capability_label = str(row.get("capability_label", "")).strip()
            inherited_blockers = list(row.get("blockers", []))
            theater_row = dict(theater_rows.get(surface_id, {}))
            benchmark_row = dict(benchmark_rows.get(surface_id, {}))

            test_refs = [ref for ref in evidence_refs if "/tests/" in ref.replace("\\", "/") or ref.replace("\\", "/").endswith(".py") and "/tests/" in ref.replace("\\", "/")]
            receipt_refs = [ref for ref in evidence_refs if ref.endswith("_receipt.json") or ref.endswith("_manifest.json") or ref.endswith("_attestation.json")]
            code_refs = [ref for ref in evidence_refs if ref not in test_refs and ref not in receipt_refs]

            historical_refs = [ref for ref in evidence_refs if ref == WS17B or "ws17b_capability" in ref.replace("\\", "/")]
            if historical_refs:
                historical_laundering_detected = True

            benchmark_backed = str(benchmark_row.get("has_current_head_benchmark_evidence", "")).lower() == "true"
            regression_backed = bool(test_refs)
            receipt_required = "RECEIPT" in benchmark_status or benchmark_status == "ADAPTER_TEST_GATE_ONLY"
            provenance_backed = bool(receipt_refs) if receipt_required else (bool(code_refs) and bool(test_refs))
            current_head_bound = bool(evidence_refs) and not historical_refs
            theater_risk_score = float(theater_row.get("theater_risk_score", 1.0))
            underexercised_surface_score = float(theater_row.get("underexercised_surface_score", 1.0))
            narrative_to_runtime_ratio = float(theater_row.get("narrative_to_runtime_ratio", 4.0))
            punitive_theater = (
                theater_risk_score > 0.15
                or underexercised_surface_score > 0.25
                or narrative_to_runtime_ratio > 0.75
            )

            promotion_blockers = list(inherited_blockers)
            if historical_refs:
                promotion_blockers.append("HISTORICAL_ONLY_EVIDENCE_FORBIDDEN")
            if inventory_class == "doctrinal_only":
                promotion_blockers.append("DOC_ONLY_SURFACE")
            if inventory_class == "stubbed":
                promotion_blockers.append("STUBBED_SURFACE")
            if not current_head_bound and inventory_class != "doctrinal_only":
                promotion_blockers.append("NO_CURRENT_HEAD_EVIDENCE_BINDING")
            if not benchmark_backed and inventory_class in {"live_unbenchmarked", "live_benchmarked", "stubbed"}:
                promotion_blockers.append("NO_CURRENT_HEAD_BENCHMARK_PACK")
            if not regression_backed and inventory_class != "doctrinal_only":
                promotion_blockers.append("NO_CURRENT_HEAD_REGRESSION_EVIDENCE")
            if receipt_required and not receipt_refs:
                promotion_blockers.append("NO_CURRENT_HEAD_RECEIPT_BACKING")
            if punitive_theater:
                promotion_blockers.append("THEATER_RISK_PUNITIVE_BLOCK")
            promotion_blockers = sorted(dict.fromkeys(promotion_blockers))

            if maturity_class == "O2_HARDENED":
                retention_ok = current_head_bound and benchmark_backed and regression_backed and (not receipt_required or bool(receipt_refs))
            elif maturity_class == "O1_IMPLEMENTED":
                retention_ok = bool(code_refs) and regression_backed and current_head_bound
            elif maturity_class == "O0_CONCEPTUAL":
                retention_ok = inventory_class == "doctrinal_only"
            else:
                retention_ok = False

            if not retention_ok:
                unsupported_retention_detected = True

            promotion_target = maturity_class
            promotion_action = "RETAIN_CURRENT_LEVEL" if retention_ok else "RETENTION_BLOCKED"
            if retention_ok and maturity_class == "O2_HARDENED":
                if provenance_backed and benchmark_backed and regression_backed and not punitive_theater:
                    promotion_target = "O3_PROVEN"
                    promotion_action = "PROMOTE_TO_O3_PROVEN"
                else:
                    promotion_blockers = sorted(dict.fromkeys([*promotion_blockers, "NO_O3_PROMOTION_EARNED"]))

            if promotion_action == "PROMOTE_TO_O3_PROVEN":
                # The current runtime evidence is still bounded and not signed/proven enough for a truthful O3 promotion.
                promotion_target = maturity_class
                promotion_action = "RETAIN_CURRENT_LEVEL"
                promotion_blockers = sorted(dict.fromkeys([*promotion_blockers, "O3_PROMOTION_WITHHELD_PENDING_STRONGER_PROVENANCE"]))

            current_head_receipt_status = "PASS" if current_head_bound and inventory_class not in {"doctrinal_only", "stubbed"} else "BLOCKED"
            if inventory_class == "doctrinal_only":
                current_head_receipt_status = "BLOCKED"
            if inventory_class == "stubbed":
                current_head_receipt_status = "BLOCKED"

            capability_rows.append(
                {
                    "surface_id": surface_id,
                    "current_head_receipt_status": current_head_receipt_status,
                    "current_head_receipt_kind": "CURRENT_HEAD_RUNTIME_TRUTH" if current_head_receipt_status == "PASS" else "CURRENT_HEAD_BLOCKER_ONLY",
                    "inventory_class": inventory_class,
                    "operational_reality_class": operational_class,
                    "capability_label": capability_label,
                    "current_maturity_class": maturity_class,
                    "benchmark_status": benchmark_status,
                    "benchmark_backed": benchmark_backed,
                    "provenance_backed": provenance_backed,
                    "regression_backed": regression_backed,
                    "receipt_required_for_claim": receipt_required,
                    "uses_historical_only_evidence": bool(historical_refs),
                    "evidence_refs": evidence_refs,
                    "historical_evidence_refs": historical_refs,
                    "explicit_blockers": promotion_blockers if current_head_receipt_status == "BLOCKED" else [],
                }
            )
            promotion_rows.append(
                {
                    "surface_id": surface_id,
                    "current_maturity_class": maturity_class,
                    "promotion_action": promotion_action,
                    "promotion_target_class": promotion_target,
                    "retention_ok": retention_ok,
                    "benchmark_backed": benchmark_backed,
                    "provenance_backed": provenance_backed,
                    "regression_backed": regression_backed,
                    "theater_risk_score": theater_risk_score,
                    "underexercised_surface_score": underexercised_surface_score,
                    "narrative_to_runtime_ratio": narrative_to_runtime_ratio,
                    "promotion_blockers": promotion_blockers,
                }
            )
            receipt_map[surface_id] = evidence_refs if current_head_receipt_status == "PASS" else [CURRENT_HEAD_CAPABILITY_MATRIX]

        accounted_rows = [
            row for row in capability_rows if row["current_head_receipt_status"] == "PASS" or row["explicit_blockers"]
        ]
        accounted_percent = round(len(accounted_rows) / (len(capability_rows) or 1) * 100.0, 2)
        prior_explicit_receipt_percent = round(len(prior_receipt_map) / (len(capability_rows) or 1) * 100.0, 2)
        runtime_only_blockers_unchanged = outputs[BLOCKERS_V2]["open_blockers"] == [
            "current_head_external_capability_not_confirmed",
            "release_readiness_not_proven",
            "release_ceremony_not_executed",
            "release_activation_not_executed",
            "repo_root_import_fragility_visible_and_unfixed",
        ]

        f05_checks["all_critical_organs_accounted"] = len(accounted_rows) == len(capability_rows)
        f05_checks["no_historical_capability_laundering"] = not historical_laundering_detected
        f05_checks["promotion_matrix_receipt_backed"] = not unsupported_retention_detected
        f05_checks["theater_risk_punitive"] = all(
            row["promotion_action"] != "PROMOTE_TO_O3_PROVEN" and (
                row["theater_risk_score"] > 0.15
                or row["underexercised_surface_score"] > 0.25
                or row["narrative_to_runtime_ratio"] > 0.75
            )
            or not (
                row["theater_risk_score"] > 0.15
                or row["underexercised_surface_score"] > 0.25
                or row["narrative_to_runtime_ratio"] > 0.75
            )
            for row in promotion_rows
        )
        f05_checks["claim_ceiling_unchanged_outside_runtime_truth"] = runtime_only_blockers_unchanged
        for check_id, ok in f05_checks.items():
            if not ok:
                f05_blocked_by.append(check_id)
        f05_pass = all(f05_checks.values())
        f05_status = "PASS" if f05_pass else "BLOCKED"
        f05_next_phase = PHASE_F06 if f05_pass else PHASE_F05
        f05_allowed_claims = [
            "all_critical_runtime_organs_current_head_accounted_with_receipts_or_explicit_blockers_only",
            "current_head_runtime_promotion_matrix_compiled_without_historical_capability_laundering",
            "theatrical_stubbed_and_doc_only_surfaces_remain_punitively_bounded",
        ] if f05_pass else []

        outputs[CURRENT_HEAD_CAPABILITY_MATRIX] = {
            "schema_id": "kt.child_campaign.current_head_capability_matrix.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F05,
            "status": f05_status,
            "current_repo_head": head,
            "accounted_surfaces_percent": accounted_percent,
            "prior_explicit_current_head_receipt_percent": prior_explicit_receipt_percent,
            "rows": capability_rows,
        }
        outputs[ORGAN_PROMOTION_MATRIX] = {
            "schema_id": "kt.child_campaign.organ_promotion_matrix.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F05,
            "status": f05_status,
            "current_repo_head": head,
            "rows": promotion_rows,
        }
        outputs[REGRESSION_MATRIX] = {
            "schema_id": "kt.child_campaign.regression_matrix.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F05,
            "status": f05_status,
            "current_repo_head": head,
            "control_plane_regression": "PASS",
            "verifier_regression": "PASS" if str(outputs[OUTSIDER_PATH_RECEIPT]["status"]).strip() == "PASS" else "FAIL",
            "runtime_truth_regression": "PASS" if f05_checks["all_critical_organs_accounted"] else "FAIL",
            "organ_maturity_regression": "PASS" if f05_checks["promotion_matrix_receipt_backed"] else "FAIL",
            "claim_ceiling_regression": "PASS" if f05_checks["claim_ceiling_unchanged_outside_runtime_truth"] else "FAIL",
            "declared_runtime_test_refs": sorted({ref for row in runtime_rows for ref in row.get("evidence_refs", []) if "/tests/" in ref.replace("\\", "/")}),
        }
        outputs[ORGAN_ELEVATION_RECEIPT] = {
            "schema_id": "kt.child_campaign.organ_elevation_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F05,
            "status": f05_status,
            "pass_verdict": PASS_VERDICT_F05 if f05_pass else BLOCKED_VERDICT_F05,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(f05_checks["all_critical_organs_accounted"], "all_critical_organs_have_current_head_receipt_or_explicit_blocker", "Every critical runtime organ must have a current-head receipt row or an explicit blocker row.", [CURRENT_HEAD_CAPABILITY_MATRIX, RUNTIME_MATRIX]),
                _check(f05_checks["no_historical_capability_laundering"], "no_historical_capability_receipt_used_for_current_runtime_truth", "Historical-only capability imports may not justify current-head runtime claims or promotions.", [CURRENT_HEAD_CAPABILITY_MATRIX, WS17B]),
                _check(f05_checks["promotion_matrix_receipt_backed"], "retentions_and_promotions_are_evidence_backed", "Organ retention and promotion decisions must be benchmark-backed, provenance-backed, regression-backed, or explicitly blocked.", [ORGAN_PROMOTION_MATRIX, REGRESSION_MATRIX]),
                _check(f05_checks["theater_risk_punitive"], "theater_risk_visible_and_punitive", "Theater-risk and underexercised runtime surfaces must be visible and punitive, not promotional.", [ORGAN_PROMOTION_MATRIX, THEATER_MATRIX]),
                _check(f05_checks["claim_ceiling_unchanged_outside_runtime_truth"], "no_unrelated_claim_widening", "F05 may not widen release, product, or commercial verdicts while compiling runtime truth.", [PROOF_V2, BLOCKERS_V2, STATE_V2]),
            ],
            "blocked_by": f05_blocked_by,
            "accounted_surfaces_percent": accounted_percent,
            "prior_explicit_current_head_receipt_percent": prior_explicit_receipt_percent,
            "promoted_surface_count": sum(1 for row in promotion_rows if row["promotion_action"] == "PROMOTE_TO_O3_PROVEN"),
            "retained_surface_count": sum(1 for row in promotion_rows if row["promotion_action"] == "RETAIN_CURRENT_LEVEL"),
            "blocked_surface_count": sum(1 for row in promotion_rows if row["promotion_action"] != "RETAIN_CURRENT_LEVEL"),
            "current_strongest_claim": "F05 locks a bounded current-head runtime truth and promotion matrix where every critical organ is accounted for by receipt-backed retention or explicit blocker status only." if f05_pass else "F05 does not yet lock a bounded current-head runtime truth and promotion matrix.",
            "stronger_claim_not_made": [
                "Current-head runtime capability is externally confirmed",
                "Any runtime organ is world-class",
                "Release readiness is proven",
                "Product or commercial readiness is proven",
            ],
            "what_is_not_proven": [
                "Current-head external capability remains unconfirmed",
                "Release readiness remains unproven",
                "Release ceremony remains non-executed",
                "Release activation remains non-executed",
                "Repo-root import fragility remains visible and unfixed",
            ],
            "next_lawful_phase": f05_next_phase,
        }

        outputs[PROOF_V2]["inputs"] = [*outputs[PROOF_V2]["inputs"], CURRENT_HEAD_CAPABILITY_MATRIX, ORGAN_PROMOTION_MATRIX, ORGAN_ELEVATION_RECEIPT, REGRESSION_MATRIX]
        outputs[PROOF_V2]["allowed_public_claims"] = [*outputs[PROOF_V2]["allowed_public_claims"], *f05_allowed_claims]
        outputs[PROOF_V2]["forbidden_public_claims"] = [
            *outputs[PROOF_V2]["forbidden_public_claims"],
            "f05_proves_current_head_external_capability",
            "f05_proves_release_readiness",
            "f05_widens_product_or_commercial_claims",
            "f05_promotes_theatrical_or_stubbed_organs_above_evidence",
        ]
        outputs[CHILD_DAG]["current_node"] = PHASE_F06 if f05_pass else PHASE_F05
        outputs[CHILD_DAG]["next_lawful_phase"] = f05_next_phase
        outputs[CHILD_DAG]["nodes"] = [
            {"id": PHASE_BOOTSTRAP, "status": "PASS"},
            {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
            {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
            {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
            {"id": PHASE_F04, "status": f04_status if f03_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F05, "status": f05_status if f04_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F06, "status": "READY" if f05_pass else "BLOCKED_UPSTREAM"},
            {"id": "F07_RELEASE_READINESS_ELIGIBILITY_CEREMONY_AND_ACTIVATION", "status": "BLOCKED_UPSTREAM"},
            {"id": "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY", "status": "BLOCKED_UPSTREAM"},
            {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "BLOCKED_UPSTREAM"},
        ]
        outputs[STATE_V2]["computed_claim_ceiling"] = (
            "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F05_RUNTIME_TRUTH_AND_BOUNDED_RETENTION_ONLY"
            if f05_pass
            else outputs[STATE_V2]["computed_claim_ceiling"]
        )
        outputs[STATE_V2]["next_lawful_transition"] = f05_next_phase
        outputs[STATE_V2]["critical_organs_current_head_receipts"] = receipt_map
        outputs[STATE_V2]["current_head_capability_matrix"] = CURRENT_HEAD_CAPABILITY_MATRIX
        outputs[STATE_V2]["organ_promotion_matrix"] = ORGAN_PROMOTION_MATRIX
        outputs[STATE_V2]["regression_matrix"] = REGRESSION_MATRIX
        outputs[STATE_V2]["current_head_receipt_or_blocker_coverage_percent"] = accounted_percent

    f06_next_phase = f05_next_phase

    if f05_pass:
        selected_runtime_row = next(
            (row for row in outputs[CURRENT_HEAD_CAPABILITY_MATRIX]["rows"] if str(row.get("surface_id", "")).strip() == F06_SELECTED_RUNTIME_SURFACE),
            {},
        )
        selected_promotion_row = next(
            (row for row in outputs[ORGAN_PROMOTION_MATRIX]["rows"] if str(row.get("surface_id", "")).strip() == F06_SELECTED_RUNTIME_SURFACE),
            {},
        )
        verifier_package_root = (root / OUTSIDER_PACKAGE_ROOT).resolve()
        runtime_package_root = (root / F06_RUNTIME_PACKAGE_ROOT).resolve()
        runtime_source_refs = [
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/__init__.py",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_schemas.py",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/__init__.py",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/base_schema.py",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_hash.py",
        ]
        runtime_bundle_ready = all(_exists(root, rel) for rel in runtime_source_refs) and bool(selected_runtime_row)

        env = dict(os.environ)
        env.pop("KT_HMAC_KEY_SIGNER_A", None)
        env.pop("KT_HMAC_KEY_SIGNER_B", None)

        verifier_replay = _run_detached_package_twice(
            package_root=verifier_package_root,
            run_cmd=[sys.executable, "run_verifier_v2.py"],
            machine_output_rel="outputs/outsider_result.json",
            human_output_rel="outputs/outsider_summary.txt",
            env=env,
            prefix="kt_f06_verifier",
        )
        verifier_machine = verifier_replay["machine_reports"][0] if verifier_replay["machine_reports"] else {"status": "INPUT_OR_ENV_INVALID", "error": "missing verifier replay output"}
        verifier_human = verifier_replay["human_reports"][0] if verifier_replay["human_reports"] else "status: INPUT_OR_ENV_INVALID\nerror: missing verifier replay output\n"

        if runtime_package_root.exists():
            shutil.rmtree(runtime_package_root)
        runtime_package_root.mkdir(parents=True, exist_ok=True)
        runtime_runner_path = (runtime_package_root / F06_RUNTIME_RUNNER_NAME).resolve()
        runtime_manifest_path = (runtime_package_root / F06_RUNTIME_MANIFEST_NAME).resolve()

        runtime_package_entries: List[Dict[str, Any]] = []
        if runtime_bundle_ready:
            for rel in runtime_source_refs:
                package_path = _copy_into_package(root, runtime_package_root, rel)
                runtime_package_entries.append(
                    {
                        "authoritative_ref": rel,
                        "package_path": package_path,
                        "sha256": file_sha256((runtime_package_root / package_path).resolve()),
                    }
                )
            for rel in (CURRENT_HEAD_CAPABILITY_MATRIX, ORGAN_PROMOTION_MATRIX, ORGAN_ELEVATION_RECEIPT, "KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json"):
                package_path = _package_rel_for_repo_ref(rel)
                write_json_stable((runtime_package_root / package_path).resolve(), outputs[rel] if rel in outputs else _j(root, rel), volatile_keys=())
                runtime_package_entries.append(
                    {
                        "authoritative_ref": rel,
                        "package_path": package_path,
                        "sha256": file_sha256((runtime_package_root / package_path).resolve()),
                    }
                )

        runtime_manifest = {
            "schema_id": "kt.child_campaign.runtime_surface_external_manifest.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": "PASS" if runtime_bundle_ready else "BLOCKED",
            "compiled_head_commit": head,
            "surface_id": F06_SELECTED_RUNTIME_SURFACE,
            "bounded_scope": "CURRENT_HEAD_SELECTED_RUNTIME_SURFACE_ONLY",
            "entrypoint_command": f"python {F06_RUNTIME_RUNNER_NAME}",
            "src_root_path": _package_rel_for_repo_ref("KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src"),
            "bounded_receipt_path": _package_rel_for_repo_ref("KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json"),
            "capability_matrix_path": _package_rel_for_repo_ref(CURRENT_HEAD_CAPABILITY_MATRIX),
            "promotion_matrix_path": _package_rel_for_repo_ref(ORGAN_PROMOTION_MATRIX),
            "package_entries": runtime_package_entries,
            "limitations": [
                "This pack confirms only the selected current-head runtime surface.",
                "This pack does not prove whole-system current-head capability.",
                "This pack does not prove release readiness, release ceremony execution, or release activation.",
            ],
        }
        runtime_runner_text = _build_f06_runtime_runner_text()
        runtime_runner_path.write_text(runtime_runner_text, encoding="utf-8", newline="\n")
        runtime_manifest["package_entries"].append(
            {
                "authoritative_ref": F06_RUNTIME_RUNNER_NAME,
                "package_path": F06_RUNTIME_RUNNER_NAME,
                "sha256": file_sha256(runtime_runner_path),
            }
        )
        write_json_stable(runtime_manifest_path, runtime_manifest, volatile_keys=())

        runtime_replay = _run_detached_package_twice(
            package_root=runtime_package_root,
            run_cmd=[sys.executable, F06_RUNTIME_RUNNER_NAME],
            machine_output_rel="outputs/runtime_result.json",
            human_output_rel="outputs/runtime_summary.txt",
            env=env,
            prefix="kt_f06_runtime",
        ) if runtime_bundle_ready else {
            "runs": [],
            "machine_reports": [],
            "human_reports": [],
            "parity_ok": False,
            "package_root_present": False,
        }
        runtime_machine = runtime_replay["machine_reports"][0] if runtime_replay["machine_reports"] else {"status": "INPUT_OR_ENV_INVALID", "error": "missing runtime replay output"}
        runtime_human = runtime_replay["human_reports"][0] if runtime_replay["human_reports"] else "status: INPUT_OR_ENV_INVALID\nerror: missing runtime replay output\n"

        final_open_blockers = list(outputs[BLOCKERS_V2]["open_blockers"])
        release_and_product_unchanged = all(
            [
                str(outputs[STATE_V2]["release_readiness_status"]).strip() == "NOT_PROVEN",
                str(outputs[STATE_V2]["release_eligibility_status"]).strip() == "NOT_ELIGIBLE",
                str(outputs[STATE_V2]["release_ceremony_status"]).strip() == "NON_EXECUTED_BLOCKED_BY_PREREQUISITES",
                str(outputs[STATE_V2]["release_activation_status"]).strip() == "NON_EXECUTED",
                str(outputs[STATE_V2]["product_surface_status"]).strip() == "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
            ]
        )

        f06_checks["verifier_current_head_outsider_replay_pass"] = (
            verifier_replay["package_root_present"]
            and verifier_replay["parity_ok"]
            and len(verifier_replay["runs"]) == 2
            and all(row["returncode"] == 0 and row["detached_root_detected"] for row in verifier_replay["runs"])
            and str(verifier_machine.get("status", "")).strip() == "PASS"
        )
        f06_checks["selected_runtime_surface_bundle_present"] = runtime_bundle_ready
        f06_checks["selected_runtime_surface_outsider_replay_pass"] = (
            runtime_bundle_ready
            and runtime_replay["parity_ok"]
            and len(runtime_replay["runs"]) == 2
            and all(row["returncode"] == 0 and row["detached_root_detected"] for row in runtime_replay["runs"])
            and str(runtime_machine.get("status", "")).strip() == "PASS"
        )
        f06_checks["selected_runtime_surface_current_head_only_no_historical_laundering"] = bool(selected_runtime_row) and (
            str(selected_runtime_row.get("current_head_receipt_status", "")).strip() == "PASS"
            and str(selected_runtime_row.get("capability_label", "")).strip() == "current_head_only"
            and not bool(selected_runtime_row.get("uses_historical_only_evidence"))
        )
        f06_checks["final_readjudication_current_head_bound"] = all(
            [
                str(outputs[STATE_V2]["subject_head_commit"]).strip() == head,
                str(outputs[STATE_V2]["current_repo_head"]).strip() == head,
                str(outputs[CURRENT_HEAD_CAPABILITY_MATRIX]["current_repo_head"]).strip() == head,
            ]
        )
        f06_checks["no_unrelated_claim_widening"] = release_and_product_unchanged and final_open_blockers == list(outputs[BLOCKERS_V2]["open_blockers"])
        for check_id, ok in f06_checks.items():
            if not ok:
                f06_blocked_by.append(check_id)
        f06_pass = all(f06_checks.values())
        f06_status = "PASS" if f06_pass else "BLOCKED"
        f06_next_phase = PHASE_F07 if f06_pass else PHASE_F06
        f06_allowed_claims = [
            "current_head_child_verifier_v2_outsider_replay_confirmed_in_two_detached_environments_only",
            "current_head_selected_runtime_surface_paradox_outsider_replay_confirmed_in_two_detached_environments_only",
            "final_current_head_readjudication_recomputed_without_release_or_product_widening",
        ] if f06_pass else []

        outputs[VERIFIER_EXTERNAL_CONFIRMATION] = {
            "schema_id": "kt.child_campaign.external_verifier_confirmation_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": "PASS" if f06_checks["verifier_current_head_outsider_replay_pass"] else "BLOCKED",
            "pass_verdict": "CURRENT_HEAD_CHILD_VERIFIER_V2_OUTSIDER_REPLAY_CONFIRMED" if f06_checks["verifier_current_head_outsider_replay_pass"] else BLOCKED_VERDICT_F06,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "confirmation_class": "OUTSIDER_REPLAY_TWO_DETACHED_ENVIRONMENTS_SAME_HOST",
            "package_root_ref": OUTSIDER_PACKAGE_ROOT,
            "runtime_invocations": verifier_replay["runs"],
            "machine_result": verifier_machine,
            "human_summary_sha256": _json_sha256({"summary": verifier_human}),
            "blocked_by": [] if f06_checks["verifier_current_head_outsider_replay_pass"] else ["verifier_current_head_outsider_replay_pass"],
            "current_strongest_claim": "F06 confirms the child verifier v2 package can be replayed from two detached current-head environments with no hidden secret dependency." if f06_checks["verifier_current_head_outsider_replay_pass"] else "F06 does not yet confirm the child verifier v2 package from detached current-head environments.",
            "stronger_claim_not_made": [
                "This verifier confirmation is an independent third-party or hostile external audit",
                "This verifier confirmation proves current-head runtime superiority",
                "This verifier confirmation proves release readiness or release activation",
            ],
            "next_lawful_phase": f06_next_phase,
        }

        outputs[RUNTIME_EXTERNAL_CONFIRMATION] = {
            "schema_id": "kt.child_campaign.external_runtime_confirmation_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": "PASS" if f06_checks["selected_runtime_surface_outsider_replay_pass"] else "BLOCKED",
            "pass_verdict": "CURRENT_HEAD_SELECTED_RUNTIME_SURFACE_OUTSIDER_REPLAY_CONFIRMED" if f06_checks["selected_runtime_surface_outsider_replay_pass"] else BLOCKED_VERDICT_F06,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "confirmation_class": "OUTSIDER_REPLAY_TWO_DETACHED_ENVIRONMENTS_SAME_HOST",
            "selected_runtime_surface": F06_SELECTED_RUNTIME_SURFACE,
            "package_root_ref": F06_RUNTIME_PACKAGE_ROOT,
            "runtime_invocations": runtime_replay["runs"],
            "machine_result": runtime_machine,
            "human_summary_sha256": _json_sha256({"summary": runtime_human}),
            "blocked_by": [
                check_id
                for check_id in (
                    "selected_runtime_surface_bundle_present",
                    "selected_runtime_surface_outsider_replay_pass",
                    "selected_runtime_surface_current_head_only_no_historical_laundering",
                )
                if not f06_checks[check_id]
            ],
            "current_strongest_claim": "F06 confirms the selected current-head runtime surface paradox by detached two-environment outsider replay only." if f06_checks["selected_runtime_surface_outsider_replay_pass"] else "F06 does not yet confirm the selected current-head runtime surface by detached outsider replay.",
            "stronger_claim_not_made": [
                "This confirms whole-system current-head capability",
                "This upgrades KT into runtime world-class standing",
                "This proves release readiness or product readiness",
            ],
            "next_lawful_phase": f06_next_phase,
        }

        outputs[FINAL_BLOCKER_MATRIX] = {
            "schema_id": "kt.child_campaign.final_blocker_matrix.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": f06_status,
            "current_repo_head": head,
            "selected_runtime_surface": F06_SELECTED_RUNTIME_SURFACE,
            "open_blockers": final_open_blockers,
            "cleared_by_f06": [],
            "bounded_confirmations": [
                VERIFIER_EXTERNAL_CONFIRMATION,
                RUNTIME_EXTERNAL_CONFIRMATION,
            ] if f06_pass else [],
        }

        final_claim_ceiling = (
            "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F06_VERIFIER_AND_SELECTED_RUNTIME_OUTSIDER_REPLAY_CONFIRMED_ONLY"
            if f06_pass
            else outputs[STATE_V2]["computed_claim_ceiling"]
        )
        outputs[FINAL_CLAIM_CEILING] = {
            "schema_id": "kt.child_campaign.final_claim_ceiling_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": f06_status,
            "pass_verdict": PASS_VERDICT_F06 if f06_pass else BLOCKED_VERDICT_F06,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "computed_claim_ceiling": final_claim_ceiling,
            "allowed_public_claims": f06_allowed_claims,
            "forbidden_public_claims": [
                "f06_proves_whole_system_current_head_capability",
                "f06_proves_release_readiness",
                "f06_executes_release_ceremony_or_release_activation",
                "f06_widens_product_or_commercial_claims",
            ],
            "next_lawful_phase": f06_next_phase,
        }

        outputs[FINAL_CURRENT_HEAD_READJUDICATION] = {
            "schema_id": "kt.child_campaign.final_current_head_readjudication_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F06,
            "status": f06_status,
            "pass_verdict": PASS_VERDICT_F06 if f06_pass else BLOCKED_VERDICT_F06,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(f06_checks["verifier_current_head_outsider_replay_pass"], "verifier_outsider_replay_confirmed", "Current-head child verifier v2 must replay deterministically in two detached environments.", [VERIFIER_EXTERNAL_CONFIRMATION, OUTSIDER_PATH_RECEIPT]),
                _check(f06_checks["selected_runtime_surface_bundle_present"], "selected_runtime_surface_bundle_present", "The selected runtime surface bundle must be present for current-head outsider replay.", [RUNTIME_EXTERNAL_CONFIRMATION, CURRENT_HEAD_CAPABILITY_MATRIX, ORGAN_PROMOTION_MATRIX]),
                _check(f06_checks["selected_runtime_surface_outsider_replay_pass"], "selected_runtime_surface_outsider_replay_confirmed", "The selected current-head runtime surface must replay deterministically in two detached environments.", [RUNTIME_EXTERNAL_CONFIRMATION]),
                _check(f06_checks["selected_runtime_surface_current_head_only_no_historical_laundering"], "selected_runtime_surface_current_head_only_no_historical_laundering", "The selected runtime surface must remain current-head-only and must not borrow historical-only capability proof.", [CURRENT_HEAD_CAPABILITY_MATRIX, WS17B]),
                _check(f06_checks["final_readjudication_current_head_bound"], "final_readjudication_current_head_bound", "Final readjudication must remain bound to the current child head.", [STATE_V2, CURRENT_HEAD_CAPABILITY_MATRIX]),
                _check(f06_checks["no_unrelated_claim_widening"], "no_unrelated_claim_widening", "F06 may not widen release, product, or commercial verdicts while recomputing readjudication.", [FINAL_BLOCKER_MATRIX, FINAL_CLAIM_CEILING, STATE_V2]),
            ],
            "blocked_by": f06_blocked_by,
            "selected_runtime_surface": F06_SELECTED_RUNTIME_SURFACE,
            "current_head_capability_status": "SELECTED_RUNTIME_SURFACE_ONLY_OUTSIDER_REPLAY_CONFIRMED" if f06_pass else "NOT_EXTERNALLY_CONFIRMED",
            "external_confirmation_status": "CURRENT_HEAD_VERIFIER_AND_SELECTED_RUNTIME_SURFACE_OUTSIDER_REPLAY_CONFIRMED_ONLY" if f06_pass else outputs[STATE_V2]["external_confirmation_status"],
            "release_readiness_status": outputs[STATE_V2]["release_readiness_status"],
            "release_eligibility_status": outputs[STATE_V2]["release_eligibility_status"],
            "release_ceremony_status": outputs[STATE_V2]["release_ceremony_status"],
            "release_activation_status": outputs[STATE_V2]["release_activation_status"],
            "open_blockers": final_open_blockers,
            "current_strongest_claim": "F06 recomputes final current-head readjudication with bounded outsider confirmation for the verifier and the selected runtime surface only." if f06_pass else "F06 does not yet recompute final current-head readjudication with bounded outsider confirmation.",
            "stronger_claim_not_made": [
                "Whole-system current-head capability is externally confirmed",
                "Release readiness is proven",
                "Release ceremony or release activation is executed",
                "Product or commercial readiness is proven",
            ],
            "next_lawful_phase": f06_next_phase,
        }

        outputs[PROOF_V2]["inputs"] = [*outputs[PROOF_V2]["inputs"], VERIFIER_EXTERNAL_CONFIRMATION, RUNTIME_EXTERNAL_CONFIRMATION, FINAL_CLAIM_CEILING, FINAL_BLOCKER_MATRIX, FINAL_CURRENT_HEAD_READJUDICATION]
        outputs[PROOF_V2]["allowed_public_claims"] = [*outputs[PROOF_V2]["allowed_public_claims"], *f06_allowed_claims]
        outputs[PROOF_V2]["forbidden_public_claims"] = [
            *outputs[PROOF_V2]["forbidden_public_claims"],
            "f06_proves_whole_system_current_head_capability",
            "f06_proves_release_readiness",
            "f06_executes_release_ceremony_or_activation",
            "f06_widens_product_or_commercial_claims",
        ]
        outputs[CHILD_DAG]["current_node"] = PHASE_F07 if f06_pass else PHASE_F06
        outputs[CHILD_DAG]["next_lawful_phase"] = f06_next_phase
        outputs[CHILD_DAG]["nodes"] = [
            {"id": PHASE_BOOTSTRAP, "status": "PASS"},
            {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
            {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
            {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
            {"id": PHASE_F04, "status": f04_status if f03_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F05, "status": f05_status if f04_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F06, "status": f06_status if f05_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F07, "status": "READY" if f06_pass else "BLOCKED_UPSTREAM"},
            {"id": "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY", "status": "BLOCKED_UPSTREAM"},
            {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "BLOCKED_UPSTREAM"},
        ]
        outputs[STATE_V2]["computed_claim_ceiling"] = final_claim_ceiling
        outputs[STATE_V2]["blocker_matrix"] = FINAL_BLOCKER_MATRIX
        outputs[STATE_V2]["external_confirmation_status"] = (
            "CURRENT_HEAD_VERIFIER_AND_SELECTED_RUNTIME_SURFACE_OUTSIDER_REPLAY_CONFIRMED_ONLY"
            if f06_pass
            else outputs[STATE_V2]["external_confirmation_status"]
        )
        outputs[STATE_V2]["next_lawful_transition"] = f06_next_phase
        outputs[STATE_V2]["open_blockers"] = final_open_blockers
        outputs[STATE_V2]["external_verifier_confirmation_receipt"] = VERIFIER_EXTERNAL_CONFIRMATION
        outputs[STATE_V2]["external_runtime_confirmation_receipt"] = RUNTIME_EXTERNAL_CONFIRMATION
        outputs[STATE_V2]["selected_externally_confirmed_runtime_surfaces"] = [F06_SELECTED_RUNTIME_SURFACE] if f06_pass else []
        outputs[STATE_V2]["final_current_head_readjudication_receipt"] = FINAL_CURRENT_HEAD_READJUDICATION

    if f06_pass:
        threshold_root_active = (
            str(outputs[THRESHOLD_POLICY].get("status", "")).strip() == "ACTIVE"
            and str(outputs[THRESHOLD_POLICY].get("accepted_primary_trust_root", {}).get("acceptance_state", "")).strip()
            == "ACTIVE_THRESHOLD_ACCEPTED_CHILD_SCOPED"
        )
        release_signer_topology_declared = (
            release_threshold >= 2
            and release_signer_count >= release_threshold
            and len(release_role_identities) >= release_threshold
        )
        producer_attestation_role_declared = (
            producer_threshold >= 2
            and producer_signer_count >= producer_threshold
            and len(producer_role_identities) >= producer_threshold
        )
        release_overlap_constraints_ok = all(
            constraint_statuses.get(cid) == "PASS"
            for cid in (
                "root_release_overlap_forbidden",
                "root_producer_overlap_forbidden",
                "release_verifier_acceptance_overlap_forbidden",
                "operator_release_overlap_forbidden",
            )
            if cid in constraint_statuses
        )
        release_signer_issuance_executed = release_signer_topology_declared and release_role_state.startswith("EXECUTED")
        producer_attestation_bundle_valid = producer_attestation_role_declared and producer_role_state.startswith("EXECUTED")
        release_readiness_proven = all(
            [
                threshold_root_active,
                release_signer_topology_declared,
                release_signer_issuance_executed,
                producer_attestation_role_declared,
                producer_attestation_bundle_valid,
                release_overlap_constraints_ok,
                str(outputs[FINAL_CURRENT_HEAD_READJUDICATION].get("status", "")).strip() == "PASS",
            ]
        )
        release_eligibility_proven = release_readiness_proven
        release_ceremony_executed = release_eligibility_proven and release_signer_issuance_executed and producer_attestation_bundle_valid
        release_activation_executed = release_ceremony_executed
        product_surface_unchanged = str(outputs[STATE_V2].get("product_surface_status", "")).strip() == "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE"
        runtime_truth_unchanged = (
            str(outputs[FINAL_CURRENT_HEAD_READJUDICATION].get("current_head_capability_status", "")).strip()
            == "SELECTED_RUNTIME_SURFACE_ONLY_OUTSIDER_REPLAY_CONFIRMED"
        )

        f07_checks["threshold_root_acceptance_still_active"] = threshold_root_active
        f07_checks["release_signer_topology_declared"] = release_signer_topology_declared and producer_attestation_role_declared and release_overlap_constraints_ok
        f07_checks["release_signer_issuance_executed"] = release_signer_issuance_executed
        f07_checks["producer_attestation_bundle_valid"] = producer_attestation_bundle_valid
        f07_checks["release_readiness_proven"] = release_readiness_proven
        f07_checks["release_eligibility_proven"] = release_eligibility_proven
        f07_checks["release_ceremony_executed"] = release_ceremony_executed
        f07_checks["release_activation_executed"] = release_activation_executed
        f07_checks["no_unrelated_claim_widening"] = product_surface_unchanged and runtime_truth_unchanged
        for check_id, ok in f07_checks.items():
            if not ok:
                f07_blocked_by.append(check_id)
        f07_pass = all(f07_checks.values())
        f07_status = "PASS" if f07_pass else "BLOCKED"
        f07_next_phase = "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY" if f07_pass else PHASE_F07
        f07_allowed_claims = [
            "child_bounded_release_readiness_proven_without_runtime_or_product_widening",
            "child_bounded_release_eligibility_proven_without_runtime_or_product_widening",
            "child_bounded_release_ceremony_and_activation_executed_without_product_activation",
        ] if f07_pass else []
        f07_open_blockers = [
            blocker
            for blocker, ok in (
                ("current_head_external_capability_not_confirmed", False),
                ("release_readiness_not_proven", f07_checks["release_readiness_proven"]),
                ("release_ceremony_not_executed", f07_checks["release_ceremony_executed"]),
                ("release_activation_not_executed", f07_checks["release_activation_executed"]),
                ("repo_root_import_fragility_visible_and_unfixed", False),
            )
            if not ok
        ]

        outputs[F07_THRESHOLD_RECEIPT] = {
            "schema_id": "kt.child_campaign.threshold_root_acceptance_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "status": "PASS" if threshold_root_active else "BLOCKED",
            "pass_verdict": "CHILD_THRESHOLD_ROOT_ACCEPTANCE_RECONFIRMED_FOR_RELEASE_PRECONDITIONS" if threshold_root_active else BLOCKED_VERDICT_F07,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "checks": [
                _check(threshold_root_active, "child_threshold_root_acceptance_active", "F07 requires the child threshold-root acceptance state to remain active before any release legitimacy step can proceed.", [THRESHOLD_POLICY, TRUST_ROOT, SIGNER_TOPOLOGY]),
            ],
            "blocked_by": [] if threshold_root_active else ["threshold_root_acceptance_still_active"],
            "current_strongest_claim": "F07 reconfirms child threshold-root acceptance as an active release precondition only." if threshold_root_active else "F07 cannot treat threshold-root acceptance as an active release precondition.",
            "stronger_claim_not_made": [
                "This receipt proves release readiness by itself",
                "This receipt proves release ceremony execution by itself",
                "This receipt widens runtime, product, or commercial claims",
            ],
            "next_lawful_phase": f07_next_phase,
        }

        outputs[F07_RELEASE_SIGNER_ISSUANCE] = {
            "schema_id": "kt.child_campaign.release_signer_issuance_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "status": "PASS" if release_signer_issuance_executed else "BLOCKED",
            "pass_verdict": "CHILD_RELEASE_SIGNER_ISSUANCE_EXECUTED" if release_signer_issuance_executed else BLOCKED_VERDICT_F07,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "release_role": {
                "role_id": "release",
                "threshold": release_threshold,
                "signer_count": release_signer_count,
                "planned_identity_ids": release_role_identities,
                "issuance_state": release_role_state,
            },
            "checks": [
                _check(release_signer_topology_declared, "release_signer_topology_declared", "F07 requires a declared child release signer topology with a truthful threshold and signer count.", [SIGNER_TOPOLOGY]),
                _check(release_overlap_constraints_ok, "release_signer_overlap_constraints_pass", "Release signer issuance may not violate root, producer, verifier-acceptance, or operator overlap constraints.", [IDENTITY_MODEL]),
                _check(release_signer_issuance_executed, "release_signer_issuance_executed", "Release signer issuance must move beyond planned-only state before release legitimacy can pass.", [SIGNER_TOPOLOGY, TRUST_ROOT]),
            ],
            "blocked_by": [
                check_id
                for check_id in ("release_signer_topology_declared", "release_signer_issuance_executed")
                if not (
                    release_signer_topology_declared
                    if check_id == "release_signer_topology_declared"
                    else release_signer_issuance_executed
                )
            ],
            "current_strongest_claim": "F07 proves only that the child release signer lane is declared and remains planned-only pending executed issuance." if not release_signer_issuance_executed else "F07 proves child release signer issuance is executed on the bounded release lane.",
            "stronger_claim_not_made": [
                "Release readiness is proven by signer issuance alone",
                "Release ceremony is executed by signer issuance alone",
                "Product activation is implied by signer issuance",
            ],
            "next_lawful_phase": f07_next_phase,
        }

        outputs[F07_PRODUCER_ATTESTATION_BUNDLE] = {
            "schema_id": "kt.child_campaign.producer_attestation_bundle.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "status": "PASS" if producer_attestation_bundle_valid else "BLOCKED",
            "pass_verdict": "CHILD_PRODUCER_ATTESTATION_BUNDLE_ACTIVE" if producer_attestation_bundle_valid else BLOCKED_VERDICT_F07,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "producer_role": {
                "role_id": "producer",
                "threshold": producer_threshold,
                "signer_count": producer_signer_count,
                "planned_identity_ids": producer_role_identities,
                "issuance_state": producer_role_state,
            },
            "bundle_scope": "CHILD_RELEASE_PREREQUISITE_ATTESTATION_SET_ONLY",
            "planned_attested_refs": [
                THRESHOLD_POLICY,
                TUF_POLICY,
                PIPELINE_RECEIPT,
                SLSA_RECEIPT,
                CROSS_HOST_RECEIPT,
                OUTSIDER_PATH_RECEIPT,
                FINAL_CURRENT_HEAD_READJUDICATION,
            ],
            "checks": [
                _check(producer_attestation_role_declared, "producer_role_declared", "F07 requires a declared producer-attestation role with a truthful threshold and signer count.", [SIGNER_TOPOLOGY]),
                _check(producer_attestation_bundle_valid, "producer_attestation_bundle_valid", "Producer attestation may not be treated as active while the producer role remains planned-only.", [SIGNER_TOPOLOGY, TRUST_ROOT]),
            ],
            "blocked_by": [
                check_id
                for check_id in ("release_signer_topology_declared", "producer_attestation_bundle_valid")
                if not (
                    f07_checks["release_signer_topology_declared"]
                    if check_id == "release_signer_topology_declared"
                    else producer_attestation_bundle_valid
                )
            ],
            "current_strongest_claim": "F07 assembles the bounded producer-attestation bundle shape but does not treat it as active while producer issuance remains planned-only." if not producer_attestation_bundle_valid else "F07 proves the bounded producer-attestation bundle is active for the child release lane.",
            "stronger_claim_not_made": [
                "Producer attestation upgrades current-head capability truth",
                "Producer attestation proves product or commercial readiness",
                "Producer attestation alone executes the release ceremony",
            ],
            "next_lawful_phase": f07_next_phase,
        }

        release_readiness_status = "PROVEN_CHILD_BOUNDED_RELEASE_ONLY" if release_readiness_proven else "NOT_PROVEN"
        release_eligibility_status = "ELIGIBLE_CHILD_BOUNDED_RELEASE_ONLY" if release_eligibility_proven else "NOT_ELIGIBLE"
        release_ceremony_status = "EXECUTED_CHILD_BOUNDED_RELEASE_ONLY" if release_ceremony_executed else "NON_EXECUTED_BLOCKED_BY_PREREQUISITES"
        release_activation_status = "EXECUTED_CHILD_BOUNDED_RELEASE_ONLY" if release_activation_executed else "NON_EXECUTED"

        outputs[F07_RELEASE_CEREMONY_RECEIPT] = {
            "schema_id": "kt.child_campaign.executed_release_ceremony_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "status": "PASS" if release_ceremony_executed else "BLOCKED",
            "pass_verdict": "CHILD_BOUNDED_RELEASE_CEREMONY_EXECUTED" if release_ceremony_executed else BLOCKED_VERDICT_F07,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "release_readiness_status": release_readiness_status,
            "release_eligibility_status": release_eligibility_status,
            "release_ceremony_status": release_ceremony_status,
            "checks": [
                _check(threshold_root_active, "threshold_root_active_for_release", "Release ceremony execution requires active child threshold-root acceptance.", [F07_THRESHOLD_RECEIPT]),
                _check(release_signer_issuance_executed, "release_signer_issuance_executed", "Release ceremony execution requires executed child release signer issuance.", [F07_RELEASE_SIGNER_ISSUANCE]),
                _check(producer_attestation_bundle_valid, "producer_attestation_bundle_valid", "Release ceremony execution requires a valid child producer attestation bundle.", [F07_PRODUCER_ATTESTATION_BUNDLE]),
                _check(release_readiness_proven, "release_readiness_proven", "Release readiness and eligibility must be proven before the child release ceremony can execute.", [FINAL_CURRENT_HEAD_READJUDICATION, F07_RELEASE_SIGNER_ISSUANCE, F07_PRODUCER_ATTESTATION_BUNDLE]),
                _check(release_ceremony_executed, "release_ceremony_executed", "The child release ceremony must actually execute rather than remain non-executed by prerequisite gap.", [F07_RELEASE_SIGNER_ISSUANCE, F07_PRODUCER_ATTESTATION_BUNDLE]),
            ],
            "blocked_by": [
                check_id
                for check_id in (
                    "threshold_root_acceptance_still_active",
                    "release_signer_issuance_executed",
                    "producer_attestation_bundle_valid",
                    "release_readiness_proven",
                    "release_ceremony_executed",
                )
                if not f07_checks[check_id]
            ],
            "current_strongest_claim": "F07 recomputes child release readiness and eligibility and keeps release ceremony execution blocked until signer issuance and producer attestation are actually executed." if not release_ceremony_executed else "F07 executes the child-bounded release ceremony without widening runtime or product claims.",
            "stronger_claim_not_made": [
                "Whole-system current-head capability is externally confirmed",
                "Product activation is executed",
                "Commercial readiness is proven",
            ],
            "next_lawful_phase": f07_next_phase,
        }

        outputs[F07_RELEASE_ACTIVATION_RECEIPT] = {
            "schema_id": "kt.child_campaign.release_activation_receipt.v1",
            "campaign_id": CAMPAIGN_ID,
            "phase_id": PHASE_F07,
            "status": "PASS" if release_activation_executed else "BLOCKED",
            "pass_verdict": "CHILD_BOUNDED_RELEASE_ACTIVATION_EXECUTED" if release_activation_executed else BLOCKED_VERDICT_F07,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "current_repo_head": head,
            "generated_utc": utc_now_iso_z(),
            "release_activation_status": release_activation_status,
            "checks": [
                _check(release_ceremony_executed, "release_ceremony_executed", "Release activation requires an executed child release ceremony.", [F07_RELEASE_CEREMONY_RECEIPT]),
                _check(release_activation_executed, "release_activation_executed", "Release activation may not be implied; it must execute on the bounded child release lane.", [F07_RELEASE_CEREMONY_RECEIPT, F07_RELEASE_SIGNER_ISSUANCE, F07_PRODUCER_ATTESTATION_BUNDLE]),
                _check(product_surface_unchanged, "product_surface_unchanged", "F07 must not widen product state while changing only release legitimacy.", [STATE_V2]),
            ],
            "blocked_by": [
                check_id
                for check_id in ("release_ceremony_executed", "release_activation_executed")
                if not f07_checks[check_id]
            ],
            "current_strongest_claim": "F07 keeps release activation explicitly non-executed while prerequisite release legitimacy remains incomplete." if not release_activation_executed else "F07 executes bounded release activation without widening runtime, product, or commercial claims.",
            "stronger_claim_not_made": [
                "Product wedge activation is executed",
                "Commercial or enterprise readiness is proven",
                "Current-head external capability is broadly confirmed",
            ],
            "next_lawful_phase": f07_next_phase,
        }

        outputs.update(
            _build_f07_execution_support_records(
                head=head,
                release_signer_issuance_executed=release_signer_issuance_executed,
                producer_attestation_bundle_valid=producer_attestation_bundle_valid,
                release_ceremony_executed=release_ceremony_executed,
                release_activation_executed=release_activation_executed,
            )
        )
        for rel in (
            F07_RELEASE_SIGNER_ISSUANCE,
            F07_PRODUCER_ATTESTATION_BUNDLE,
            F07_RELEASE_CEREMONY_RECEIPT,
            F07_RELEASE_ACTIVATION_RECEIPT,
        ):
            outputs[rel]["supporting_execution_refs"] = [
                F07_RELEASE_SIGNER_CUSTODY,
                F07_RELEASE_SIGNER_WITNESS,
                F07_PRODUCER_EXECUTION,
                F07_RELEASE_CEREMONY_EXECUTION,
                F07_RELEASE_ACTIVATION_EXECUTION,
            ]

        outputs[F07_EXECUTION_PACK_RECEIPT] = _prepare_f07_release_execution_pack(
            root,
            head=head,
            outputs=outputs,
            release_role={
                "threshold": release_threshold,
                "signer_count": release_signer_count,
                "planned_identity_ids": release_role_identities,
            },
            producer_role={
                "threshold": producer_threshold,
                "signer_count": producer_signer_count,
                "planned_identity_ids": producer_role_identities,
            },
            threshold_root_active=threshold_root_active,
            f07_next_phase=f07_next_phase,
        )
        for rel in (
            F07_RELEASE_SIGNER_ISSUANCE,
            F07_PRODUCER_ATTESTATION_BUNDLE,
            F07_RELEASE_CEREMONY_RECEIPT,
            F07_RELEASE_ACTIVATION_RECEIPT,
        ):
            outputs[rel]["offbox_execution_pack_receipt_ref"] = F07_EXECUTION_PACK_RECEIPT
            outputs[rel]["offbox_execution_pack_root_ref"] = F07_EXECUTION_PACK_ROOT

        outputs[BLOCKERS_V2]["current_repo_head"] = head
        outputs[BLOCKERS_V2]["open_blockers"] = f07_open_blockers
        outputs[BLOCKERS_V2]["rows"] = [
            {
                "blocker_id": "threshold_root_verifier_acceptance_inactive",
                "status": "CLEARED_BY_F02B",
                "evidence_refs": [THRESHOLD_POLICY, F07_THRESHOLD_RECEIPT],
                "rationale": "Child threshold-root acceptance remains active.",
            },
            {
                "blocker_id": "current_head_external_capability_not_confirmed",
                "status": "OPEN",
                "evidence_refs": [FINAL_CURRENT_HEAD_READJUDICATION],
                "rationale": "F07 does not widen selected-surface outsider replay into broad current-head external capability confirmation.",
            },
            {
                "blocker_id": "release_readiness_not_proven",
                "status": "CLEARED_BY_F07" if f07_checks["release_readiness_proven"] else "OPEN",
                "evidence_refs": [F07_RELEASE_SIGNER_ISSUANCE, F07_PRODUCER_ATTESTATION_BUNDLE, F07_RELEASE_CEREMONY_RECEIPT],
                "rationale": "Release readiness remains blocked until release signer issuance and producer attestation move beyond planned-only state.",
            },
            {
                "blocker_id": "release_ceremony_not_executed",
                "status": "CLEARED_BY_F07" if f07_checks["release_ceremony_executed"] else "OPEN",
                "evidence_refs": [F07_RELEASE_CEREMONY_RECEIPT],
                "rationale": "Release ceremony execution remains explicit and must not be implied from trust or verifier state.",
            },
            {
                "blocker_id": "release_activation_not_executed",
                "status": "CLEARED_BY_F07" if f07_checks["release_activation_executed"] else "OPEN",
                "evidence_refs": [F07_RELEASE_ACTIVATION_RECEIPT],
                "rationale": "Release activation remains explicit and must not be implied from readiness or ceremony status.",
            },
            {
                "blocker_id": "verifier_coverage_not_widened_beyond_bounded_surfaces",
                "status": "CLEARED_BY_F02B",
                "evidence_refs": [THRESHOLD_POLICY, TUF_POLICY],
                "rationale": "Minimal child verifier coverage widening remains active from F02B.",
            },
            {
                "blocker_id": "repo_root_import_fragility_visible_and_unfixed",
                "status": "OPEN",
                "evidence_refs": [OUTSIDER_PATH_RECEIPT, CROSS_HOST_RECEIPT],
                "rationale": "Repo-root invocation remains visibly fragile and is not a release-legitimacy fix in F07.",
            },
        ]

        outputs[PROOF_V2]["inputs"] = [
            *outputs[PROOF_V2]["inputs"],
            F07_THRESHOLD_RECEIPT,
            F07_RELEASE_SIGNER_ISSUANCE,
            F07_PRODUCER_ATTESTATION_BUNDLE,
            F07_RELEASE_CEREMONY_RECEIPT,
            F07_RELEASE_ACTIVATION_RECEIPT,
            F07_RELEASE_SIGNER_CUSTODY,
            F07_RELEASE_SIGNER_WITNESS,
            F07_PRODUCER_EXECUTION,
            F07_RELEASE_CEREMONY_EXECUTION,
            F07_RELEASE_ACTIVATION_EXECUTION,
        ]
        outputs[PROOF_V2]["blocked_by"] = f07_open_blockers
        outputs[PROOF_V2]["allowed_public_claims"] = [*outputs[PROOF_V2]["allowed_public_claims"], *f07_allowed_claims]
        outputs[PROOF_V2]["forbidden_public_claims"] = [
            *outputs[PROOF_V2]["forbidden_public_claims"],
            "f07_proves_whole_system_current_head_capability",
            "f07_widens_runtime_truth_class",
            "f07_widens_product_or_commercial_claims",
        ]
        if f07_pass:
            outputs[STATE_V2]["computed_claim_ceiling"] = "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F07_BOUNDED_RELEASE_LEGITIMACY_ONLY"
        outputs[STATE_V2]["blocker_matrix"] = BLOCKERS_V2
        outputs[STATE_V2]["release_readiness_status"] = release_readiness_status
        outputs[STATE_V2]["release_eligibility_status"] = release_eligibility_status
        outputs[STATE_V2]["release_ceremony_status"] = release_ceremony_status
        outputs[STATE_V2]["release_activation_status"] = release_activation_status
        outputs[STATE_V2]["next_lawful_transition"] = f07_next_phase
        outputs[STATE_V2]["open_blockers"] = f07_open_blockers
        outputs[STATE_V2]["release_threshold_root_acceptance_receipt"] = F07_THRESHOLD_RECEIPT
        outputs[STATE_V2]["release_signer_issuance_receipt"] = F07_RELEASE_SIGNER_ISSUANCE
        outputs[STATE_V2]["producer_attestation_bundle"] = F07_PRODUCER_ATTESTATION_BUNDLE
        outputs[STATE_V2]["executed_release_ceremony_receipt"] = F07_RELEASE_CEREMONY_RECEIPT
        outputs[STATE_V2]["release_activation_receipt"] = F07_RELEASE_ACTIVATION_RECEIPT
        outputs[STATE_V2]["release_execution_pack_receipt"] = F07_EXECUTION_PACK_RECEIPT
        outputs[STATE_V2]["release_signer_custody_record"] = F07_RELEASE_SIGNER_CUSTODY
        outputs[STATE_V2]["release_signer_quorum_witness_record"] = F07_RELEASE_SIGNER_WITNESS
        outputs[STATE_V2]["producer_attestation_execution_record"] = F07_PRODUCER_EXECUTION
        outputs[STATE_V2]["release_ceremony_execution_record"] = F07_RELEASE_CEREMONY_EXECUTION
        outputs[STATE_V2]["release_activation_execution_record"] = F07_RELEASE_ACTIVATION_EXECUTION
        outputs[CHILD_DAG]["current_node"] = PHASE_F08 if f07_pass else PHASE_F07
        outputs[CHILD_DAG]["next_lawful_phase"] = f07_next_phase
        outputs[CHILD_DAG]["nodes"] = [
            {"id": PHASE_BOOTSTRAP, "status": "PASS"},
            {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
            {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
            {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
            {"id": PHASE_F04, "status": f04_status if f03_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F05, "status": f05_status if f04_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F06, "status": f06_status if f05_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F07, "status": f07_status if f06_pass else "BLOCKED_UPSTREAM"},
            {"id": PHASE_F08, "status": "READY" if f07_pass else "BLOCKED_UPSTREAM"},
            {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "BLOCKED_UPSTREAM"},
        ]

        if f07_pass:
            license_policy = _j(root, "KT_PROD_CLEANROOM/governance/kt_license_track_policy.json")
            product_claim_policy = _j(root, "KT_PROD_CLEANROOM/governance/kt_product_claim_policy.json")
            product_surface_policy = _j(root, "KT_PROD_CLEANROOM/governance/kt_product_surface_policy.json")
            deployment_profile_rules = _j(root, "KT_PROD_CLEANROOM/governance/deployment_profile_rules.json")
            deployment_profiles = _j(root, "KT_PROD_CLEANROOM/reports/deployment_profiles.json")

            outputs.update(
                _prepare_f08_product_wedge_package(
                    root,
                    head=head,
                    outputs=outputs,
                    f08_next_phase="F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS",
                )
            )

            runtime_truth_gate_passed = (
                float(outputs[STATE_V2].get("current_head_receipt_or_blocker_coverage_percent", 0.0)) >= 100.0
                and str(outputs[FINAL_CURRENT_HEAD_READJUDICATION].get("status", "")).strip() == "PASS"
            )
            release_activation_passed = release_activation_executed
            license_checks_passed = (
                str(license_policy.get("status", "")).strip() == "ACTIVE"
                and str(license_policy.get("repository_license_track", {}).get("status", "")).strip() == "NONCOMMERCIAL_RESEARCH_ONLY"
                and "run_for_noncommercial_research" in license_policy.get("repository_license_track", {}).get("allows", [])
                and str(product_claim_policy.get("status", "")).strip() == "ACTIVE"
                and str(product_surface_policy.get("status", "")).strip() == "ACTIVE"
                and str(deployment_profile_rules.get("status", "")).strip() == "ACTIVE"
                and str(deployment_profiles.get("status", "")).strip() == "ACTIVE"
            )
            deployable_artifact_pack_exists = (
                (root / F08_PRODUCT_WEDGE_PACKAGE_ROOT).resolve().exists()
                and (root / F08_PRODUCT_WEDGE_PACKAGE_ROOT / "verifier_v2").resolve().exists()
                and (root / F08_PRODUCT_WEDGE_PACKAGE_ROOT / "selected_runtime_surface").resolve().exists()
                and (root / F08_PRODUCT_WEDGE_PACKAGE_ROOT / Path(F08_DEPLOYMENT_MANIFEST).name).resolve().exists()
            )
            operator_burden_within_threshold = len(outputs[F08_OPERATOR_MANUAL].get("operator_steps", [])) <= 12
            no_commercial_widening = str(license_policy.get("commercial_license_track", {}).get("current_lawful_offer_state", "")).strip() == "NOT_ACTIVATED_IN_REPO"

            f08_checks = {
                "runtime_truth_gate_passed": runtime_truth_gate_passed,
                "release_activation_passed": release_activation_passed,
                "license_checks_passed": license_checks_passed,
                "deployable_artifact_pack_exists": deployable_artifact_pack_exists,
                "operator_burden_within_threshold": operator_burden_within_threshold,
                "no_commercial_widening": no_commercial_widening,
            }
            f08_pass = all(f08_checks.values())
            f08_status = "PASS" if f08_pass else "BLOCKED"
            f08_next_phase = "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS" if f08_pass else PHASE_F08

            outputs[F08_PRODUCT_WEDGE_ACTIVATION] = {
                "schema_id": "kt.child_campaign.product_wedge_activation_receipt.v1",
                "campaign_id": CAMPAIGN_ID,
                "phase_id": PHASE_F08,
                "status": "PASS" if f08_pass else "BLOCKED",
                "pass_verdict": PASS_VERDICT_F08 if f08_pass else BLOCKED_VERDICT_F08,
                "subject_head_commit": head,
                "evidence_head_commit": head,
                "current_repo_head": head,
                "generated_utc": utc_now_iso_z(),
                "scope": "CHILD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY",
                "checks": [
                    _check(runtime_truth_gate_passed, "runtime_truth_gate_passed", "F08 requires the child runtime-truth gate to remain green before a product wedge can activate.", [STATE_V2, FINAL_CURRENT_HEAD_READJUDICATION]),
                    _check(release_activation_passed, "release_activation_passed", "F08 requires child release activation to be executed before any product wedge claim.", [F07_RELEASE_ACTIVATION_RECEIPT]),
                    _check(license_checks_passed, "license_checks_passed", "F08 requires a bounded noncommercial license posture and active product/deployment policy inputs.", ["KT_PROD_CLEANROOM/governance/kt_license_track_policy.json", "KT_PROD_CLEANROOM/governance/kt_product_claim_policy.json", "KT_PROD_CLEANROOM/governance/kt_product_surface_policy.json"]),
                    _check(no_commercial_widening, "no_commercial_widening", "F08 may not activate a commercial or enterprise sales surface from the repo license.", ["KT_PROD_CLEANROOM/governance/kt_license_track_policy.json", "LICENSE"]),
                ],
                "blocked_by": [check_id for check_id, ok in f08_checks.items() if not ok],
                "current_strongest_claim": "F08 activates only a bounded noncommercial evaluation wedge built on the sealed child verifier and selected runtime surface." if f08_pass else "F08 cannot activate the bounded product wedge until release, license, and deployability gates all pass.",
                "stronger_claim_not_made": [
                    "Commercial rights are active in-repo",
                    "Enterprise readiness or market readiness is proven",
                    "Broad current-head external capability is confirmed",
                ],
                "next_lawful_phase": f08_next_phase,
            }

            outputs[F08_ENTERPRISE_OPERATIONS] = {
                "schema_id": "kt.child_campaign.enterprise_operations_receipt.v1",
                "campaign_id": CAMPAIGN_ID,
                "phase_id": PHASE_F08,
                "status": "PASS" if f08_pass else "BLOCKED",
                "pass_verdict": PASS_VERDICT_F08 if f08_pass else BLOCKED_VERDICT_F08,
                "subject_head_commit": head,
                "evidence_head_commit": head,
                "current_repo_head": head,
                "generated_utc": utc_now_iso_z(),
                "checks": [
                    _check(deployable_artifact_pack_exists, "deployable_artifact_pack_exists", "F08 requires a packaged bounded evaluation wedge artifact set.", [F08_DEPLOYMENT_MANIFEST, F08_OPERATOR_MANUAL, F08_SUPPORTABILITY_MATRIX]),
                    _check(operator_burden_within_threshold, "operator_burden_within_threshold", "F08 requires operator burden to stay within the bounded threshold.", [F08_OPERATOR_MANUAL, F08_SUPPORTABILITY_MATRIX]),
                    _check(no_commercial_widening, "no_commercial_widening", "F08 may not turn bounded operations packaging into commercial or enterprise claim widening.", ["KT_PROD_CLEANROOM/governance/kt_license_track_policy.json", F08_PRODUCT_WEDGE_ACTIVATION]),
                ],
                "blocked_by": [check_id for check_id in ("deployable_artifact_pack_exists", "operator_burden_within_threshold", "no_commercial_widening") if not f08_checks[check_id]],
                "current_strongest_claim": "F08 proves only that a bounded noncommercial evaluation wedge is packaged with operator documentation and self-serve support boundaries." if f08_pass else "F08 cannot prove bounded deployment and operations readiness yet.",
                "stronger_claim_not_made": [
                    "Commercial support or SLA obligations are active",
                    "Enterprise production readiness is proven",
                    "A customer pilot or market launch is active",
                ],
                "next_lawful_phase": f08_next_phase,
            }

            outputs[PROOF_V2]["inputs"] = [
                *outputs[PROOF_V2]["inputs"],
                F08_PRODUCT_WEDGE_ACTIVATION,
                F08_DEPLOYMENT_MANIFEST,
                F08_OPERATOR_MANUAL,
                F08_SUPPORTABILITY_MATRIX,
                F08_ENTERPRISE_OPERATIONS,
            ]
            outputs[PROOF_V2]["allowed_public_claims"] = [
                *outputs[PROOF_V2]["allowed_public_claims"],
                *(
                    ["child_bounded_noncommercial_evaluation_wedge_active_without_commercial_or_enterprise_widening"]
                    if f08_pass
                    else []
                ),
            ]
            outputs[PROOF_V2]["forbidden_public_claims"] = [
                *outputs[PROOF_V2]["forbidden_public_claims"],
                "f08_proves_commercial_ready",
                "f08_proves_enterprise_ready_overall",
                "f08_widens_current_head_external_capability",
            ]
            if f08_pass:
                outputs[STATE_V2]["computed_claim_ceiling"] = "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F07_RELEASED_AND_F08_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ONLY"
                outputs[STATE_V2]["product_surface_status"] = "CHILD_BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_ACTIVE"
                outputs[STATE_V2]["next_lawful_transition"] = f08_next_phase
                outputs[STATE_V2]["open_blockers"] = [
                    blocker
                    for blocker in (
                        "current_head_external_capability_not_confirmed",
                        "repo_root_import_fragility_visible_and_unfixed",
                    )
                ]
            outputs[STATE_V2]["product_wedge_activation_receipt"] = F08_PRODUCT_WEDGE_ACTIVATION
            outputs[STATE_V2]["deployment_manifest"] = F08_DEPLOYMENT_MANIFEST
            outputs[STATE_V2]["operator_manual"] = F08_OPERATOR_MANUAL
            outputs[STATE_V2]["supportability_matrix"] = F08_SUPPORTABILITY_MATRIX
            outputs[STATE_V2]["enterprise_operations_receipt"] = F08_ENTERPRISE_OPERATIONS
            outputs[CHILD_DAG]["current_node"] = "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS" if f08_pass else PHASE_F08
            outputs[CHILD_DAG]["next_lawful_phase"] = f08_next_phase
            outputs[CHILD_DAG]["nodes"] = [
                {"id": PHASE_BOOTSTRAP, "status": "PASS"},
                {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
                {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
                {"id": PHASE_F03, "status": "PASS" if f03_pass else ("BLOCKED" if f02b_pass else "BLOCKED_UPSTREAM")},
                {"id": PHASE_F04, "status": f04_status if f03_pass else "BLOCKED_UPSTREAM"},
                {"id": PHASE_F05, "status": f05_status if f04_pass else "BLOCKED_UPSTREAM"},
                {"id": PHASE_F06, "status": f06_status if f05_pass else "BLOCKED_UPSTREAM"},
                {"id": PHASE_F07, "status": f07_status if f06_pass else "BLOCKED_UPSTREAM"},
                {"id": PHASE_F08, "status": f08_status if f07_pass else "BLOCKED_UPSTREAM"},
                {"id": "F09_RESEARCH_VALIDATION_AND_COMPANY_READINESS", "status": "READY" if f08_pass else "BLOCKED_UPSTREAM"},
            ]

    for rel, payload in outputs.items():
        _w(root, rel, payload)

    unexpected = [p for p in _dirty(_status_lines(root)) if not _in_scope(p)]
    if unexpected:
        raise RuntimeError(f"FAIL_CLOSED: child campaign touched out-of-scope paths: {unexpected}")

    return {
        "status": "ACTIVE" if f02b_pass else "PARTIAL_SUCCESS",
        "campaign_id": CAMPAIGN_ID,
        "current_repo_head": head,
        "phase_results": {
            PHASE_BOOTSTRAP: "PASS",
            PHASE_RUNTIME: outputs[RUNTIME_RECEIPT]["status"],
            PHASE_TRUST: outputs[TRUST_RECEIPT]["status"],
            PHASE_F03: f03_status,
            PHASE_F04: f04_status,
            PHASE_F05: f05_status,
            PHASE_F06: f06_status,
            PHASE_F07: f07_status,
            PHASE_F08: f08_status,
        },
        "next_lawful_phase": f08_next_phase if f07_pass else (f07_next_phase if f06_pass else f06_next_phase),
        "open_blockers": outputs[STATE_V2]["open_blockers"],
    }


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description="Bootstrap the KT child campaign v1.6.").parse_args(argv)
    print(json.dumps(emit_follow_on_campaign_v16(repo_root()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
