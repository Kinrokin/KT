from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


CAMPAIGN_ID = "KT_SINGLE_PROJECT_INSTITUTIONAL_ELEVATION_V1_6"
PHASE_BOOTSTRAP = "F01_LINEAGE_LAW_AND_SUPERSESSION_REPAIR"
PHASE_RUNTIME = "F02A_RUNTIME_REALITY_AND_CURRENT_HEAD_BASELINE"
PHASE_TRUST = "F02B_TRUST_ROOT_TRANSPARENCY_AND_TUF_ACTIVATION"
PHASE_F03 = "F03_PROOF_REPRO_HARDENING_AND_STABILITY"
BLOCKED_VERDICT_TRUST = "TRUST_ACTIVATION_BLOCKED_BY_PRESERVED_PARENT_GAPS"
PASS_VERDICT_TRUST = "THRESHOLD_ROOT_ACCEPTANCE_AND_CHILD_TUF_DISTRIBUTION_ACTIVE"

REPORT = "KT_PROD_CLEANROOM/reports"
GOV = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/follow_on_campaign_v16_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_follow_on_campaign_v16_validate.py"

PARENT_DAG = f"{GOV}/kt_execution_dag.json"
PARENT_FINAL = f"{REPORT}/kt_final_readjudication_receipt.json"
PARENT_PRODUCT = f"{REPORT}/kt_product_surface_receipt.json"
OLD_STATE = f"{REPORT}/kt_state_vector.json"
OLD_PROOF = f"{REPORT}/kt_claim_proof_ceiling_compiler.json"
TRUST_ROOT = f"{GOV}/kt_trust_root_policy.json"
SIGNER_TOPOLOGY = f"{GOV}/kt_signer_topology.json"
RELEASE = f"{GOV}/kt_release_ceremony.json"
DETERMINISM = f"{GOV}/kt_determinism_envelope_policy.json"
IDENTITY_MODEL = f"{GOV}/kt_identity_model_policy.json"
LOG_MONITOR_POLICY = f"{GOV}/kt_log_monitor_policy.json"
THRESHOLD_POLICY = f"{GOV}/kt_threshold_root_acceptance_policy.json"
TUF_POLICY = f"{GOV}/kt_tuf_distribution_policy.json"
WS11 = f"{REPORT}/kt_sigstore_integration_receipt.json"
WS12 = f"{REPORT}/kt_supply_chain_policy_receipt.json"
WS14 = f"{REPORT}/kt_public_verifier_release_receipt.json"
WS17A = f"{REPORT}/kt_external_assurance_confirmation_receipt.json"
WS17B = f"{REPORT}/kt_external_capability_confirmation_receipt.json"
WS19_DETACHED = f"{REPORT}/kt_public_verifier_detached_receipt.json"
TUF_ROOT_INIT = f"{REPORT}/kt_tuf_root_initialization.json"
LOG_MONITOR = f"{REPORT}/kt_log_monitor_plane_receipt.json"

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

PLANNED = {
    TOOL_REL,
    TEST_REL,
    CHILD_DAG,
    SINGLE_REALITY,
    PROOF_V2,
    THRESHOLD_POLICY,
    TUF_POLICY,
    STATE_V2,
    BLOCKERS_V2,
    RUNTIME_MATRIX,
    BENCHMARK_MATRIX,
    THEATER_MATRIX,
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

    outputs = {
        CHILD_DAG: {
            "schema_id": "kt.child_campaign.execution_dag.v1_6",
            "campaign_id": CAMPAIGN_ID,
            "status": "ACTIVE",
            "current_repo_head": head,
            "campaign_execution_state": "ACTIVE" if f02b_pass else "PARTIAL_SUCCESS",
            "current_node": PHASE_F03 if f02b_pass else PHASE_TRUST,
            "next_lawful_phase": PHASE_F03 if f02b_pass else PHASE_TRUST,
            "nodes": [
                {"id": PHASE_BOOTSTRAP, "status": "PASS"},
                {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
                {"id": PHASE_TRUST, "status": "PASS" if f02b_pass else "BLOCKED"},
                {"id": PHASE_F03, "status": "READY" if f02b_pass else "BLOCKED_UPSTREAM"},
                {"id": "F04_ADJUDICATION_VERIFIER_V2_AND_OUTSIDER_PATH", "status": "BLOCKED_UPSTREAM"},
                {"id": "F05_ORGAN_ELEVATION_AND_RUNTIME_PROMOTION", "status": "BLOCKED_UPSTREAM"},
                {"id": "F06_EXTERNAL_CONFIRMATION_AND_FINAL_CURRENT_HEAD_READJUDICATION", "status": "BLOCKED_UPSTREAM"},
                {"id": "F07_RELEASE_READINESS_ELIGIBILITY_CEREMONY_AND_ACTIVATION", "status": "BLOCKED_UPSTREAM"},
                {"id": "F08_PRODUCT_WEDGE_ENTERPRISE_DEPLOYMENT_AND_OPERATIONS_READY", "status": "BLOCKED_UPSTREAM"},
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
            "inputs": [STATE_V2, BLOCKERS_V2, PARENT_FINAL, TRUST_ROOT, RELEASE, THRESHOLD_POLICY, TUF_POLICY],
            "allowed_public_claims": [
                "threshold_root_verifier_acceptance_active_for_child_scoped_verifier_distribution_surfaces_only",
                "child_tuf_distribution_active_for_minimal_verifier_bundle_set_only",
            ] if f02b_pass else [],
            "forbidden_public_claims": [
                "current_head_external_capability_world_class",
                "release_readiness_proven",
                "release_activation_executed",
                "campaign_completion_proven",
                "threshold_root_verifier_acceptance_active_beyond_child_scoped_verifier_distribution_surfaces",
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
        STATE_V2: {
            "schema_id": "kt.child_campaign.state_vector.v2",
            "computed_state_id": f"kt_state_vector_v2::{head}",
            "single_reality_id": "KT_SINGLE_REALITY_LAW_V1_20260318",
            "campaign_id": CAMPAIGN_ID,
            "current_repo_head": head,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "parent_terminal_state_ref": PARENT_PRODUCT,
            "computed_claim_ceiling": "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_F02B_TRUST_ACTIVATION_ONLY" if f02b_pass else "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_BOOTSTRAP_AND_RUNTIME_BASELINE_ONLY",
            "blocker_matrix": BLOCKERS_V2,
            "trust_root_status": "CHILD_THRESHOLD_ROOT_ACCEPTANCE_ACTIVE" if f02b_pass else "RERATIFIED_3_OF_3_ROOT_EXECUTED_THRESHOLD_ACCEPTANCE_STILL_INACTIVE",
            "verifier_status": "CHILD_THRESHOLD_ROOT_ACCEPTANCE_AND_MINIMAL_TUF_DISTRIBUTION_ACTIVE" if f02b_pass else "BOUNDED_STATIC_VERIFIER_BOOTSTRAP_ROOT_ONLY",
            "release_readiness_status": "NOT_PROVEN",
            "release_eligibility_status": "NOT_ELIGIBLE",
            "release_ceremony_status": "NON_EXECUTED_BLOCKED_BY_PREREQUISITES",
            "release_activation_status": "NON_EXECUTED",
            "reproducibility_status": "DECLARED_CLASS_A_CLASS_B_ONLY",
            "product_surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
            "external_confirmation_status": "CURRENT_HEAD_ASSURANCE_ONLY_AND_HISTORICAL_CAPABILITY_ONLY",
            "next_lawful_transition": PHASE_F03 if f02b_pass else PHASE_TRUST,
            "last_update_time": utc_now_iso_z(),
            "runtime_truth_matrix": RUNTIME_MATRIX,
            "doctrine_only_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] == "doctrinal_only"],
            "stubbed_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] == "stubbed"],
            "live_capability_surfaces": [row["surface_id"] for row in rows if row["inventory_class"] in {"live_unbenchmarked", "live_benchmarked"}],
            "benchmark_coverage_matrix": BENCHMARK_MATRIX,
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
        },
        "next_lawful_phase": PHASE_F03 if f02b_pass else PHASE_TRUST,
        "open_blockers": active_blockers,
    }


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description="Bootstrap the KT child campaign v1.6.").parse_args(argv)
    print(json.dumps(emit_follow_on_campaign_v16(repo_root()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
