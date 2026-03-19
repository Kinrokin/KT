from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


CAMPAIGN_ID = "KT_SINGLE_PROJECT_INSTITUTIONAL_ELEVATION_V1_6"
PHASE_BOOTSTRAP = "F01_LINEAGE_LAW_AND_SUPERSESSION_REPAIR"
PHASE_RUNTIME = "F02A_RUNTIME_REALITY_AND_CURRENT_HEAD_BASELINE"
PHASE_TRUST = "F02B_TRUST_ROOT_TRANSPARENCY_AND_TUF_ACTIVATION"
BLOCKED_VERDICT_TRUST = "TRUST_ACTIVATION_BLOCKED_BY_PRESERVED_PARENT_GAPS"

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
WS11 = f"{REPORT}/kt_sigstore_integration_receipt.json"
WS17A = f"{REPORT}/kt_external_assurance_confirmation_receipt.json"
WS17B = f"{REPORT}/kt_external_capability_confirmation_receipt.json"

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

BLOCKERS = [
    "threshold_root_verifier_acceptance_inactive",
    "current_head_external_capability_not_confirmed",
    "release_readiness_not_proven",
    "release_ceremony_not_executed",
    "release_activation_not_executed",
    "verifier_coverage_not_widened_beyond_bounded_surfaces",
    "repo_root_import_fragility_visible_and_unfixed",
]

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


def _profile(cls: str) -> Dict[str, float]:
    return {
        "doctrinal_only": {"theater_risk_score": 1.0, "underexercised_surface_score": 1.0, "narrative_to_runtime_ratio": 4.0},
        "stubbed": {"theater_risk_score": 0.66, "underexercised_surface_score": 0.78, "narrative_to_runtime_ratio": 1.8},
        "live_unbenchmarked": {"theater_risk_score": 0.44, "underexercised_surface_score": 0.58, "narrative_to_runtime_ratio": 0.95},
        "live_benchmarked": {"theater_risk_score": 0.18, "underexercised_surface_score": 0.28, "narrative_to_runtime_ratio": 0.62},
    }[cls]


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
    _j(root, SIGNER_TOPOLOGY)
    _j(root, RELEASE)
    _j(root, DETERMINISM)
    ws11 = _j(root, WS11)
    ws17a = _j(root, WS17A)
    _j(root, WS17B)

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

    blocker_rows = [{"blocker_id": blocker, "status": "OPEN"} for blocker in BLOCKERS]
    threshold_pending = trust_root.get("verifier_acceptance_impact", {}).get("post_pass_target_state") == "THRESHOLD_ROOT_ACCEPTANCE_STILL_PENDING_LATER_EXPLICIT_BUNDLE"
    tuf_present = _exists(root, f"{GOV}/kt_tuf_distribution_policy.json")

    outputs = {
        CHILD_DAG: {
            "schema_id": "kt.child_campaign.execution_dag.v1_6",
            "campaign_id": CAMPAIGN_ID,
            "status": "ACTIVE",
            "current_repo_head": head,
            "campaign_execution_state": "PARTIAL_SUCCESS",
            "current_node": PHASE_TRUST,
            "next_lawful_phase": PHASE_TRUST,
            "nodes": [
                {"id": PHASE_BOOTSTRAP, "status": "PASS"},
                {"id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED"},
                {"id": PHASE_TRUST, "status": "BLOCKED"},
                {"id": "F03_PROOF_REPRO_HARDENING_AND_STABILITY", "status": "BLOCKED_UPSTREAM"},
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
        PROOF_V2: {
            "schema_id": "kt.child_campaign.claim_proof_ceiling_compiler_policy.v2",
            "policy_id": "KT_CHILD_CLAIM_PROOF_CEILING_POLICY_V2_20260318",
            "status": "ACTIVE",
            "current_repo_head": head,
            "slsa_version_normalized": "v1.2",
            "inputs": [STATE_V2, BLOCKERS_V2, PARENT_FINAL, TRUST_ROOT, RELEASE],
            "forbidden_public_claims": [
                "current_head_external_capability_world_class",
                "threshold_root_verifier_acceptance_active",
                "release_readiness_proven",
                "release_activation_executed",
                "campaign_completion_proven",
            ],
            "blocked_by": BLOCKERS,
        },
        RUNTIME_MATRIX: {"schema_id": "kt.child_campaign.runtime_truth_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "surface_rows": rows},
        BENCHMARK_MATRIX: {"schema_id": "kt.child_campaign.benchmark_coverage_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "coverage_percent": bench_cov, "required_minimum_for_f02a_pass": 50, "rows": [{"surface_id": row["surface_id"], "benchmark_status": row["benchmark_status"], "has_current_head_benchmark_evidence": row["benchmark_status"] not in {"NONE", "TEST_ONLY"}} for row in rows]},
        THEATER_MATRIX: {"schema_id": "kt.child_campaign.theater_risk_matrix.v1", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "rows": theater_rows},
        BLOCKERS_V2: {"schema_id": "kt.child_campaign.blocker_matrix.v2", "campaign_id": CAMPAIGN_ID, "status": "ACTIVE", "current_repo_head": head, "open_blockers": BLOCKERS, "rows": blocker_rows},
        STATE_V2: {
            "schema_id": "kt.child_campaign.state_vector.v2",
            "computed_state_id": f"kt_state_vector_v2::{head}",
            "single_reality_id": "KT_SINGLE_REALITY_LAW_V1_20260318",
            "campaign_id": CAMPAIGN_ID,
            "current_repo_head": head,
            "subject_head_commit": head,
            "evidence_head_commit": head,
            "parent_terminal_state_ref": PARENT_PRODUCT,
            "computed_claim_ceiling": "PARENT_BOUNDED_NON_RELEASE_ELIGIBLE_PLUS_CHILD_BOOTSTRAP_AND_RUNTIME_BASELINE_ONLY",
            "blocker_matrix": BLOCKERS_V2,
            "trust_root_status": "RERATIFIED_3_OF_3_ROOT_EXECUTED_THRESHOLD_ACCEPTANCE_STILL_INACTIVE",
            "verifier_status": "BOUNDED_STATIC_VERIFIER_BOOTSTRAP_ROOT_ONLY",
            "release_readiness_status": "NOT_PROVEN",
            "release_eligibility_status": "NOT_ELIGIBLE",
            "release_ceremony_status": "NON_EXECUTED_BLOCKED_BY_PREREQUISITES",
            "release_activation_status": "NON_EXECUTED",
            "reproducibility_status": "DECLARED_CLASS_A_CLASS_B_ONLY",
            "product_surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
            "external_confirmation_status": "CURRENT_HEAD_ASSURANCE_ONLY_AND_HISTORICAL_CAPABILITY_ONLY",
            "next_lawful_transition": PHASE_TRUST,
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
            "open_blockers": BLOCKERS,
        },
        STATE_STALE: {"schema_id": "kt.child_campaign.state_vector_staleness_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "LEGACY_STATE_VECTOR_IDENTIFIED_AS_STALE_PRE_ADJUDICATION_ARTIFACT", "current_repo_head": head, "superseded_artifact": OLD_STATE},
        STATE_SUPERSEDE: {"schema_id": "kt.child_campaign.state_vector_supersession_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_STATE_VECTOR_V2_ESTABLISHED", "current_repo_head": head, "superseded_artifacts": [OLD_STATE], "new_artifact": STATE_V2},
        PROOF_SUPERSEDE: {"schema_id": "kt.child_campaign.claim_proof_ceiling_supersession_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_PROOF_CEILING_POLICY_V2_ESTABLISHED", "current_repo_head": head, "superseded_artifacts": [OLD_PROOF], "new_artifact": PROOF_V2},
        BOOTSTRAP_RECEIPT: {"schema_id": "kt.child_campaign.bootstrap_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_BOOTSTRAP, "status": "PASS", "pass_verdict": "CHILD_CAMPAIGN_BOOTSTRAPPED_WITH_SINGLE_REALITY_STATE_CORE_V2", "subject_head_commit": head, "evidence_head_commit": head, "current_repo_head": head, "generated_utc": utc_now_iso_z(), "checks": checks, "next_lawful_phase": PHASE_RUNTIME},
        RUNTIME_RECEIPT: {"schema_id": "kt.child_campaign.current_head_capability_baseline_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_RUNTIME, "status": "PASS" if cap_cov >= 60.0 and bench_cov >= 50.0 else "BLOCKED", "pass_verdict": "CURRENT_HEAD_RUNTIME_BASELINE_CLASSIFIED_AND_BOUNDED" if cap_cov >= 60.0 and bench_cov >= 50.0 else "CURRENT_HEAD_RUNTIME_BASELINE_INCOMPLETE", "subject_head_commit": head, "evidence_head_commit": head, "current_repo_head": head, "generated_utc": utc_now_iso_z(), "current_head_capability_coverage_percent": cap_cov, "benchmark_coverage_percent": bench_cov, "next_lawful_phase": PHASE_TRUST},
        TRUST_RECEIPT: {"schema_id": "kt.child_campaign.f02b_trust_activation_receipt.v1", "campaign_id": CAMPAIGN_ID, "phase_id": PHASE_TRUST, "status": "BLOCKED", "pass_verdict": BLOCKED_VERDICT_TRUST, "subject_head_commit": head, "evidence_head_commit": head, "current_repo_head": head, "generated_utc": utc_now_iso_z(), "checks": [_check(_j(root, WS11).get("status") == "PASS", "sigstore_and_rekor_path_active", "The bounded WS11 path remains active.", [WS11]), _check(_j(root, WS17A).get("status") == "PASS", "outsider_secret_free_assurance_exists", "A secret-free outsider assurance replay exists.", [WS17A]), _check(not threshold_pending, "threshold_root_acceptance_active", "F02B requires threshold-root acceptance to be active.", [TRUST_ROOT]), _check(tuf_present, "tuf_distribution_scope_active", "F02B requires an explicit TUF distribution policy.", [GOV])], "blocked_by": ["threshold_root_verifier_acceptance_inactive", "release_readiness_not_proven", "verifier_coverage_not_widened_beyond_bounded_surfaces"], "next_lawful_phase": PHASE_TRUST},
    }

    for rel, payload in outputs.items():
        _w(root, rel, payload)

    unexpected = [p for p in _dirty(_status_lines(root)) if not _in_scope(p)]
    if unexpected:
        raise RuntimeError(f"FAIL_CLOSED: child campaign touched out-of-scope paths: {unexpected}")

    return {"status": "PARTIAL_SUCCESS", "campaign_id": CAMPAIGN_ID, "current_repo_head": head, "phase_results": {PHASE_BOOTSTRAP: "PASS", PHASE_RUNTIME: outputs[RUNTIME_RECEIPT]["status"], PHASE_TRUST: "BLOCKED"}, "next_lawful_phase": PHASE_TRUST, "open_blockers": BLOCKERS}


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description="Bootstrap the KT child campaign v1.6.").parse_args(argv)
    print(json.dumps(emit_follow_on_campaign_v16(repo_root()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
