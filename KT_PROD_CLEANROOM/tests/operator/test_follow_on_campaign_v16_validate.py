from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.follow_on_campaign_v16_validate import (  # noqa: E402
    ADJUDICATION_PACKET,
    ADJUDICATION_SPLIT_RECEIPT,
    AIRLOCK_RECEIPT,
    ARTIFACT_CLASS,
    BENCHMARK_MATRIX,
    BLOCKERS_V2,
    BOOTSTRAP_RECEIPT,
    CHILD_DAG,
    CURRENT_HEAD_CAPABILITY_MATRIX,
    CROSS_HOST_RECEIPT,
    DEPENDENCY_VALIDATION,
    DRIFT_RECEIPT,
    IDENTITY_MODEL,
    LOG_MONITOR,
    OLD_PROOF,
    OLD_STATE,
    PARENT_DAG,
    PARENT_FINAL,
    PARENT_PRODUCT,
    PHASE_F06,
    PHASE_F03,
    PHASE_F04,
    PHASE_F05,
    PHASE_RUNTIME,
    PHASE_TRUST,
    ORGAN_ELEVATION_RECEIPT,
    ORGAN_PROMOTION_MATRIX,
    OUTSIDER_PATH_RECEIPT,
    OUTSIDER_TEST_REL,
    OUTSIDER_TOOL_REL,
    PIPELINE_RECEIPT,
    PROOF_SUPERSEDE,
    PROOF_V2,
    RELEASE,
    REGRESSION_MATRIX,
    RUNTIME_MATRIX,
    RUNTIME_RECEIPT,
    SINGLE_REALITY,
    STATE_STALE,
    STATE_SUPERSEDE,
    STATE_V2,
    STATIC_BUNDLE_ATTESTATION,
    STATIC_BUNDLE_MANIFEST,
    STATIC_BUNDLE_SBOM,
    SLSA_RECEIPT,
    TEST_REL,
    THEATER_MATRIX,
    THRESHOLD_POLICY,
    TUF_POLICY,
    TUF_ROOT_INIT,
    TOOL_REL,
    TRUST_RECEIPT,
    TRUST_ROOT,
    WS11,
    WS12,
    WS13,
    WS14,
    WS17A,
    WS17B,
    WS19_DETACHED,
    VERIFIER_V2_MANIFEST,
    VERIFIER_V2_VSA,
    emit_follow_on_campaign_v16,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _touch(path: Path, text: str = "seed\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _git(tmp_path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True, encoding="utf-8").strip()


def _commit_all(tmp_path: Path, message: str) -> str:
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", message)
    return _git(tmp_path, "rev-parse", "HEAD")


def _init_git_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")


def _seed_runtime(tmp_path: Path) -> None:
    for rel in [
        "KT_PROD_CLEANROOM/tools/router/run_router_hat_demo.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py",
        "KT_PROD_CLEANROOM/tests/operator/test_paradox_verification_compile.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/tests/test_multiverse_engine.py",
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_adapters.py",
        "KT_PROD_CLEANROOM/tools/tournament/run_tournament.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py",
        "KT_PROD_CLEANROOM/tests/fl3/test_fl4_promotion_atomic.py",
    ]:
        _touch(tmp_path / rel)
    _write_json(tmp_path / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json", {"schema_id": "kt.runtime_registry.v1", "adapters": {"entries": []}})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/adapter_registry.json", {"schema_id": "kt.adapter_registry.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/router_policy_registry.json", {"schema_id": "kt.router_policy_registry.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/tournament_law.json", {"schema_id": "kt.tournament_law.v1"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_paradox_invariants.json", {"schema_id": "seed", "status": "ACTIVE"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_adapter_testing_gate_receipt.json", {"schema_id": "seed", "status": "PASS"})


def _seed_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    source_root = Path(__file__).resolve().parents[2]
    for rel in [
        TOOL_REL,
        OUTSIDER_TOOL_REL,
        "KT_PROD_CLEANROOM/tools/operator/dependency_inventory_emit.py",
        "KT_PROD_CLEANROOM/tools/operator/dependency_inventory_validate.py",
        "KT_PROD_CLEANROOM/tools/operator/titanium_common.py",
    ]:
        source = source_root / Path(rel).relative_to("KT_PROD_CLEANROOM")
        if rel.startswith("KT_PROD_CLEANROOM/"):
            source = source_root / Path(rel.replace("KT_PROD_CLEANROOM/", "", 1))
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    (tmp_path / TEST_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / TEST_REL).write_text("seed\n", encoding="utf-8", newline="\n")
    (tmp_path / OUTSIDER_TEST_REL).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / OUTSIDER_TEST_REL).write_text("seed\n", encoding="utf-8", newline="\n")
    _seed_runtime(tmp_path)
    _write_json(tmp_path / PARENT_DAG, {"schema_id": "kt.governance.execution_dag.v1", "status": "ACTIVE", "campaign_completion_status": "STILL_BLOCKED", "next_lawful_workstream": None})
    _write_json(tmp_path / PARENT_FINAL, {"schema_id": "kt.operator.ws18.final_readjudication_receipt.v1", "status": "PASS", "final_verdict": {"current_head_capability_status": "NOT_EXTERNALLY_CONFIRMED", "release_eligibility": "NOT_ELIGIBLE"}})
    _write_json(tmp_path / PARENT_PRODUCT, {"schema_id": "kt.operator.ws19.product_surface_receipt.v1", "status": "PASS", "campaign_completion_status": "STILL_BLOCKED", "next_lawful_workstream": None})
    _write_json(tmp_path / OLD_STATE, {"schema_id": "kt.operator.state_vector.v1", "state_vector_id": "legacy", "adjudication_status": "PRE_ADJUDICATION_PENDING_STEP_12"})
    _write_json(tmp_path / OLD_PROOF, {"schema_id": "kt.operator.claim_proof_ceiling_compiler.v1", "status": "PASS"})
    _write_json(
        tmp_path / TRUST_ROOT,
        {
            "schema_id": "kt.governance.trust_root_policy.v1",
            "status": "EXECUTED_RERATIFIED_3_OF_3",
            "ratified_root_topology": {"target_trust_root_id": "KT_SOVEREIGN_ROOT_TARGET_20260317", "root_threshold": 3},
            "verifier_acceptance_impact": {"post_pass_target_state": "THRESHOLD_ROOT_ACCEPTANCE_STILL_PENDING_LATER_EXPLICIT_BUNDLE"},
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/governance/kt_signer_topology.json",
        {
            "schema_id": "kt.governance.signer_topology.v1",
            "status": "EXECUTED_RERATIFIED_3_OF_3",
            "roles": [{"role_id": "verifier_acceptance", "threshold": 1, "signer_count": 2}],
        },
    )
    _write_json(tmp_path / RELEASE, {"schema_id": "kt.governance.release_ceremony.v1", "status": "ACTIVE_LOCKED_PENDING_EXECUTION_PREREQUISITES"})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json",
        {
            "schema_id": "kt.governance.determinism_envelope_policy.v1",
            "status": "ACTIVE",
            "forbidden_drift": ["unordered directory walks", "wall-clock timestamps inside class-a equality targets"],
            "class_b_canonicalization_profiles": [{"profile_id": "live_validation_index_v1"}],
            "normalization_rules": {"timestamp_policy": {"class_b_canonicalization_strips_wall_clock_fields": True}},
        },
    )
    _write_json(
        tmp_path / ARTIFACT_CLASS,
        {
            "schema_id": "kt.governance.artifact_class_policy.v1",
            "status": "ACTIVE",
            "classes": [
                {
                    "class_id": "CLASS_A",
                    "surfaces": [
                        {"path": ARTIFACT_CLASS},
                        {"path": "KT_PROD_CLEANROOM/governance/kt_determinism_envelope_policy.json"},
                    ],
                }
            ],
        },
    )
    _write_json(
        tmp_path / IDENTITY_MODEL,
        {
            "schema_id": "kt.governance.identity_model_policy.v1",
            "principal_sets": {"verifier_acceptance_maintainers": ["KT_VERIFIER_ACCEPTANCE_A", "KT_VERIFIER_ACCEPTANCE_B"]},
            "current_overlap_scan": [
                {"constraint_id": "root_verifier_acceptance_overlap_forbidden", "status": "PASS"},
                {"constraint_id": "release_verifier_acceptance_overlap_forbidden", "status": "PASS"},
                {"constraint_id": "verifier_acceptance_ci_keyless_overlap_forbidden", "status": "PASS"},
                {"constraint_id": "operator_verifier_acceptance_overlap_forbidden", "status": "PASS"},
            ],
        },
    )
    _write_json(tmp_path / TUF_ROOT_INIT, {"schema_id": "kt.operator.tuf_root_initialization.v1", "status": "PASS", "trust_root_id": "KT_TUF_ROOT_BOOTSTRAP_20260314"})
    _write_json(tmp_path / WS11, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS12, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS14, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS17A, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS17B, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / WS19_DETACHED, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / LOG_MONITOR, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/governance/kt_log_monitor_policy.json", {"schema_id": "seed", "status": "ACTIVE"})
    _write_json(tmp_path / STATIC_BUNDLE_MANIFEST, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / STATIC_BUNDLE_SBOM, {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / STATIC_BUNDLE_ATTESTATION, {"schema_id": "seed", "status": "PASS"})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/source_build_attestation/in_toto_statement.json",
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicate": {"schema_id": "kt.in_toto.predicate.source_build_subject.v1"},
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
        {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicate": {"schema_id": "kt.in_toto.predicate.authority_subject.v1"},
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_build_provenance.dsse", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_verification_summary_attestation.dsse", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_build_verification_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json", {"schema_id": "seed", "status": "PASS"})
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_release_manifest.json",
        {
            "schema_id": "seed",
            "status": "PASS",
            "included_paths": [
                "KT_PROD_CLEANROOM/reports/source_build_attestation/in_toto_statement.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
                "KT_PROD_CLEANROOM/reports/kt_build_provenance.dsse",
                "KT_PROD_CLEANROOM/reports/kt_verification_summary_attestation.dsse",
                "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json",
                "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json",
            ],
            "packaged_input_refs": [
                "KT_PROD_CLEANROOM/reports/source_build_attestation/in_toto_statement.json",
                "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json",
                "KT_PROD_CLEANROOM/reports/kt_build_provenance.dsse",
                "KT_PROD_CLEANROOM/reports/kt_verification_summary_attestation.dsse",
                "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json",
                "KT_PROD_CLEANROOM/reports/kt_sigstore_publication_bundle.json",
            ],
        },
    )
    _write_json(tmp_path / "KT_PROD_CLEANROOM/reports/kt_public_verifier_detached_sbom.json", {"schema_id": "seed", "status": "PASS"})
    _touch(tmp_path / "KT_PROD_CLEANROOM/policy_c/drift_guard.py", "def drift_guard_seed():\n    return 'ok'\n")
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM/policy_c/schemas/policy_c_drift_report_schema_v1.json",
        {
            "schema_id": "kt.policy_c.drift_report.v1",
            "additionalProperties": False,
            "required": [
                "epoch_id",
                "baseline_epoch_id",
                "pressure_delta_l2",
                "pressure_delta_max",
                "invariant_violations",
                "drift_class",
                "reason_codes",
                "timestamp",
            ],
        },
    )
    for rel in [
        "KT_PROD_CLEANROOM/tests/policy_c/test_drift_guard.py",
        "KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_drift_gate.py",
        "KT_PROD_CLEANROOM/tests/policy_c/test_policy_c_drift_schema.py",
    ]:
        _touch(tmp_path / rel, "pass\n")
    base_head = _commit_all(tmp_path, "seed repo base")
    _write_json(
        tmp_path / WS13,
        {
            "schema_id": "kt.operator.ws13.determinism_envelope_receipt.v1",
            "status": "PASS",
            "current_repo_head": base_head,
            "compiled_against": base_head,
            "environments_used": {
                "local": {"environment_class": "local_windows"},
                "ci": {"environment_class": "github_actions_ubuntu"},
            },
            "hash_comparison_results": {
                "deterministic_outputs": [
                    {"artifact": "kt_artifact_class_registry.json", "status": "PASS"},
                    {"artifact": "kt_determinism_envelope_manifest.json", "status": "PASS"},
                ]
            },
        },
    )
    return _commit_all(tmp_path, "seed repo evidence")


def test_child_campaign_f05_passes_with_bounded_runtime_truth_and_promotion_matrix(tmp_path: Path) -> None:
    head = _seed_repo(tmp_path)
    summary = emit_follow_on_campaign_v16(tmp_path)
    assert summary["status"] == "ACTIVE"
    assert summary["current_repo_head"] == head
    assert summary["phase_results"][PHASE_RUNTIME] == "PASS"
    assert summary["phase_results"][PHASE_TRUST] == "PASS"
    assert summary["phase_results"][PHASE_F03] == "PASS"
    assert summary["phase_results"][PHASE_F04] == "PASS"
    assert summary["phase_results"][PHASE_F05] == "PASS"
    assert summary["next_lawful_phase"] == PHASE_F06

    runtime = json.loads((tmp_path / RUNTIME_RECEIPT).read_text(encoding="utf-8"))
    trust = json.loads((tmp_path / TRUST_RECEIPT).read_text(encoding="utf-8"))
    bench = json.loads((tmp_path / BENCHMARK_MATRIX).read_text(encoding="utf-8"))
    state = json.loads((tmp_path / STATE_V2).read_text(encoding="utf-8"))
    pipeline = json.loads((tmp_path / PIPELINE_RECEIPT).read_text(encoding="utf-8"))
    slsa = json.loads((tmp_path / SLSA_RECEIPT).read_text(encoding="utf-8"))
    repro = json.loads((tmp_path / CROSS_HOST_RECEIPT).read_text(encoding="utf-8"))
    airlock = json.loads((tmp_path / AIRLOCK_RECEIPT).read_text(encoding="utf-8"))
    drift = json.loads((tmp_path / DRIFT_RECEIPT).read_text(encoding="utf-8"))
    adjudication = json.loads((tmp_path / ADJUDICATION_PACKET).read_text(encoding="utf-8"))
    split = json.loads((tmp_path / ADJUDICATION_SPLIT_RECEIPT).read_text(encoding="utf-8"))
    outsider = json.loads((tmp_path / OUTSIDER_PATH_RECEIPT).read_text(encoding="utf-8"))
    capability_matrix = json.loads((tmp_path / CURRENT_HEAD_CAPABILITY_MATRIX).read_text(encoding="utf-8"))
    promotion_matrix = json.loads((tmp_path / ORGAN_PROMOTION_MATRIX).read_text(encoding="utf-8"))
    elevation = json.loads((tmp_path / ORGAN_ELEVATION_RECEIPT).read_text(encoding="utf-8"))
    regression = json.loads((tmp_path / REGRESSION_MATRIX).read_text(encoding="utf-8"))
    assert runtime["status"] == "PASS"
    assert trust["status"] == "PASS"
    assert pipeline["status"] == "PASS"
    assert slsa["status"] == "PASS"
    assert repro["status"] == "PASS"
    assert airlock["status"] == "PASS"
    assert drift["status"] == "PASS"
    assert adjudication["status"] == "PASS"
    assert split["status"] == "PASS"
    assert outsider["status"] == "PASS"
    assert capability_matrix["status"] == "PASS"
    assert promotion_matrix["status"] == "PASS"
    assert elevation["status"] == "PASS"
    assert regression["status"] == "PASS"
    assert bench["coverage_percent"] >= 50.0
    assert state["next_lawful_transition"] == PHASE_F06
    assert "threshold_root_verifier_acceptance_inactive" not in state["open_blockers"]
    assert "verifier_coverage_not_widened_beyond_bounded_surfaces" not in state["open_blockers"]
    assert state["reproducibility_status"].startswith("DECLARED_CLASS_A_CARRY_FORWARD_CROSS_HOST_PROVEN")
    assert state["current_head_receipt_or_blocker_coverage_percent"] == 100.0
    assert any(row["surface_id"] == "openclaw_labor_organ" and row["current_head_receipt_status"] == "BLOCKED" for row in capability_matrix["rows"])
    assert any(row["surface_id"] == "adapter_layer" and "STUBBED_SURFACE" in row["promotion_blockers"] for row in promotion_matrix["rows"])

    for rel in [
        CHILD_DAG,
        SINGLE_REALITY,
        PROOF_V2,
        THRESHOLD_POLICY,
        TUF_POLICY,
        BLOCKERS_V2,
        RUNTIME_MATRIX,
        THEATER_MATRIX,
        STATE_STALE,
        STATE_SUPERSEDE,
        PROOF_SUPERSEDE,
        BOOTSTRAP_RECEIPT,
        DEPENDENCY_VALIDATION,
        ADJUDICATION_PACKET,
        ADJUDICATION_SPLIT_RECEIPT,
        VERIFIER_V2_MANIFEST,
        VERIFIER_V2_VSA,
        OUTSIDER_PATH_RECEIPT,
        CURRENT_HEAD_CAPABILITY_MATRIX,
        ORGAN_PROMOTION_MATRIX,
        ORGAN_ELEVATION_RECEIPT,
        REGRESSION_MATRIX,
    ]:
        assert (tmp_path / rel).exists()


def test_child_campaign_f02b_blocks_if_threshold_root_target_missing(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    broken = json.loads((tmp_path / TRUST_ROOT).read_text(encoding="utf-8"))
    broken["ratified_root_topology"] = {"target_trust_root_id": "", "root_threshold": 0}
    _write_json(tmp_path / TRUST_ROOT, broken)
    _commit_all(tmp_path, "break threshold root target")

    summary = emit_follow_on_campaign_v16(tmp_path)
    trust = json.loads((tmp_path / TRUST_RECEIPT).read_text(encoding="utf-8"))
    assert summary["status"] == "PARTIAL_SUCCESS"
    assert summary["phase_results"][PHASE_TRUST] == "BLOCKED"
    assert trust["status"] == "BLOCKED"
    assert "threshold_root_verifier_acceptance_inactive" in trust["blocked_by"]


def test_child_campaign_fails_if_parent_has_illegal_next_workstream(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    broken = json.loads((tmp_path / PARENT_DAG).read_text(encoding="utf-8"))
    broken["next_lawful_workstream"] = "WS20_ILLEGAL_CONTINUATION"
    _write_json(tmp_path / PARENT_DAG, broken)
    _commit_all(tmp_path, "break parent closure")
    try:
        emit_follow_on_campaign_v16(tmp_path)
    except RuntimeError as exc:
        assert "prerequisites are not satisfied" in str(exc)
    else:
        raise AssertionError("expected fail-closed lineage error")


def test_child_campaign_f03_blocks_if_class_a_surfaces_drift(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    drifted = json.loads((tmp_path / ARTIFACT_CLASS).read_text(encoding="utf-8"))
    drifted["status"] = "DRIFTED"
    _write_json(tmp_path / ARTIFACT_CLASS, drifted)
    _commit_all(tmp_path, "drift class-a surface")

    summary = emit_follow_on_campaign_v16(tmp_path)
    repro = json.loads((tmp_path / CROSS_HOST_RECEIPT).read_text(encoding="utf-8"))
    assert summary["phase_results"][PHASE_TRUST] == "PASS"
    assert summary["phase_results"][PHASE_F03] == "BLOCKED"
    assert summary["next_lawful_phase"] == PHASE_F03
    assert repro["status"] == "BLOCKED"
    assert repro["class_a_drift_paths"] == [ARTIFACT_CLASS]


def test_child_campaign_f04_blocks_if_outsider_runtime_source_missing(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    (tmp_path / OUTSIDER_TOOL_REL).unlink()
    _commit_all(tmp_path, "remove outsider verifier source")

    summary = emit_follow_on_campaign_v16(tmp_path)
    split = json.loads((tmp_path / ADJUDICATION_SPLIT_RECEIPT).read_text(encoding="utf-8"))
    assert summary["phase_results"][PHASE_F03] == "PASS"
    assert summary["phase_results"][PHASE_F04] == "BLOCKED"
    assert summary["next_lawful_phase"] == PHASE_F04
    assert split["status"] == "BLOCKED"


def test_child_campaign_f05_blocks_if_bounded_runtime_receipt_disappears(tmp_path: Path) -> None:
    _seed_repo(tmp_path)
    (tmp_path / "KT_PROD_CLEANROOM/reports/kt_paradox_program_bounded_receipt.json").unlink()
    _commit_all(tmp_path, "remove paradox bounded receipt")

    summary = emit_follow_on_campaign_v16(tmp_path)
    elevation = json.loads((tmp_path / ORGAN_ELEVATION_RECEIPT).read_text(encoding="utf-8"))
    promotion = json.loads((tmp_path / ORGAN_PROMOTION_MATRIX).read_text(encoding="utf-8"))
    paradox_row = next(row for row in promotion["rows"] if row["surface_id"] == "paradox")
    assert summary["phase_results"][PHASE_F04] == "PASS"
    assert summary["phase_results"][PHASE_F05] == "BLOCKED"
    assert summary["next_lawful_phase"] == PHASE_F05
    assert elevation["status"] == "BLOCKED"
    assert "NO_CURRENT_HEAD_RECEIPT_BACKING" in paradox_row["promotion_blockers"]
