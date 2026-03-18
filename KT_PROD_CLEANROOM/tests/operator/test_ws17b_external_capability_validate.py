from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.ws17b_external_capability_validate import (  # noqa: E402
    BENCHMARK_WINDOWS_REL,
    BUILD_VERIFICATION_RECEIPT_REL,
    COMPARATOR_REGISTRY_REL,
    DETACHED_VERIFIER_RECEIPT_REL,
    EXECUTION_DAG_REL,
    EXTERNAL_REPRODUCTION_RECEIPT_REL,
    FORMAL_INVARIANT_RECEIPT_REL,
    FRONTIER_PACKET_REL,
    FRONTIER_SCORECARD_REL,
    HISTORICAL_CAPABILITY_SUBJECT,
    IMPORT_MANIFEST_REL,
    NEXT_WORKSTREAM_ON_PASS,
    OPERATOR_GREENLINE_RECEIPT_REL,
    PASS_VERDICT,
    PUBLIC_HORIZON_RECEIPT_REL,
    READJUDICATION_RECEIPT_REL,
    RED_TEAM_RESULTS_REL,
    REPLAY_REPORT_REL,
    REPO_HYGIENE_RECEIPT_REL,
    REVISION_TRUST_RECEIPT_REL,
    TEST_REL,
    TOOL_REL,
    WS12_CLOSURE_RECEIPT_REL,
    WS12_FINAL_BUNDLE_REL,
    WS15_AUTHORITY_VERDICT_REL,
    WS15_CANONICAL_HMAC_VERDICT_REL,
    WS15_STATUS_VERDICT_REL,
    WS16_RECEIPT_REL,
    WS17A_RECEIPT_REL,
    emit_ws17b_external_capability,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
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


def _seed_ws17b_repo(tmp_path: Path) -> str:
    _init_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("seed\n", encoding="utf-8")
    tool_source = Path(__file__).resolve().parents[2] / "tools/operator/ws17b_external_capability_validate.py"
    _write_text(tmp_path / TOOL_REL, tool_source.read_text(encoding="utf-8"))
    _write_text(tmp_path / TEST_REL, "seed\n")
    frozen_head = _commit_all(tmp_path, "freeze ws17a boundary")

    _write_json(
        tmp_path / COMPARATOR_REGISTRY_REL,
        {
            "schema_id": "kt.governance.comparator_registry.v1",
            "status": "ACTIVE",
            "comparators": [
                {"comparator_id": "sha256_exact_file_match_v1"},
                {"comparator_id": "subject_head_equality_v1"},
                {"comparator_id": "freshness_window_fail_closed_v1"},
                {"comparator_id": "worst_case_pack_status_v1"},
            ],
        },
    )
    _write_json(
        tmp_path / BENCHMARK_WINDOWS_REL,
        {
            "schema_id": "kt.governance.benchmark_validity_windows.v1",
            "status": "ACTIVE",
            "windows": [
                {"window_id": "local_truth_barrier_current_head", "requires_subject_binding": True, "staleness_action": "FAIL_CLOSED"},
                {"window_id": "ci_truth_barrier_current_head", "requires_subject_binding": True, "staleness_action": "FAIL_CLOSED"},
            ],
        },
    )
    _write_json(
        tmp_path / WS16_RECEIPT_REL,
        {
            "schema_id": "kt.operator.tevv_dataset_registry_receipt.v1",
            "status": "PASS",
            "generated_utc": "2026-03-18T05:45:00Z",
            "checks": [{"check": "current_head_truth_rows_within_validity_windows", "status": "PASS"}],
        },
    )
    _write_json(
        tmp_path / WS17A_RECEIPT_REL,
        {
            "schema_id": "kt.operator.ws17a.external_assurance_confirmation_receipt.v1",
            "status": "PASS",
            "generated_utc": "2026-03-18T09:18:43Z",
            "assurance_only_not_capability": True,
        },
    )
    _write_json(
        tmp_path / FRONTIER_PACKET_REL,
        {
            "schema_id": "kt.operator.frontier_audit_packet.v1",
            "sealed_subject_anchor_commit": HISTORICAL_CAPABILITY_SUBJECT,
            "evaluated_repo_head_commit": "0cf1ccdde5a5543678daffe9e60284c903b911ab",
        },
    )
    _write_json(
        tmp_path / FRONTIER_SCORECARD_REL,
        {
            "schema_id": "kt.operator.frontier_rerun_scorecard.v1",
            "sealed_subject_anchor_commit": HISTORICAL_CAPABILITY_SUBJECT,
            "evaluated_repo_head_commit": "0cf1ccdde5a5543678daffe9e60284c903b911ab",
            "target_checks": [{"target_id": "repo_hygiene", "status": "PASS"}],
            "hard_stop_checks": [{"condition_id": "critical_ci_remains_red_after_recovery_workstream", "status": "PASS"}],
            "final_readjudication": {"status": "PASS", "frontier_posture": "BOUNDED_SOTA_A", "overall_bounded_system_grade": "A"},
        },
    )
    _write_json(
        tmp_path / READJUDICATION_RECEIPT_REL,
        {
            "schema_id": "kt.operator.sota_readjudication_receipt.v1",
            "status": "PASS",
            "pass_verdict": "BOUNDED_SOTA_ON_LIVE_AUDITED_TARGET_PROVEN",
            "subject_head_commit": HISTORICAL_CAPABILITY_SUBJECT,
            "evidence_head_commit": HISTORICAL_CAPABILITY_SUBJECT,
            "questions": {
                "what_final_audited_target_was_rerun": {
                    "evaluated_repo_head_commit": "0cf1ccdde5a5543678daffe9e60284c903b911ab"
                }
            },
        },
    )
    for rel, schema_id in [
        (PUBLIC_HORIZON_RECEIPT_REL, "kt.operator.public_horizon_receipt.v1"),
        (RED_TEAM_RESULTS_REL, "kt.operator.red_team_results_receipt.v1"),
        (FORMAL_INVARIANT_RECEIPT_REL, "kt.operator.formal_invariant_receipt.v1"),
        (EXTERNAL_REPRODUCTION_RECEIPT_REL, "kt.operator.external_reproduction_receipt.v1"),
        (DETACHED_VERIFIER_RECEIPT_REL, "kt.operator.public_verifier_detached_receipt.v1"),
        (BUILD_VERIFICATION_RECEIPT_REL, "kt.operator.build_verification_receipt.v1"),
        (REVISION_TRUST_RECEIPT_REL, "kt.operator.revision_trust_receipt.v1"),
    ]:
        _write_json(tmp_path / rel, {"schema_id": schema_id, "status": "PASS", "subject_head_commit": HISTORICAL_CAPABILITY_SUBJECT})
    _write_json(tmp_path / REPO_HYGIENE_RECEIPT_REL, {"schema_id": "kt.operator.repo_hygiene_receipt.v1", "status": "PASS"})
    _write_json(tmp_path / OPERATOR_GREENLINE_RECEIPT_REL, {"schema_id": "kt.operator.operator_greenline_receipt.v1", "status": "PASS"})
    _write_json(
        tmp_path / WS12_CLOSURE_RECEIPT_REL,
        {
            "schema_id": "kt.operator.total_closure_campaign_completion_receipt.v1",
            "status": "PASS",
            "public_showability_gate_status": "BLOCKED",
            "tournament_gate_status": "BLOCKED",
        },
    )
    _write_json(tmp_path / WS12_FINAL_BUNDLE_REL, {"proof_class_summary": {"governance_ceiling": "WORKFLOW_GOVERNANCE_ONLY"}})
    _write_text(tmp_path / WS15_STATUS_VERDICT_REL, "KT_STATUS_PASS cmd=status profile=v1 allow_dirty=0 head=b4789...")
    _write_text(tmp_path / WS15_CANONICAL_HMAC_VERDICT_REL, "KT_CERTIFY_PASS cmd=certify lane=canonical_hmac profile=v1 allow_dirty=0 head=b4789...")
    _write_text(tmp_path / WS15_AUTHORITY_VERDICT_REL, "KT_AUTHORITY_GRADE_A status=PASS blockers=0 integrity_failures=0 head=b4789...")
    _write_json(
        tmp_path / EXECUTION_DAG_REL,
        {
            "schema_id": "kt.governance.execution_dag.v1",
            "status": "ACTIVE",
            "current_node": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE",
            "current_repo_head": frozen_head,
            "next_lawful_workstream": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY",
            "semantic_boundary": {"lawful_current_claim": "seed", "stronger_claim_not_made": []},
            "nodes": [
                {"id": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE", "status": "PASS", "ratification_checkpoint": "kt_external_assurance_confirmation_receipt.json"},
                {"id": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY", "status": "UNLOCKED", "ratification_checkpoint": "external_capability_receipt"},
                {"id": NEXT_WORKSTREAM_ON_PASS, "status": "LOCKED_PENDING_WS17B_PASS", "ratification_checkpoint": "final_readjudication_receipt"},
            ],
        },
    )
    return _commit_all(tmp_path, "seed ws17b inputs")


def test_emit_ws17b_passes_with_detached_capability_replay(tmp_path: Path) -> None:
    frozen_head = _seed_ws17b_repo(tmp_path)
    receipt = emit_ws17b_external_capability(root=tmp_path)
    assert receipt["status"] == "PASS"
    assert receipt["pass_verdict"] == PASS_VERDICT
    assert receipt["compiled_against"] == frozen_head
    assert receipt["next_lawful_workstream"] == NEXT_WORKSTREAM_ON_PASS
    assert (tmp_path / IMPORT_MANIFEST_REL).exists()
    assert (tmp_path / REPLAY_REPORT_REL).exists()
    replay = json.loads((tmp_path / REPLAY_REPORT_REL).read_text(encoding="utf-8"))
    assert replay["status"] == "PASS"


def test_emit_ws17b_blocks_when_subject_binding_breaks(tmp_path: Path) -> None:
    _seed_ws17b_repo(tmp_path)
    broken = json.loads((tmp_path / FRONTIER_SCORECARD_REL).read_text(encoding="utf-8"))
    broken["sealed_subject_anchor_commit"] = "deadbeef"
    _write_json(tmp_path / FRONTIER_SCORECARD_REL, broken)
    _commit_all(tmp_path, "break subject binding")
    receipt = emit_ws17b_external_capability(root=tmp_path)
    assert receipt["status"] == "BLOCKED"
    assert "HISTORICAL_SUBJECT_HEAD_MISMATCH" in receipt["blocked_by"]
