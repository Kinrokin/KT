from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_02_shared_evidence_harvest_and_authority_partition_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_02_shared_evidence_harvest_and_authority_partition_binds(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    docs = tmp_path / "docs"
    prompts = tmp_path / "prompts"
    operator_tools = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "operator"
    operator_tests = tmp_path / "KT_PROD_CLEANROOM" / "tests" / "operator"
    baseline_prompt = prompts / "baseline_scope_normalized_v3_1.md"
    current_prompt = prompts / "current_truth_hardened_post_f_v1.md"
    work_order = tmp_path / "cohort0_post_f_track_02_dual_audit_work_order_v2.json"

    _write_text(tmp_path / ".gitignore", "_tmp/\n")
    _write_text(tmp_path / ".venv" / ".gitignore", "*\n")
    _write_text(docs / "REPO_BOUNDARY.md", "boundary\n")
    _write_text(operator_tools / "sample_operator.py", "def run():\n    return 'ok'\n")
    _write_text(operator_tests / "test_sample_operator.py", "def test_ok():\n    assert True\n")
    _write_text(baseline_prompt, "baseline prompt\n")
    _write_text(current_prompt, "current prompt\n")
    _write_json(
        reports / "cohort0_post_f_track_01_final_summary_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_final_summary_packet.v1",
            "status": "PASS",
            "summary_outcome": "POST_F_TRACK_01_REPEATED_BOUNDED_ADVANTAGE_FROZEN__CANONICAL_WEDGE_ONLY",
            "subject_head": "head-123",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
                "track_01_closed_as_bounded_proof_packet": True,
            },
        },
    )

    baseline_sha = hashlib.sha256(baseline_prompt.read_bytes()).hexdigest()
    current_sha = hashlib.sha256(current_prompt.read_bytes()).hexdigest()
    _write_json(
        work_order,
        {
            "schema_version": "1.1.0",
            "work_order_id": "cohort0_post_f_track_02_dual_audit_work_order",
            "repo": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "require_clean_worktree": True,
                "fail_closed_on_dirty_state": True,
            },
            "anchors": {
                "frozen_baseline": {"ref_name": "kt-post-f-reaudit-pass"},
                "current_truth": {"ref_name": "expansion/post-f-track-01"},
                "supporting_release_tags": [
                    "kt-v11-minimum-path-complete",
                    "kt-gate-f-local-verifier-wedge-confirmed",
                ],
            },
            "prompt_artifacts": {
                "baseline_frozen": {
                    "prompt_id": "KT_SUPER_HARSH_ADVERSARIAL_AUDIT_V3_1_SCOPE_NORMALIZED",
                    "sha256": baseline_sha,
                },
                "current_truth_hardened": {
                    "prompt_id": "KT_MAX_POWER_ADVERSARIAL_AUDIT_PLUS_ELEVATION_BRIEF__POST_F_HARDENED",
                    "sha256": current_sha,
                },
            },
            "shared_evidence_harvest": {
                "mode": "single_shared_harvest",
                "one_harvest_two_views": True,
                "secret_policy": {
                    "never_read_globs": ["**/.envsecrets"],
                    "metadata_only_globs": ["**/.envsecrets"],
                    "emit_secret_presence_note": True,
                },
                "sources": [
                    {
                        "source_id": "git_state",
                        "source_type": "git",
                        "location": "${KT_ROOT:-.}",
                        "capture_mode": "metadata_and_content",
                        "required": True,
                    },
                    {
                        "source_id": "repo_boundary",
                        "source_type": "docs",
                        "location": "${KT_ROOT:-.}",
                        "capture_mode": "full_text",
                        "required": True,
                        "include_globs": [".gitignore", "docs/REPO_BOUNDARY.md"],
                    },
                    {
                        "source_id": "cleanroom_reports",
                        "source_type": "reports",
                        "location": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/reports",
                        "capture_mode": "full_text",
                        "required": True,
                        "include_globs": ["**/*.json"],
                    },
                    {
                        "source_id": "operator_tranches",
                        "source_type": "tools",
                        "location": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/tools/operator",
                        "capture_mode": "full_text",
                        "required": True,
                        "include_globs": ["**/*.py"],
                    },
                    {
                        "source_id": "operator_tests",
                        "source_type": "tests",
                        "location": "${KT_ROOT:-.}/KT_PROD_CLEANROOM/tests/operator",
                        "capture_mode": "full_text",
                        "required": True,
                        "include_globs": ["**/*.py"],
                    },
                    {
                        "source_id": "google_drive_exports",
                        "source_type": "drive",
                        "location": "${KT_DRIVE_EXPORT_ROOT:-./drive_exports}",
                        "capture_mode": "metadata_and_content",
                        "required": False,
                        "include_globs": ["**/*.json"],
                    },
                    {
                        "source_id": "chat_log_exports",
                        "source_type": "chat_logs",
                        "location": "${KT_CHAT_EXPORT_ROOT:-./chat_exports}",
                        "capture_mode": "metadata_and_content",
                        "required": False,
                        "include_globs": ["**/*.json"],
                    },
                    {
                        "source_id": "secret_presence_note",
                        "source_type": "secrets_note",
                        "location": "${KT_ROOT:-.}/.envsecrets",
                        "capture_mode": "metadata_only",
                        "required": False,
                    },
                ],
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
        {
            "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_scope_packet.v1",
            "status": "PASS",
            "scope_outcome": "POST_F_TRACK_02_DUAL_AUDIT_SCOPE_DEFINED__SEPARATE_BASELINE_AND_CURRENT_TRUTH_VERDICTS",
            "next_lawful_move": "EXECUTE_POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION",
            "subject_head": "head-123",
            "authority_header": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "working_branch_non_authoritative_until_protected_merge": True,
                "gate_d_cleared_on_successor_line": True,
                "gate_e_open_on_successor_line": True,
                "gate_f_narrow_wedge_confirmed": True,
                "gate_f_open": False,
                "post_f_reaudit_passed": True,
                "track_01_closed_as_bounded_proof_packet": True,
            },
            "anchor_binding": {
                "frozen_baseline": {"ref_name": "kt-post-f-reaudit-pass"},
                "current_truth": {"ref_name": "expansion/post-f-track-01"},
            },
            "work_order_binding": {
                "work_order_path": work_order.as_posix(),
            },
            "prompt_artifact_binding": {
                "baseline_frozen": {
                    "source_path": baseline_prompt.as_posix(),
                    "expected_sha256": baseline_sha,
                },
                "current_truth_hardened": {
                    "source_path": current_prompt.as_posix(),
                    "expected_sha256": current_sha,
                },
            },
            "execution_plan": {
                "authority_partition": {
                    "precedence_order": ["current_truth_anchor_commit_consistent_live_header"],
                    "stale_if": ["artifact_conflicts_with_anchor_commit_state"],
                    "view_rules": {
                        "baseline_view_rejects_post_anchor_authority": True,
                        "current_truth_view_allows_authorized_current_overrides": True,
                    },
                },
            },
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: f"{ref}-sha")

    result = tranche.run(
        reports_root=reports,
        scope_packet_path=reports / "cohort0_post_f_track_02_dual_audit_scope_packet.json",
    )

    assert result["execution_outcome"] == tranche.EXECUTION_OUTCOME

    evidence_manifest = _load(reports / "cohort0_post_f_track_02_dual_audit_evidence_manifest.json")
    hash_manifest = _load(reports / "cohort0_post_f_track_02_dual_audit_content_hash_manifest.json")
    authority_partition = _load(reports / "cohort0_post_f_track_02_dual_audit_authority_partition.json")
    baseline_view = _load(reports / tranche.OUTPUT_BASELINE_VIEW)
    current_view = _load(reports / tranche.OUTPUT_CURRENT_VIEW)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert evidence_manifest["one_harvest_two_views"] is True
    assert len(hash_manifest["artifacts"]) > 0
    repo_boundary_refs = [
        row["artifact_ref"]
        for row in evidence_manifest["evidence_entries"]
        if row.get("source_id") == "repo_boundary" and row.get("kind") == "content_hashed"
    ]
    assert str((tmp_path / ".venv" / ".gitignore").resolve()).replace("\\", "/") not in repo_boundary_refs
    assert authority_partition["anchor_resolution"]["frozen_baseline_anchor_ref"] == "kt-post-f-reaudit-pass"
    assert baseline_view["reject_post_anchor_authority"] is True
    assert current_view["live_header_precedence_enforced"] is True
    assert receipt["baseline_view_materialized"] is True
    assert receipt["current_truth_view_materialized"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
