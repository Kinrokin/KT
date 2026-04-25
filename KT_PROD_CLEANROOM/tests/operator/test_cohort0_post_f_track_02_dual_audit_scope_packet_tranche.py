from __future__ import annotations

import hashlib
import json
from pathlib import Path

from KT_PROD_CLEANROOM.tests.operator._gate_f_fixtures import seed_gate_f_base
from tools.operator import cohort0_post_f_track_01_final_summary_packet_tranche as track01_final
from tools.operator import cohort0_post_f_track_02_dual_audit_scope_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_f_track_02_dual_audit_scope_packet_binds(tmp_path: Path, monkeypatch) -> None:
    reports = seed_gate_f_base(tmp_path)
    prompts = tmp_path / "prompts"
    baseline_prompt = prompts / "baseline_scope_normalized_v3_1.md"
    current_prompt = prompts / "current_truth_hardened_post_f_v1.md"
    baseline_text = "baseline frozen audit prompt\n"
    current_text = "current truth hardened prompt\n"
    _write_text(baseline_prompt, baseline_text)
    _write_text(current_prompt, current_text)

    work_order = tmp_path / "cohort0_post_f_track_02_dual_audit_work_order_v2.json"
    _write_json(
        reports / track01_final.OUTPUT_PACKET,
        {
            "schema_id": "kt.operator.cohort0_post_f_track_01_final_summary_packet.v1",
            "status": "PASS",
            "summary_outcome": track01_final.SUMMARY_OUTCOME,
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
            },
        },
    )
    _write_json(
        work_order,
        {
            "schema_version": "1.1.0",
            "work_order_id": "cohort0_post_f_track_02_dual_audit_work_order",
            "objective": "dual audit",
            "repo": {
                "canonical_authority_branch": "main",
                "working_branch": "expansion/post-f-track-01",
                "require_clean_worktree": True,
                "fail_closed_on_dirty_state": True,
            },
            "constitutional_order_ref": {"source_packet": "kt_real_power_closure_and_execution_v11"},
            "anchors": {
                "frozen_baseline": {"ref_name": "kt-post-f-reaudit-pass"},
                "current_truth": {"ref_name": "expansion/post-f-track-01"},
                "supporting_release_tags": [
                    "kt-v11-minimum-path-complete",
                    "kt-gate-f-local-verifier-wedge-confirmed",
                    "kt-post-f-reaudit-pass",
                    "kt-canonical-clean-closeout",
                ],
            },
            "prompt_artifacts": {
                "storage_model": "external_files_with_hash_verification",
                "baseline_frozen": {
                    "prompt_id": "KT_SUPER_HARSH_ADVERSARIAL_AUDIT_V3_1_SCOPE_NORMALIZED",
                    "sha256": _sha256(baseline_text),
                    "unchanged_required": True,
                },
                "current_truth_hardened": {
                    "prompt_id": "KT_MAX_POWER_ADVERSARIAL_AUDIT_PLUS_ELEVATION_BRIEF__POST_F_HARDENED",
                    "sha256": _sha256(current_text),
                    "authorized_mutation_allowed": False,
                    "current_truth_overrides_are_inside_prompt_artifact": True,
                },
            },
            "shared_evidence_harvest": {
                "mode": "single_shared_harvest",
                "one_harvest_two_views": True,
                "sources": [{}, {}, {}],
                "secret_policy": {"emit_secret_presence_note": True},
            },
            "authority_partition": {
                "precedence_order": ["current_truth_anchor_commit_consistent_live_header"],
                "stale_if": ["artifact_conflicts_with_anchor_commit_state"],
                "view_rules": {"baseline_view_rejects_post_anchor_authority": True},
            },
            "audit_runs": [
                {
                    "run_id": "frozen_baseline_audit",
                    "prompt_ref": "baseline_frozen",
                    "anchor_ref": "frozen_baseline",
                    "evidence_view_mode": "frozen_baseline_view",
                    "outputs": {"verdict_path": "a.json"},
                },
                {
                    "run_id": "hardened_current_truth_audit",
                    "prompt_ref": "current_truth_hardened",
                    "anchor_ref": "current_truth",
                    "evidence_view_mode": "current_truth_live_view",
                    "outputs": {"verdict_path": "b.json"},
                },
            ],
            "delta_crosswalk": {"enabled": True},
            "meta_summary": {"enabled": True},
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: "expansion/post-f-track-01")
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_tag_exists", lambda root, ref_name: True)

    result = tranche.run(
        reports_root=reports,
        track01_final_summary_packet_path=reports / track01_final.OUTPUT_PACKET,
        work_order_path=work_order,
        baseline_prompt_path=baseline_prompt,
        current_truth_prompt_path=current_prompt,
    )

    assert result["scope_outcome"] == tranche.SCOPE_OUTCOME

    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["prompt_artifact_binding"]["baseline_frozen"]["sha256"] == _sha256(baseline_text)
    assert packet["prompt_artifact_binding"]["current_truth_hardened"]["sha256"] == _sha256(current_text)
    assert packet["authority_header"]["track_01_closed_as_bounded_proof_packet"] is True
    assert packet["execution_plan"]["shared_evidence_harvest"]["one_harvest_two_views"] is True
    assert len(packet["execution_plan"]["audit_runs"]) == 2
    assert packet["next_lawful_move"] == tranche.NEXT_MOVE
    assert receipt["baseline_prompt_hash_verified"] is True
    assert receipt["current_truth_prompt_hash_verified"] is True
    assert receipt["audit_run_count"] == 2
