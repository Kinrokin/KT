from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_post_merge_canonical_truth_boundary_readiness_audit_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_required_reports(reports: Path) -> None:
    pass_receipt = {"schema_id": "x", "status": "PASS", "execution_status": "PASS", "outcome": "BOUND", "next_lawful_move": "NEXT"}
    for name in [
        "cohort0_post_f_track_01_final_summary_receipt.json",
        "cohort0_post_f_track_02_final_summary_receipt.json",
        "cohort0_post_f_track_03_final_summary_receipt.json",
        "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json",
    ]:
        _write_json(reports / name, pass_receipt)
    _write_json(
        reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
        {"schema_id": "prep", "status": "PASS", "execution_status": "PASS", "outcome": tranche.EXPECTED_TRUST_ZONE_PREP_OUTCOME},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json",
        {"schema_id": "pr15", "status": "PASS", "blocking_blocker_count": 0, "t05_validation": {"full_fl3_suite_green": True, "full_fl3_summary": "239 passed, 1 skipped"}},
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        {
            "schema_id": "recompute",
            "status": "PASS",
            "branch_ref": "main",
            "recompute_scope": "CANONICAL_MAIN_REPLAY_CONVERGED",
            "blocking_contradiction_count": 0,
            "advisory_condition_count": 0,
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_contradiction_ledger.json",
        {"schema_id": "ledger", "status": "PASS", "blocking_contradiction_count": 0, "advisory_contradiction_count": 0, "contradictions": []},
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_posture_index.json",
        {
            "schema_id": "posture",
            "package_truth_posture": ["PACKAGE_PROMOTION_DEFERRED"],
            "merge_truth_posture": ["TRACK03_REPO_AUTHORITY_CANONICAL_ON_MAIN"],
            "theorem_truth_posture": ["THEOREM_POSTURE_CANONICAL_ON_MAIN"],
            "product_truth_posture": ["PRODUCT_POSTURE_STILL_BOUNDED"],
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json",
        {
            "schema_id": "handoff",
            "status": "PASS",
            "blocking_contradiction_count": 0,
            "advisory_condition_count": 0,
            "next_lawful_move": tranche.NEXT_MOVE,
        },
    )


def test_post_merge_boundary_readiness_audit_confirms_next_lane(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_required_reports(reports)
    quarantine_manifest = tmp_path / "_tmp" / "local_untracked_quarantine" / "20260425T230953Z" / "manifest.json"
    _write_json(quarantine_manifest, {"schema_id": "local", "status": "PASS"})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "head" if ref == "HEAD" else "origin-main")
    monkeypatch.setattr(tranche, "_git_is_ancestor", lambda root, ancestor, descendant: True)
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "trust", "status": "PASS", "checks": [{"status": "PASS"}], "failures": []})

    result = tranche.run(
        reports_root=reports,
        track01_receipt_path=reports / "cohort0_post_f_track_01_final_summary_receipt.json",
        track02_receipt_path=reports / "cohort0_post_f_track_02_final_summary_receipt.json",
        track03_receipt_path=reports / "cohort0_post_f_track_03_final_summary_receipt.json",
        track03_post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
        pr15_receipt_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json",
        pr15_blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json",
        recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        contradiction_ledger_path=reports / "cohort0_post_f_truth_engine_contradiction_ledger.json",
        posture_index_path=reports / "cohort0_post_f_truth_engine_posture_index.json",
        handoff_receipt_path=reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json",
        trust_zone_prep_receipt_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
    )

    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["package_boundary"]["package_promotion_remains_deferred"] is True
    assert packet["boundary_readiness"]["ready_to_promote_authoritative_lane"] is True
    assert packet["local_untracked_residue"]["manifest_count"] == 1
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE


def test_post_merge_boundary_readiness_audit_fails_on_nonzero_contradiction(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_required_reports(reports)
    ledger = _load(reports / "cohort0_post_f_truth_engine_contradiction_ledger.json")
    ledger["advisory_contradiction_count"] = 1
    _write_json(reports / "cohort0_post_f_truth_engine_contradiction_ledger.json", ledger)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "head")
    monkeypatch.setattr(tranche, "_git_is_ancestor", lambda root, ancestor, descendant: True)
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "trust", "status": "PASS", "checks": [], "failures": []})

    with pytest.raises(RuntimeError, match="must match contradiction ledger counts"):
        tranche.run(
            reports_root=reports,
            track01_receipt_path=reports / "cohort0_post_f_track_01_final_summary_receipt.json",
            track02_receipt_path=reports / "cohort0_post_f_track_02_final_summary_receipt.json",
            track03_receipt_path=reports / "cohort0_post_f_track_03_final_summary_receipt.json",
            track03_post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
            pr15_receipt_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json",
            pr15_blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json",
            recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
            contradiction_ledger_path=reports / "cohort0_post_f_truth_engine_contradiction_ledger.json",
            posture_index_path=reports / "cohort0_post_f_truth_engine_posture_index.json",
            handoff_receipt_path=reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json",
            trust_zone_prep_receipt_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
        )


def test_post_merge_boundary_readiness_audit_requires_non_authoritative_prep_outcome(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_required_reports(reports)
    prep = _load(reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json")
    prep["outcome"] = "SOME_OTHER_PASS_OUTCOME"
    _write_json(reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json", prep)

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "head")
    monkeypatch.setattr(tranche, "_git_is_ancestor", lambda root, ancestor, descendant: True)
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "trust", "status": "PASS", "checks": [], "failures": []})

    with pytest.raises(RuntimeError, match="expected non-authoritative prep outcome"):
        tranche.run(
            reports_root=reports,
            track01_receipt_path=reports / "cohort0_post_f_track_01_final_summary_receipt.json",
            track02_receipt_path=reports / "cohort0_post_f_track_02_final_summary_receipt.json",
            track03_receipt_path=reports / "cohort0_post_f_track_03_final_summary_receipt.json",
            track03_post_merge_receipt_path=reports / "cohort0_post_f_track_03_post_merge_closeout_receipt.json",
            pr15_receipt_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json",
            pr15_blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json",
            recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
            contradiction_ledger_path=reports / "cohort0_post_f_truth_engine_contradiction_ledger.json",
            posture_index_path=reports / "cohort0_post_f_truth_engine_posture_index.json",
            handoff_receipt_path=reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_receipt.json",
            trust_zone_prep_receipt_path=reports / "cohort0_post_f_parallel_trust_zone_boundary_purification_receipt.json",
        )
