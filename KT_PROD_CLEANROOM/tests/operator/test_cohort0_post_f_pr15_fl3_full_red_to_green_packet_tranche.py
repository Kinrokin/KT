from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_post_f_pr15_fl3_full_red_to_green_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_receipt(path: Path, *, tranche_id: str, next_move: str) -> None:
    _write_json(
        path,
        {
            "schema_id": f"{tranche_id}-receipt",
            "status": "PASS",
            "tranche_id": tranche_id,
            "tranche_state": "cleared",
            "lane_outcome": f"{tranche_id}_CLEARED",
            "next_lawful_move": next_move,
        },
    )


def test_t05_packet_binds_green_closeout_and_zero_live_blockers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    audits = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS"
    audits.mkdir(parents=True, exist_ok=True)
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        {
            "schema_id": "authority-packet",
            "status": "PASS",
            "authority_header": {
                "package_promotion_still_deferred": True,
                "truth_engine_law_unchanged": True,
                "replay_on_main_still_deferred_until_pr15_merge": True,
            },
        },
    )
    _write_json(reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json", {"schema_id": "authority-receipt", "status": "PASS"})
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json", tranche_id="T01", next_move="AUTHOR_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_PACKET")
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json", tranche_id="T02", next_move="AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET")
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json", tranche_id="T03", next_move="AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET")
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json", tranche_id="T04", next_move="AUTHOR_POST_F_PR15_FL3_FULL_RED_TO_GREEN_PACKET")
    (audits / "LAW_BUNDLE_FL3.sha256").write_text("abc123\n", encoding="utf-8")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(tranche.t01, "_load_law_bundle", lambda root: {"files": [], "laws": []})
    monkeypatch.setattr(tranche.t01, "_compute_bundle_hash", lambda root, bundle: "abc123")
    monkeypatch.setattr(
        tranche.t01,
        "_scan_amendment_support",
        lambda root, bundle_hash: [{"path": "/tmp/amendment.json", "amendment_id": "AMEND", "created_at": "2026-04-25T18:00:00Z"}],
    )
    monkeypatch.setattr(
        tranche.t01,
        "_scan_change_receipt_support",
        lambda root, bundle_hash: [{"path": "/tmp/change.json", "receipt_id": "CHANGE", "created_at": "2026-04-25T18:00:00Z"}],
    )
    monkeypatch.setattr(
        tranche,
        "_run_meta_evaluator",
        lambda root: {"returncode": 0, "combined_tail": "", "stdout": "", "stderr": ""},
    )
    monkeypatch.setattr(
        tranche,
        "_run_full_fl3_suite",
        lambda root: {
            "returncode": 0,
            "summary_line": "239 passed, 1 skipped in 75.55s",
            "counts": {"passed": 239, "failed": 0, "skipped": 1, "xfailed": 0, "xpassed": 0, "errors": 0},
            "combined_tail": "",
            "stdout": "",
            "stderr": "",
        },
    )

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        tranche1_receipt_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
        tranche2_receipt_path=reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
        tranche3_receipt_path=reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
        tranche4_receipt_path=reports / "cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    blockers = _load(reports / tranche.OUTPUT_BLOCKERS)
    assert packet["validation_result"]["full_fl3_suite"]["counts"]["passed"] == 239
    assert packet["final_law_bundle_state"]["pin_matches_current"] is True
    assert blockers["blocking_blocker_count"] == 0
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE


def test_t05_packet_fail_closes_if_prior_tranche_not_cleared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    audits = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS"
    audits.mkdir(parents=True, exist_ok=True)
    _write_json(reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json", {"schema_id": "a", "status": "PASS", "authority_header": {}})
    _write_json(reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json", {"schema_id": "b", "status": "PASS"})
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
        {"schema_id": "t01", "status": "PASS", "tranche_id": "T01", "tranche_state": "defined", "next_lawful_move": "X"},
    )
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json", tranche_id="T02", next_move="AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET")
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json", tranche_id="T03", next_move="AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET")
    _write_receipt(reports / "cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json", tranche_id="T04", next_move="AUTHOR_POST_F_PR15_FL3_FULL_RED_TO_GREEN_PACKET")
    (audits / "LAW_BUNDLE_FL3.sha256").write_text("abc123\n", encoding="utf-8")

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    with pytest.raises(RuntimeError, match="T01 is not cleared"):
        tranche.run(
            reports_root=reports,
            authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
            authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
            tranche1_receipt_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
            tranche2_receipt_path=reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
            tranche3_receipt_path=reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
            tranche4_receipt_path=reports / "cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json",
        )
