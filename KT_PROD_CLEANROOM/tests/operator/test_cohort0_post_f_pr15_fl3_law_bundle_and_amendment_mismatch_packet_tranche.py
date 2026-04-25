from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_t01_packet_freezes_live_vs_pinned_law_bundle_mismatch(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
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
            "do_not_widen_boundaries": [
                "Do not widen package truth.",
                "Do not change truth-engine derivation law.",
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        {
            "schema_id": "authority-receipt",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "blocker-ledger",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01", "blocker_id": "PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH"},
                {"tranche_id": "T02", "blocker_id": "OTHER"},
            ],
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(
        tranche,
        "_load_law_bundle",
        lambda root: {
            "bundle_id": "LAW_BUNDLE_FL3",
            "files": [{"path": "a"}, {"path": "b"}],
            "laws": [{"law_id": "FL3_SOVEREIGN_PROTOCOL"}],
        },
    )
    monkeypatch.setattr(tranche, "_compute_bundle_hash", lambda root, bundle: "905ab6")
    monkeypatch.setattr(tranche, "_read_sha_pin", lambda root: "375558")
    monkeypatch.setattr(
        tranche,
        "_scan_amendment_support",
        lambda root, bundle_hash: [{"path": "/tmp/LAW_AMENDMENT.json"}] if bundle_hash == "375558" else [],
    )
    monkeypatch.setattr(
        tranche,
        "_scan_change_receipt_support",
        lambda root, bundle_hash: [{"path": "/tmp/LAW_BUNDLE_CHANGE_RECEIPT.json"}] if bundle_hash == "375558" else [],
    )
    monkeypatch.setattr(
        tranche,
        "_probe_fl3_meta_evaluator",
        lambda root: {
            "returncode": 1,
            "combined_tail": "Missing kt.law_amendment.v2 for current LAW_BUNDLE hash (fail-closed)",
        },
    )

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_MISMATCH
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["tranche_header"]["tranche_id"] == "T01"
    assert packet["live_bundle_state"]["computed_bundle_hash"] == "905ab6"
    assert packet["live_bundle_state"]["pinned_bundle_hash"] == "375558"
    assert packet["support_chain_state"]["current_hash"]["matching_law_amendment_v2_count"] == 0
    assert packet["support_chain_state"]["pinned_hash"]["matching_change_receipt_count"] == 1
    assert packet["live_resolution_read"]["recommended_resolution_class"] == "BIND_SUPERSESSION_AND_AMENDMENT_MAPPING"
    assert len(packet["allowed_resolution_classes"]) == 4
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_MISMATCH


def test_t01_packet_can_rerun_after_remediation_and_advance_to_tranche2(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
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
            "do_not_widen_boundaries": [
                "Do not widen package truth.",
                "Do not change truth-engine derivation law.",
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        {
            "schema_id": "authority-receipt",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_PACKET",
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "blocker-ledger",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01", "blocker_id": "PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH"},
                {"tranche_id": "T02", "blocker_id": "OTHER"},
            ],
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(
        tranche,
        "_load_law_bundle",
        lambda root: {
            "bundle_id": "LAW_BUNDLE_FL3",
            "files": [{"path": "a"}, {"path": "b"}],
            "laws": [{"law_id": "FL3_SOVEREIGN_PROTOCOL"}],
        },
    )
    monkeypatch.setattr(tranche, "_compute_bundle_hash", lambda root, bundle: "905ab6")
    monkeypatch.setattr(tranche, "_read_sha_pin", lambda root: "905ab6")
    monkeypatch.setattr(
        tranche,
        "_scan_amendment_support",
        lambda root, bundle_hash: [{"path": "/tmp/LAW_AMENDMENT.json"}] if bundle_hash == "905ab6" else [],
    )
    monkeypatch.setattr(
        tranche,
        "_scan_change_receipt_support",
        lambda root, bundle_hash: [{"path": "/tmp/LAW_BUNDLE_CHANGE_RECEIPT.json"}] if bundle_hash == "905ab6" else [],
    )
    monkeypatch.setattr(
        tranche,
        "_probe_fl3_meta_evaluator",
        lambda root: {
            "returncode": 0,
            "combined_tail": "",
        },
    )

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_CLEARED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)

    assert packet["tranche_header"]["tranche_state"] == "cleared"
    assert packet["live_resolution_read"]["recommended_resolution_class"] == "ADVANCE_TO_T02_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT"
    assert packet["live_bundle_state"]["pin_matches_current"] is True
    assert receipt["current_hash_support_complete"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_CLEARED
