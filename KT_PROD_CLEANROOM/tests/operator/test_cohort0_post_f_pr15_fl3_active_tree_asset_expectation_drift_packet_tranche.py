from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_t02_packet_freezes_root_selection_drift_instead_of_missing_assets(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    audits = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS"
    tests_fl3 = tmp_path / "KT_PROD_CLEANROOM" / "tests" / "fl3"
    tools_ai = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "audit_intelligence"
    nested = tmp_path / "KT_PROD_CLEANROOM" / "KT_PROD_CLEANROOM"
    audits.mkdir(parents=True, exist_ok=True)
    tests_fl3.mkdir(parents=True, exist_ok=True)
    tools_ai.mkdir(parents=True, exist_ok=True)
    (audits / "FL3_CANONICAL_RUNTIME_PATHS.json").write_text('{"schema_id":"kt.fl3.canonical_runtime_paths.v1"}\n', encoding="utf-8")
    (audits / "FAILURE_TAXONOMY_FL3.json").write_text('{"schema_id":"kt.failure_taxonomy.v1","mappings":[{"reason_code":"X","category_id":"Y"}]}\n', encoding="utf-8")
    (tests_fl3 / "test_fl3_canonical_runtime_paths.py").write_text(
        "from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath\n\n"
        "def _repo_root() -> str:\n"
        "    return 'weak'\n",
        encoding="utf-8",
    )
    (tools_ai / "run_audit_intelligence.py").write_text("# fixture\n", encoding="utf-8")
    nested.mkdir(parents=True, exist_ok=True)

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
        {"schema_id": "authority-receipt", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "blocker-ledger",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01", "blocker_id": "X"},
                {"tranche_id": "T02", "blocker_id": "Y"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
        {
            "schema_id": "t01",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_PACKET",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(
        tranche,
        "_canonical_repo_root_from",
        lambda path: tmp_path,
    )
    monkeypatch.setattr(
        tranche,
        "_audit_intelligence_repo_root_from",
        lambda path: tmp_path / "KT_PROD_CLEANROOM",
    )

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        tranche1_receipt_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_DRIFT
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["asset_truth"]["canonical_runtime_paths_exists"] is True
    assert packet["asset_truth"]["failure_taxonomy_exists"] is True
    assert packet["asset_truth"]["nested_cleanroom_subtree_exists"] is True
    assert packet["drift_evidence"]["weak_test_runtime_paths_target_exists"] is False
    assert packet["drift_evidence"]["audit_intelligence_failure_taxonomy_target_exists"] is False
    assert packet["drift_evidence"]["shared_helper_failure_taxonomy_target_exists"] is True
    assert packet["live_resolution_read"]["genuine_missing_asset"] is False
    assert receipt["weak_root_selection_still_active_in_test"] is True
    assert receipt["audit_intelligence_local_root_still_misroutes_failure_taxonomy"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_DRIFT


def test_t02_packet_can_clear_after_root_selection_normalization(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    audits = tmp_path / "KT_PROD_CLEANROOM" / "AUDITS"
    tests_fl3 = tmp_path / "KT_PROD_CLEANROOM" / "tests" / "fl3"
    tools_ai = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "audit_intelligence"
    nested = tmp_path / "KT_PROD_CLEANROOM" / "KT_PROD_CLEANROOM"
    audits.mkdir(parents=True, exist_ok=True)
    tests_fl3.mkdir(parents=True, exist_ok=True)
    tools_ai.mkdir(parents=True, exist_ok=True)
    (audits / "FL3_CANONICAL_RUNTIME_PATHS.json").write_text('{"schema_id":"kt.fl3.canonical_runtime_paths.v1"}\n', encoding="utf-8")
    (audits / "FAILURE_TAXONOMY_FL3.json").write_text('{"schema_id":"kt.failure_taxonomy.v1","mappings":[{"reason_code":"X","category_id":"Y"}]}\n', encoding="utf-8")
    (tests_fl3 / "test_fl3_canonical_runtime_paths.py").write_text(
        "from KT_PROD_CLEANROOM.tests.fl3._bootstrap import bootstrap_syspath\n\n"
        "_REPO_ROOT = bootstrap_syspath()\n",
        encoding="utf-8",
    )
    (tools_ai / "run_audit_intelligence.py").write_text("# fixture\n", encoding="utf-8")
    nested.mkdir(parents=True, exist_ok=True)

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
        {"schema_id": "authority-receipt", "status": "PASS"},
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "blocker-ledger",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01", "blocker_id": "X"},
                {"tranche_id": "T02", "blocker_id": "Y"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
        {
            "schema_id": "t01",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_ACTIVE_TREE_ASSET_EXPECTATION_DRIFT_PACKET",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")
    monkeypatch.setattr(
        tranche,
        "_canonical_repo_root_from",
        lambda path: tmp_path,
    )
    monkeypatch.setattr(
        tranche,
        "_audit_intelligence_repo_root_from",
        lambda path: tmp_path,
    )

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        tranche1_receipt_path=reports / "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_CLEARED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["tranche_header"]["tranche_state"] == "cleared"
    assert packet["drift_evidence"]["test_source_uses_bootstrap_root"] is True
    assert packet["drift_evidence"]["audit_intelligence_failure_taxonomy_target_exists"] is True
    assert packet["drift_evidence"]["shared_helper_failure_taxonomy_target_exists"] is True
    assert receipt["weak_root_selection_still_active_in_test"] is False
    assert receipt["audit_intelligence_local_root_still_misroutes_failure_taxonomy"] is False
    assert receipt["shared_helper_root_matches_repo_root"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_CLEARED
