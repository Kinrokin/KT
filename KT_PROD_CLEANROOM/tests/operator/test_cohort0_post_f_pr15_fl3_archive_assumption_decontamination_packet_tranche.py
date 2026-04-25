from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_archive_assumption_decontamination_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_t03_packet_freezes_archive_assumption_when_tests_still_require_receipts(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True, exist_ok=True)
    (workflow / "ci_fl3_pr_fast.yml").write_text(
        "if [ -d KT_ARCHIVE/vault/receipts ]; then\n"
        "  python -m tools.verification.validate_receipts --receipts-dir KT_ARCHIVE/vault/receipts --out-dir tmp/receipt_validation\n"
        "else\n"
        "  echo \"SKIP: KT_ARCHIVE/vault/receipts is not present on the active canonical tree\"\n"
        "fi\n",
        encoding="utf-8",
    )
    secrets_test = tmp_path / "KT_PROD_CLEANROOM" / "tests" / "fl3"
    secrets_test.mkdir(parents=True, exist_ok=True)
    (secrets_test / "test_fl3_receipts_no_secrets.py").write_text(
        "assert receipts_dir.exists()\n",
        encoding="utf-8",
    )
    vr_test = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "verification" / "tests"
    vr_test.mkdir(parents=True, exist_ok=True)
    (vr_test / "test_validate_receipts.py").write_text(
        'receipts_dir = Path("KT_ARCHIVE/vault/receipts")\nreport = validate_receipts_dir(receipts_dir=receipts_dir)\n',
        encoding="utf-8",
    )

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
            "do_not_widen_boundaries": ["Do not widen package truth."],
        },
    )
    _write_json(reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json", {"schema_id": "r", "status": "PASS"})
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "b",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01"},
                {"tranche_id": "T02"},
                {"tranche_id": "T03"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
        {
            "schema_id": "t02",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        tranche2_receipt_path=reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_DEFINED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["archive_truth"]["archive_receipts_exists_on_active_tree"] is False
    assert packet["decontamination_evidence"]["secrets_test_requires_archive_receipts"] is True
    assert packet["decontamination_evidence"]["validate_receipts_repo_test_requires_archive_dir"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_DEFINED


def test_t03_packet_can_clear_when_tests_follow_workflow_skip_law(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True, exist_ok=True)
    (workflow / "ci_fl3_pr_fast.yml").write_text(
        "if [ -d KT_ARCHIVE/vault/receipts ]; then\n"
        "  python -m tools.verification.validate_receipts --receipts-dir KT_ARCHIVE/vault/receipts --out-dir tmp/receipt_validation\n"
        "else\n"
        "  echo \"SKIP: KT_ARCHIVE/vault/receipts is not present on the active canonical tree\"\n"
        "fi\n",
        encoding="utf-8",
    )
    secrets_test = tmp_path / "KT_PROD_CLEANROOM" / "tests" / "fl3"
    secrets_test.mkdir(parents=True, exist_ok=True)
    (secrets_test / "test_fl3_receipts_no_secrets.py").write_text(
        "import pytest\npytest.skip('KT_ARCHIVE/vault/receipts is not present on the active canonical tree')\n",
        encoding="utf-8",
    )
    vr_test = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "verification" / "tests"
    vr_test.mkdir(parents=True, exist_ok=True)
    (vr_test / "test_validate_receipts.py").write_text(
        'import pytest\nreceipts_dir = Path("KT_ARCHIVE/vault/receipts")\npytest.skip("KT_ARCHIVE/vault/receipts is not present on the active canonical tree")\n',
        encoding="utf-8",
    )

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
            "do_not_widen_boundaries": ["Do not widen package truth."],
        },
    )
    _write_json(reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json", {"schema_id": "r", "status": "PASS"})
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        {
            "schema_id": "b",
            "status": "PASS",
            "blockers": [
                {"tranche_id": "T01"},
                {"tranche_id": "T02"},
                {"tranche_id": "T03"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
        {
            "schema_id": "t02",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_ARCHIVE_ASSUMPTION_DECONTAMINATION_PACKET",
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "branch-head")

    result = tranche.run(
        reports_root=reports,
        authority_packet_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_packet.json",
        authority_receipt_path=reports / "cohort0_post_f_pr15_fl3_remediation_authority_receipt.json",
        blocker_ledger_path=reports / "cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json",
        tranche2_receipt_path=reports / "cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_CLEARED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["tranche_header"]["tranche_state"] == "cleared"
    assert packet["decontamination_evidence"]["secrets_test_skips_missing_archive_receipts"] is True
    assert packet["decontamination_evidence"]["validate_receipts_repo_test_skips_missing_archive_dir"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_CLEARED
