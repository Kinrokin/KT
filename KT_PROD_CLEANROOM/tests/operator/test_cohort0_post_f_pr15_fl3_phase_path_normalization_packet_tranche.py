from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_phase_path_normalization_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_t04_packet_freezes_weak_phase_executor_root_selection(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    tools_verification = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "verification"
    tools_verification.mkdir(parents=True, exist_ok=True)
    (tools_verification / "phase1c_execute.py").write_text(
        'if (parent / "KT_PROD_CLEANROOM").exists():\n    return parent\n',
        encoding="utf-8",
    )
    (tools_verification / "phase2_execute.py").write_text(
        'if (parent / "KT_PROD_CLEANROOM").exists():\n    return parent\n',
        encoding="utf-8",
    )
    (tmp_path / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json").write_text("{}\n", encoding="utf-8")

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
                {"tranche_id": "T04"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
        {
            "schema_id": "t03",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET",
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
        tranche3_receipt_path=reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_DEFINED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["normalization_evidence"]["phase1c_source_uses_weak_root_selection"] is True
    assert packet["normalization_evidence"]["phase2_source_uses_weak_root_selection"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_DEFINED


def test_t04_packet_can_clear_when_phase_executors_use_strong_root_selection(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    tools_verification = tmp_path / "KT_PROD_CLEANROOM" / "tools" / "verification"
    tools_verification.mkdir(parents=True, exist_ok=True)
    strong_text = (
        'cleanroom_root = parent / "KT_PROD_CLEANROOM"\n'
        'if (cleanroom_root / "04_PROD_TEMPLE_V2" / "src" / "schemas" / "fl3_suite_registry_schema.py").is_file():\n'
        '    return parent\n'
    )
    (tools_verification / "phase1c_execute.py").write_text(strong_text, encoding="utf-8")
    (tools_verification / "phase2_execute.py").write_text(strong_text, encoding="utf-8")
    (tmp_path / "KT_PROD_CLEANROOM" / "kt.phase2_work_order.v1.json").write_text("{}\n", encoding="utf-8")

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
                {"tranche_id": "T04"},
            ],
        },
    )
    _write_json(
        reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
        {
            "schema_id": "t03",
            "status": "PASS",
            "next_lawful_move": "AUTHOR_POST_F_PR15_FL3_PHASE_PATH_NORMALIZATION_PACKET",
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
        tranche3_receipt_path=reports / "cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME_CLEARED
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    assert packet["tranche_header"]["tranche_state"] == "cleared"
    assert packet["normalization_evidence"]["phase1c_source_uses_strong_root_selection"] is True
    assert packet["normalization_evidence"]["phase2_source_uses_strong_root_selection"] is True
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_CLEARED
