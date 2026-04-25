from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_pr15_fl3_remediation_authority_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_pr15_fl3_remediation_authority_packet_binds_narrow_blocker_program(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(
        reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        {
            "schema_id": "recompute-receipt",
            "status": "PASS",
            "blocking_contradiction_count": 0,
            "advisory_condition_count": 1,
            "recompute_scope": "AUTHORITATIVE_BRANCH_ONLY__REMOTE_MAIN_PENDING",
            "next_lawful_move": "RERUN_POST_F_TRUTH_ENGINE_RECOMPUTE_ON_MAIN_AFTER_PR15_MERGE",
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_post_merge_replay_packet.json",
        {
            "schema_id": "replay-packet",
            "status": "PASS",
            "expected_advisory_disappearance": {
                "current_advisory_contradiction_id": "merge_truth::remote_main_pending_pr15"
            },
        },
    )
    _write_json(
        reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.json",
        {
            "schema_id": "handoff-note",
            "status": "PASS",
            "first_canonical_truth_engine_freeze_on_main": {
                "success_condition": "same derivation as branch replay with zero blocking contradictions and zero advisory contradictions"
            },
        },
    )

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(
        tranche,
        "_git_rev_parse",
        lambda root, ref: "parent-head" if ref == tranche.PARENT_AUTHORITATIVE_BRANCH else "branch-head",
    )
    monkeypatch.setattr(tranche, "_git_merge_base", lambda root, left, right: "parent-head")
    monkeypatch.setattr(
        tranche,
        "_probe_fl3_meta_evaluator",
        lambda root: {
            "returncode": 1,
            "combined_tail": "Missing kt.law_amendment.v2 for current LAW_BUNDLE hash (fail-closed)",
            "stdout": "",
            "stderr": "",
        },
    )
    monkeypatch.setattr(
        tranche,
        "_path_exists",
        lambda root, rel_path: {
            "KT_PROD_CLEANROOM/AUDITS/FL3_CANONICAL_RUNTIME_PATHS.json": False,
            "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json": False,
            "KT_ARCHIVE/vault/receipts": False,
            "KT_PROD_CLEANROOM/tools/verification/phase1c_execute.py": False,
        }[rel_path],
    )

    result = tranche.run(
        reports_root=reports,
        truth_engine_recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        truth_engine_replay_packet_path=reports / "cohort0_post_f_truth_engine_post_merge_replay_packet.json",
        truth_engine_handoff_note_path=reports / "cohort0_post_f_truth_engine_post_pr_canonical_handoff_note.json",
    )

    assert result["lane_outcome"] == tranche.OUTCOME
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    packet = _load(reports / tranche.OUTPUT_PACKET)
    blockers = _load(reports / tranche.OUTPUT_BLOCKERS)

    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert packet["success_condition"]["package_promotion_deferral_unchanged"] is True
    assert packet["authority_header"]["truth_engine_law_unchanged"] is True
    assert len(packet["tranche_order"]) == 5
    assert blockers["blocking_blocker_count"] == 5
    assert blockers["blockers"][0]["tranche_id"] == "T01"
    assert "kt.law_amendment.v2" in blockers["blockers"][0]["evidence"]
