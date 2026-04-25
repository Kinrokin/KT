from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_post_merge_replay_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_merge_replay_packet_prepares_exact_main_rerun(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_truth_engine_recompute_receipt.json", {"schema_id": "x", "status": "PASS", "next_lawful_move": tranche.NEXT_MOVE})
    _write_json(reports / "cohort0_post_f_truth_engine_posture_index.json", {"schema_id": "y", "package_truth_posture": ["PACKAGE_PROMOTION_DEFERRED"], "theorem_truth_posture": ["T"], "product_truth_posture": ["P"]})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche, "_git_rev_parse", lambda root, ref: "main-head" if ref == "main" else "branch-head")

    result = tranche.run(
        reports_root=reports,
        recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        posture_index_path=reports / "cohort0_post_f_truth_engine_posture_index.json",
    )
    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    assert packet["expected_advisory_disappearance"]["current_advisory_contradiction_id"] == "merge_truth::remote_main_pending_pr15"

