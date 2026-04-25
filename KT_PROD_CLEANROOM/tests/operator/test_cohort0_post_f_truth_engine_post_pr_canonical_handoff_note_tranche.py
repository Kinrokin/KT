from __future__ import annotations

import json
from pathlib import Path

from tools.operator import cohort0_post_f_truth_engine_post_pr_canonical_handoff_note_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_post_pr_canonical_handoff_note_preserves_package_boundary(tmp_path: Path, monkeypatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _write_json(reports / "cohort0_post_f_truth_engine_recompute_receipt.json", {"schema_id": "a", "status": "PASS"})
    _write_json(reports / "cohort0_post_f_truth_engine_posture_index.json", {"schema_id": "b", "package_truth_posture": ["PACKAGE_PROMOTION_DEFERRED"], "product_truth_posture": ["PRODUCT_POSTURE_STILL_BOUNDED"], "theorem_truth_posture": ["THEOREM_POSTURE_CANONICAL_ON_MAIN"]})

    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche, "_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche, "_git_status_porcelain", lambda root: "")

    result = tranche.run(
        reports_root=reports,
        recompute_receipt_path=reports / "cohort0_post_f_truth_engine_recompute_receipt.json",
        posture_index_path=reports / "cohort0_post_f_truth_engine_posture_index.json",
    )
    assert result["outcome"] == tranche.OUTCOME
    packet = _load(reports / tranche.OUTPUT_PACKET)
    assert packet["unchanged_boundaries_after_pr15"]["package_truth_posture"] == ["PACKAGE_PROMOTION_DEFERRED"]
