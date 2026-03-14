from __future__ import annotations

from tools.operator.foundation_pack_validate import (
    REQUIRED_CLAIM_STATUSES,
    REQUIRED_FIRST_CLASS_ORGANS,
    REQUIRED_RUN_MODES,
    build_foundation_pack_ratification_report,
)
from tools.operator.titanium_common import repo_root


def test_foundation_pack_ratification_report_passes() -> None:
    report = build_foundation_pack_ratification_report(root=repo_root())

    assert report["schema_id"] == "kt.operator.foundation_pack_ratification_receipt.v1"
    assert report["status"] == "PASS"
    assert report["pass_verdict"] == "FOUNDATION_PACK_RATIFIED"
    assert set(report["required_first_class_organs"]) == REQUIRED_FIRST_CLASS_ORGANS
    assert report["counts"]["foundation_artifact_count"] == 14
    assert report["counts"]["organ_count"] >= len(REQUIRED_FIRST_CLASS_ORGANS)
    assert report["counts"]["run_mode_count"] == len(REQUIRED_RUN_MODES)
    assert report["unexpected_touches"] == []
    assert report["protected_touch_violations"] == []
    assert report["next_lawful_step"]["step_id"] == 1
    assert len(str(report["compiled_head_commit"])) == 40
    assert len(str(report["current_head_commit"])) == 40

    check_ids = {row["check"] for row in report["checks"]}
    assert "required_first_class_organs_covered" in check_ids
    assert "claim_statuses_locked" in check_ids
    assert "run_modes_complete" in check_ids

    claim_status_check = next(row for row in report["checks"] if row["check"] == "claim_statuses_locked")
    assert claim_status_check["status"] == "PASS"
    assert REQUIRED_CLAIM_STATUSES == {
        "evidenced",
        "partially_evidenced",
        "contradicted",
        "aspirational",
        "obsolete",
        "unclear",
    }
