from __future__ import annotations

import json
from pathlib import Path

from tools.operator.documentary_truth_validate import build_documentary_truth_report


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_documentary_truth_policy_points_board_and_readiness_to_pointer(tmp_path: Path) -> None:
    _write(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "documentary_truth_policy.json",
        {
            "active_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
            "active_supporting_truth_surfaces": ["KT_PROD_CLEANROOM/reports/current_state_receipt.json"],
            "documentary_only_patterns": ["docs/**"],
        },
    )
    _write(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {"authoritative_current_head_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"},
    )
    _write(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json",
        {"authoritative_truth_source": "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"},
    )
    _write(
        tmp_path / "KT_PROD_CLEANROOM" / "exports" / "_truth" / "current" / "current_pointer.json",
        {"status": "ACTIVE"},
    )

    report = build_documentary_truth_report(root=tmp_path)
    assert report["status"] == "PASS"

