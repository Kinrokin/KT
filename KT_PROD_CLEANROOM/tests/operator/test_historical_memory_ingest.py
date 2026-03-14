from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.historical_memory_ingest import (  # noqa: E402
    build_forgotten_surface_register,
    build_historical_claims,
    build_historical_conflicts,
    build_historical_resolutions,
    build_reopened_defect_register,
)
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_historical_memory_builders_are_structurally_complete() -> None:
    root = repo_root()

    claims = build_historical_claims(root=root)
    conflicts = build_historical_conflicts(root=root)
    resolutions = build_historical_resolutions(root=root)
    forgotten = build_forgotten_surface_register(root=root)
    reopened = build_reopened_defect_register(root=root)

    assert claims["schema_id"] == "kt.operator.historical_claims.v1"
    assert len(claims["source_families"]) >= 6
    assert len(claims["claims"]) >= 8
    assert claims["crucible_history"]["registered_crucibles"] >= 14
    assert claims["crucible_history"]["total_runs"] > 0
    assert len(claims["crucible_history"]["exemplar_runs"]) >= 4

    assert conflicts["schema_id"] == "kt.operator.historical_conflicts.v1"
    assert len(conflicts["historical_blocker_conflicts"]) >= 8
    assert len(conflicts["historical_receipt_conflicts"]) >= 12
    assert len(conflicts["codex_conflict_models"]) == 2
    assert conflicts["historical_posture_conflict_receipt"]["status"] == "PASS"

    assert resolutions["schema_id"] == "kt.operator.historical_resolutions.v1"
    assert len(resolutions["historical_governance_ladders"]) >= 5
    assert any(row["ladder_id"] == "WS0_WS11_CLOSEOUT_20260314" for row in resolutions["historical_governance_ladders"])
    assert len(resolutions["resolved_blockers"]) >= 3
    assert len(resolutions["receipt_clearances"]) >= 12

    assert forgotten["schema_id"] == "kt.operator.forgotten_surface_register.v1"
    assert len(forgotten["surfaces"]) >= 18
    assert any(row["surface_ref"] == "KT-Codex/metadata/manifest.json" for row in forgotten["surfaces"])
    assert all(bool(row["exists"]) for row in forgotten["surfaces"])

    assert reopened["schema_id"] == "kt.operator.reopened_defect_register.v1"
    assert len(reopened["defects"]) >= 8
    assert any(row["defect_id"] == "LOCAL_RESIDUE_PRESENT" and row["current_status"] == "STILL_OPEN" for row in reopened["defects"])
    assert any(row["defect_id"] == "TARGET_NOT_REMOTE_EQUAL" and row["current_status"] == "RESOLVED_LATER" for row in reopened["defects"])
