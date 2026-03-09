from __future__ import annotations

import json
from pathlib import Path

from tools.operator.truth_surface_sync import _sync_secondary_surfaces


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_sync_secondary_surfaces_updates_authority_mode_and_freeze_refs(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json",
        {
            "schema_id": "kt.governance.readiness_scope_manifest.v2",
            "readiness_includes_zones": ["CANONICAL"],
            "readiness_excludes_zones": ["LAB", "ARCHIVE", "COMMERCIAL", "GENERATED_RUNTIME_TRUTH", "QUARANTINED"],
            "current_blockers": [],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json",
        {
            "schema_id": "kt.governance.execution_board.v2",
            "workstreams": [
                {"workstream_id": "PHASE_0_CORE_TRUTH_REPAIR", "status": "BLOCKED"},
                {"workstream_id": "PHASE_1_H0_FREEZE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_2_TRUTH_ENGINE", "status": "BLOCKED"},
                {"workstream_id": "PHASE_3_BOUNDARY_PURIFICATION", "status": "BLOCKED"},
            ],
        },
    )
    _write_json(
        tmp_path / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json",
        {
            "schema_id": "kt.governance.h0_freeze_policy.v2",
            "activation_state": "PENDING_TRUTHFUL_GREEN",
            "current_posture_state": "TRUTH_DEFECTS_PRESENT",
        },
    )

    _sync_secondary_surfaces(
        root=tmp_path,
        posture_state="CANONICAL_READY_FOR_REEARNED_GREEN",
        live_head="abc123",
        truth_source_ref="KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json",
        authority_mode="SETTLED_AUTHORITATIVE",
        open_blockers=["CLEAN_CLONE_NOT_RUN"],
    )

    readiness = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "readiness_scope_manifest.json").read_text(encoding="utf-8"))
    board = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "execution_board.json").read_text(encoding="utf-8"))
    freeze = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "governance" / "h0_freeze_policy.json").read_text(encoding="utf-8"))
    promotion = json.loads((tmp_path / "KT_PROD_CLEANROOM" / "reports" / "settled_authority_promotion_receipt.json").read_text(encoding="utf-8"))

    assert readiness["current_authority_mode"] == "SETTLED_AUTHORITATIVE"
    assert readiness["authoritative_truth_source"] == "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json"
    assert "CLEAN_CLONE_NOT_RUN" in readiness["current_blockers"]

    assert board["authority_mode"] == "SETTLED_AUTHORITATIVE"
    assert board["authoritative_current_head_truth_source"] == "KT_PROD_CLEANROOM/reports/settled_truth_source_receipt.json"
    assert board["last_synced_head_sha"] == "abc123"
    assert board["program_gates"]["FOUNDATIONAL_LAW_TRANCHE_COMPLETE"] is True
    assert board["program_gates"]["H1_ACTIVATION_ALLOWED"] is False

    assert freeze["freeze_scope_manifest"] == "KT_PROD_CLEANROOM/governance/canonical_freeze_manifest.json"
    assert freeze["amendment_scope_manifest"] == "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json"
    assert promotion["new_authority_state"] == "SETTLED_AUTHORITATIVE"
    assert promotion["promotion_verdict"] == "PASS"
