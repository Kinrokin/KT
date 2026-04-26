from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r1_r5_revalidation_asset_supersession_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _pass(schema_id: str) -> dict:
    return {"schema_id": schema_id, "status": "PASS"}


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "upper_stack_ratification_readiness_receipt.json",
        {
            **_pass("upper_receipt"),
            "next_lawful_move": "AUTHOR_B04_R1_R5_REVALIDATION_ASSET_SUPERSESSION_PACKET",
            "r1_through_r5_active_revalidation_replay_status": "BLOCKED_MISSING_CURRENT_CAMPAIGN_STATE_OVERLAY",
        },
    )
    _write_json(
        reports / "upper_stack_blocker_ledger.json",
        {
            **_pass("upper_blockers"),
            "live_blocker_count": 0,
            "entries": [{"blocker_id": "B04_R1_R5_ACTIVE_REVALIDATION_OVERLAY_MISSING"}],
        },
    )
    _write_json(
        reports / "upper_stack_next_ratification_lane_recommendation.json",
        {**_pass("upper_recommendation"), "recommended_next_move": "AUTHOR_B04_R1_R5_REVALIDATION_ASSET_SUPERSESSION_PACKET"},
    )
    _write_json(
        reports / "next_counted_workstream_contract.json",
        {
            "schema_id": "next",
            "source_workstream_id": tranche.R5_STEP_ID,
            "exact_next_counted_workstream_id": tranche.R6_STEP_ID,
            "execution_mode": "R6_NEXT_IN_ORDER_BLOCKED_PENDING_EARNED_SUPERIORITY__INITIAL_R5_PROOF_COMPLETE",
            "repo_state_executable_now": False,
        },
    )
    _write_json(
        reports / "resume_blockers_receipt.json",
        {
            **_pass("resume"),
            "workstream_id": tranche.R5_STEP_ID,
            "exact_next_counted_workstream_id": tranche.R6_STEP_ID,
            "repo_state_executable_now": False,
        },
    )
    _write_json(
        reports / "gate_d_decision_reanchor_packet.json",
        {"schema_id": "reanchor", "workstream_id": tranche.R5_STEP_ID, "next_lawful_move": tranche.R6_HOLD_MOVE},
    )
    _write_json(reports / "router_superiority_scorecard.json", {**_pass("scorecard"), "superiority_earned": False})
    for filename in [
        "cohort0_post_f_truth_engine_authority_graph.json",
        "cohort0_post_f_truth_engine_posture_index.json",
        "post_boundary_canonical_regrade_audit_receipt.json",
        "crucible_pressure_law_ratification_receipt.json",
        "adapter_lifecycle_law_ratification_receipt.json",
        "tournament_promotion_merge_law_ratification_receipt.json",
        "router_shadow_evaluation_ratification_receipt.json",
        "router_vs_best_adapter_proof_ratification_receipt.json",
    ]:
        _write_json(reports / filename, _pass(filename))
    for filename in ["canonical_scope_manifest.json", "readiness_scope_manifest.json"]:
        _write_json(governance / filename, {"schema_id": filename, "status": "ACTIVE"})
    return reports, governance


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(
        tranche,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []},
    )
    monkeypatch.setattr(
        tranche,
        "_run_active_replay",
        lambda root: {
            "r1": {"status": "PASS"},
            "r2": {"status": "PASS"},
            "r3": {"status": "PASS"},
            "r4": {"status": "PASS"},
            "r5": {"status": "PASS", "next_lawful_move": tranche.R6_HOLD_MOVE},
        },
    )


def test_b04_r1_r5_supersession_materializes_overlay_and_replay_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    overlay = _load(reports / tranche.CURRENT_OVERLAY)
    packet = _load(reports / tranche.OUTPUT_PACKET)
    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    replay = _load(reports / tranche.OUTPUT_REPLAY_RECEIPT)

    assert result["outcome"] == tranche.OUTCOME
    assert overlay["schema_id"] == "kt.current_campaign_state_overlay.v1"
    assert overlay["workstream_id"] == tranche.R5_STEP_ID
    assert overlay["next_counted_workstream_id"] == tranche.R6_STEP_ID
    assert overlay["repo_state_executable_now"] is False
    assert packet["resolution_class"] == "MATERIALIZE_DERIVED_CURRENT_OVERLAY_AND_PATCH_SETTLED_REPLAY_CONTRACT"
    assert receipt["active_r1_r5_replay_passed"] is True
    assert replay["status"] == "PASS"
    assert replay["next_lawful_move"] == tranche.NEXT_MOVE


def test_b04_r1_r5_supersession_fails_if_router_superiority_is_already_earned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["superiority_earned"] = True
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="router superiority is already earned"):
        tranche.run(reports_root=reports, governance_root=governance)
