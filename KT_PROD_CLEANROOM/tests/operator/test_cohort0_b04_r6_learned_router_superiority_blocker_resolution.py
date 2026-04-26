from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_learned_router_superiority_blocker_resolution as tranche


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
        reports / "b04_r1_r5_active_revalidation_replay_receipt.json",
        {
            **_pass("active_replay"),
            "next_lawful_move": "AUTHOR_B04_R6_LEARNED_ROUTER_SUPERIORITY_BLOCKER_RESOLUTION_PACKET",
            "r1_status": "PASS",
            "r2_status": "PASS",
            "r3_status": "PASS",
            "r4_status": "PASS",
            "r5_next_lawful_move": tranche.R6_HOLD_MOVE,
            "r5_status": "PASS",
            "r6_authorized": False,
            "router_superiority_earned": False,
        },
    )
    _write_json(
        reports / "current_campaign_state_overlay.json",
        {
            "schema_id": "overlay",
            "next_counted_workstream_id": tranche.R6_STEP_ID,
            "repo_state_executable_now": False,
        },
    )
    _write_json(reports / "b04_r1_r5_revalidation_asset_supersession_receipt.json", _pass("supersession"))
    _write_json(
        governance / "b04_r5_router_vs_best_adapter_terminal_state.json",
        {
            "schema_id": "r5_terminal",
            "learned_router_authorized": False,
            "next_lawful_move": tranche.R6_HOLD_MOVE,
            "router_superiority_earned": False,
            "static_router_remains_canonical": True,
        },
    )
    _write_json(
        reports / "router_superiority_scorecard.json",
        {
            **_pass("scorecard"),
            "best_static_baseline": {"adapter_id": "static.best.v1"},
            "current_git_head": "scorecard-head",
            "learned_router_candidate": {"candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT", "promotion_allowed": False},
            "overall_outcome": "HOLD_STATIC_CANONICAL_BASELINE",
            "subject_head": "scorecard-head",
            "superiority_earned": False,
        },
    )
    _write_json(
        reports / "next_counted_workstream_contract.json",
        {
            "schema_id": "next",
            "exact_next_counted_workstream_id": tranche.R6_STEP_ID,
            "repo_state_executable_now": False,
        },
    )
    _write_json(
        reports / "upper_stack_blocker_ledger.json",
        {
            **_pass("upper_blockers"),
            "entries": [{"blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"}],
        },
    )
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical_scope"})
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
        "_run_current_replay",
        lambda *, root, generated_utc, head, live_validation: {
            "schema_id": "replay",
            "status": "PASS",
            "current_git_head": head,
            "r1_status": "PASS",
            "r2_status": "PASS",
            "r3_status": "PASS",
            "r4_status": "PASS",
            "r5_next_lawful_move": tranche.R6_HOLD_MOVE,
            "r5_status": "PASS",
            "r6_authorized": False,
            "router_superiority_earned": False,
        },
    )


def test_r6_blocker_resolution_emits_authoritative_and_prep_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    authority = _load(reports / tranche.OUTPUTS["authority_packet"])
    blocker_ledger = _load(reports / tranche.OUTPUTS["blocker_ledger"])
    next_court = _load(reports / tranche.OUTPUTS["next_court_receipt"])
    comparator_draft = _load(reports / tranche.OUTPUTS["comparator_matrix_draft"])
    commercial_boundary = _load(reports / tranche.OUTPUTS["commercial_boundary_receipt"])
    harness = (reports / tranche.OUTPUTS["shadow_harness_draft"]).read_text(encoding="utf-8")

    assert result["outcome"] == tranche.OUTCOME
    assert authority["resolution_decision"] == tranche.SCREEN_ONLY_OUTCOME
    assert authority["r6_execution_authorized_now"] is False
    assert blocker_ledger["live_blocker_count"] == 1
    assert blocker_ledger["r6_blocker_count"] == 1
    assert next_court["next_lawful_move"] == tranche.NEXT_MOVE
    assert comparator_draft["authoritative"] is False
    assert commercial_boundary["status"] == "PREP_ONLY"
    assert "R6_AUTHORIZED = False" in harness


def test_r6_blocker_resolution_fails_if_superiority_is_already_claimed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["superiority_earned"] = True
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="router superiority scorecard must not claim superiority"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_r6_blocker_resolution_fails_if_scorecard_head_binding_is_malformed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["subject_head"] = "different-head"
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="current_git_head and subject_head must match"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_r6_blocker_resolution_fails_if_active_replay_authorizes_r6(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    replay = _load(reports / "b04_r1_r5_active_revalidation_replay_receipt.json")
    replay["r6_authorized"] = True
    _write_json(reports / "b04_r1_r5_active_revalidation_replay_receipt.json", replay)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="active replay receipt must keep R6 unauthorized"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_r6_blocker_resolution_fails_if_active_replay_drops_r5_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    replay = _load(reports / "b04_r1_r5_active_revalidation_replay_receipt.json")
    replay["r5_next_lawful_move"] = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
    _write_json(reports / "b04_r1_r5_active_revalidation_replay_receipt.json", replay)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="active replay receipt must preserve R5 static-hold R6 blocker"):
        tranche.run(reports_root=reports, governance_root=governance)
