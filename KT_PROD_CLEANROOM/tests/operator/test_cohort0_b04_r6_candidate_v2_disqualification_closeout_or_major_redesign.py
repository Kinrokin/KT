from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_candidate_v2_disqualification_closeout_or_major_redesign as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": "input-head",
        "subject_main_head": "input-head",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _guard_rows() -> list[dict]:
    return [
        {
            "case_id": "R6B05",
            "family": "mixed_math_governance",
            "control_degradation": True,
            "abstention_collapse": True,
            "overrouting_collapse": True,
            "cause_class": "CANDIDATE_BEHAVIOR_DEFECT",
        }
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    common = {**_base(), "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE}
    payloads = {
        "v1_receipt": {
            **common,
            "schema_id": "v1_receipt",
            "verdict": tranche.V1_VERDICT,
            "candidate_win_count": 0,
            "case_count": 4,
            "disqualifier_count": 0,
        },
        "v1_scorecard": {
            **common,
            "schema_id": "v1_scorecard",
            "screen_verdict": tranche.V1_VERDICT,
            "candidate_win_count": 0,
            "case_count": 4,
            "disqualifier_count": 0,
        },
        "v1_disqualifier_ledger": {**common, "schema_id": "v1_disqualifiers", "entries": [], "triggered_count": 0},
        "v2_receipt": {
            **common,
            "schema_id": "v2_receipt",
            "verdict": tranche.V2_VERDICT,
            "candidate_win_count": 0,
            "case_count": 6,
            "disqualifier_count": 3,
        },
        "v2_scorecard": {
            **common,
            "schema_id": "v2_scorecard",
            "screen_verdict": tranche.V2_VERDICT,
            "candidate_win_count": 0,
            "case_count": 6,
            "disqualifier_count": 3,
        },
        "v2_disqualifier_ledger": {
            **common,
            "schema_id": "v2_disqualifiers",
            "entries": [
                {"disqualifier_id": "CONTROL_DEGRADATION", "triggered": True},
                {"disqualifier_id": "ABSTENTION_COLLAPSE", "triggered": True},
                {"disqualifier_id": "OVERRouting_COLLAPSE", "triggered": True},
            ],
            "triggered_count": 3,
        },
        "forensic_receipt": {
            **common,
            "schema_id": "forensic",
            "verdict": tranche.FORENSIC_VERDICT,
            "cause_class": "CANDIDATE_BEHAVIOR_DEFECT",
            "candidate_v2_disqualified_for_current_r6_screen_law": True,
        },
        "rerun_bar_receipt": {
            **common,
            "schema_id": "rerun_bar",
            "verdict": tranche.FORENSIC_VERDICT,
            "rerun_allowed": False,
            "rerun_bar_active": True,
        },
        "guard_failure_matrix": {**common, "schema_id": "guard", "rows": _guard_rows()},
        "v2_overrouting_autopsy": {**common, "schema_id": "overrouting", "rows": _guard_rows()},
        "v2_abstention_autopsy": {**common, "schema_id": "abstention", "rows": _guard_rows()},
        "v2_control_autopsy": {**common, "schema_id": "control", "rows": _guard_rows()},
        "previous_next_lawful_move": {
            **common,
            "schema_id": "next",
            "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE,
        },
    }
    for role, payload in payloads.items():
        raw = tranche.INPUTS.get(role) or tranche.HANDOFF_INPUTS[role]
        _write_json(root / raw, payload)
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = tranche.AUTHORITY_BRANCH,
    head: str = "decision-head",
    origin_main: str = "decision-head",
) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(
        tranche.common,
        "git_rev_parse",
        lambda root, ref: origin_main if ref == "origin/main" else head,
    )
    monkeypatch.setattr(
        tranche,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []},
    )


def test_major_redesign_authorized_and_quick_v3_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["disqualification_receipt"])
    options = _load(reports / tranche.OUTPUTS["major_redesign_options"])
    blockers = _load(reports / tranche.OUTPUTS["blocker_ledger"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])
    packet = _load(reports / tranche.OUTPUTS["disqualification_packet"])

    assert result["verdict"] == tranche.OUTCOME_MAJOR_REDESIGN
    assert receipt["candidate_v2_disqualified"] is True
    assert receipt["ordinary_candidate_v3_revision_allowed"] is False
    assert receipt["major_redesign_authorized"] is True
    assert options["quick_candidate_v3_patch_allowed"] is False
    assert blockers["live_blocker_count"] == 4
    assert next_receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE
    input_paths = {row["path"] for row in packet["input_bindings"]}
    assert tranche.HANDOFF_INPUTS["previous_next_lawful_move"] not in input_paths
    assert "KT_PROD_CLEANROOM/reports/b04_r6_static_comparator_dominance_analysis.json" not in input_paths


def test_fails_closed_if_rerun_bar_not_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    rerun = _load(reports / "b04_r6_second_shadow_screen_rerun_bar_receipt.json")
    rerun["rerun_allowed"] = True
    _write_json(reports / "b04_r6_second_shadow_screen_rerun_bar_receipt.json", rerun)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="second shadow rerun must be barred"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_guard_collapse_evidence_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    guard = _load(reports / "b04_r6_candidate_v2_guard_failure_matrix.json")
    guard["rows"][0]["overrouting_collapse"] = False
    _write_json(reports / "b04_r6_candidate_v2_guard_failure_matrix.json", guard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="missing over-routing-collapse guard evidence"):
        tranche.run(reports_root=reports)


def test_runs_on_canonical_main_when_converged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    assert result["verdict"] == tranche.OUTCOME_MAJOR_REDESIGN
    assert _load(reports / tranche.OUTPUTS["disqualification_receipt"])["current_git_head"] == "main-head"


def test_replay_accepts_already_frozen_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = tranche.NEXT_LAWFUL_MOVE
    next_receipt["status"] = "FROZEN_PACKET"
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    assert result["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_authority_branch_rejects_already_frozen_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = tranche.NEXT_LAWFUL_MOVE
    next_receipt["status"] = "FROZEN_PACKET"
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path, branch=tranche.AUTHORITY_BRANCH)

    with pytest.raises(RuntimeError, match="previous next-lawful-move receipt mismatch"):
        tranche.run(reports_root=reports)


def test_fails_closed_on_noncanonical_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="local-main", origin_main="origin-main")

    with pytest.raises(RuntimeError, match="main replay requires local main converged with origin/main"):
        tranche.run(reports_root=reports)
