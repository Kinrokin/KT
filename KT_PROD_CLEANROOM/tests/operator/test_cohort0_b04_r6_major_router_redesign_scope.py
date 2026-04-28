from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_major_router_redesign_scope as tranche


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
            "candidate_win_count": 0,
            "case_count": 4,
            "disqualifier_count": 0,
        },
        "v2_receipt": {
            **common,
            "schema_id": "v2_receipt",
            "candidate_win_count": 0,
            "case_count": 6,
            "disqualifier_count": 3,
        },
        "forensic_receipt": {
            **common,
            "schema_id": "forensic",
            "cause_class": "CANDIDATE_BEHAVIOR_DEFECT",
            "candidate_v2_disqualified_for_current_r6_screen_law": True,
        },
        "rerun_bar_receipt": {
            **common,
            "schema_id": "rerun_bar",
            "rerun_allowed": False,
            "rerun_bar_active": True,
        },
        "guard_failure_matrix": {**common, "schema_id": "guard", "rows": _guard_rows()},
        "prior_disqualification_receipt": {
            **common,
            "schema_id": "prior_disqualification",
            "selected_outcome": tranche.EXPECTED_PREVIOUS_OUTCOME,
            "current_candidate_family_retired": True,
            "ordinary_candidate_v3_revision_allowed": False,
            "new_router_architecture_required": True,
            "new_blind_universe_required": True,
        },
        "prior_family_autopsy": {**common, "schema_id": "prior_family", "family_assessment": "RETIRED"},
        "prior_major_redesign_options": {**common, "schema_id": "prior_options", "options": []},
        "prior_redesign_blocker_ledger": {
            **common,
            "schema_id": "prior_blockers",
            "live_blockers_to_R6_open": [],
        },
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
    head: str = "scope-head",
    origin_main: str = "scope-head",
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


def test_scope_authorized_without_candidate_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    scope = _load(reports / tranche.OUTPUTS["scope_packet"])
    receipt = _load(reports / tranche.OUTPUTS["scope_receipt"])
    retirement = _load(reports / tranche.OUTPUTS["candidate_family_retirement"])
    options = _load(reports / tranche.OUTPUTS["architecture_options"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == tranche.OUTCOME_SCOPE_AUTHORIZED
    assert receipt["major_redesign_scope_authorized"] is True
    assert receipt["candidate_generation_authorized"] is False
    assert receipt["new_shadow_screen_authorized"] is False
    assert retirement["retired_for_r6"] is True
    assert retirement["quick_candidate_v3_forbidden"] is True
    assert scope["major_redesign_standard"]["threshold_or_weight_tweak_counts_as_major_redesign"] is False
    assert scope["new_blind_universe_law"]["six_row_blind_universe_reuse_as_fresh_proof_allowed"] is False
    assert options["status"] == "PREP_ONLY"
    assert next_receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_fails_closed_if_quick_v3_not_barred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    prior = _load(reports / "b04_r6_candidate_v2_disqualification_receipt.json")
    prior["ordinary_candidate_v3_revision_allowed"] = True
    _write_json(reports / "b04_r6_candidate_v2_disqualification_receipt.json", prior)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="ordinary candidate v3 revision must be barred"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_previous_next_move_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = "AUTHOR_WRONG_LANE"
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="previous next-lawful-move receipt mismatch"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_guard_collapse_evidence_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    guard = _load(reports / "b04_r6_candidate_v2_guard_failure_matrix.json")
    guard["rows"][0]["abstention_collapse"] = False
    _write_json(reports / "b04_r6_candidate_v2_guard_failure_matrix.json", guard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="missing abstention-collapse guard evidence"):
        tranche.run(reports_root=reports)


def test_runs_on_canonical_main_when_converged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    assert result["verdict"] == tranche.OUTCOME_SCOPE_AUTHORIZED
    assert _load(reports / tranche.OUTPUTS["scope_receipt"])["current_git_head"] == "main-head"


def test_main_replay_accepts_already_frozen_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="previous next-lawful-move receipt mismatch"):
        tranche.run(reports_root=reports)


def test_fails_closed_on_noncanonical_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="local-main", origin_main="origin-main")

    with pytest.raises(RuntimeError, match="main replay requires local main converged with origin/main"):
        tranche.run(reports_root=reports)
