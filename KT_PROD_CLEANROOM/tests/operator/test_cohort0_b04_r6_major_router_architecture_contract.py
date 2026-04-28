from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_major_router_architecture_contract as tranche


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
        "prior_scope_packet": {**common, "schema_id": "prior_scope_packet"},
        "prior_scope_receipt": {
            **common,
            "schema_id": "prior_scope_receipt",
            "selected_outcome": tranche.EXPECTED_PREVIOUS_OUTCOME,
            "architecture_contract_next": True,
            "candidate_generation_authorized": False,
            "new_shadow_screen_authorized": False,
            "quick_candidate_v3_forbidden": True,
        },
        "prior_retirement_receipt": {
            **common,
            "schema_id": "prior_retirement",
            "retired_for_r6": True,
            "quick_candidate_v3_forbidden": True,
            "old_blind_universes_diagnostic_only": True,
        },
        "prior_redesign_blocker_ledger": {
            **common,
            "schema_id": "prior_blockers",
            "live_blockers_to_r6_open": [],
            "no_blockers_to_architecture_contract": True,
        },
        "prior_architecture_options": {
            **common,
            "schema_id": "prior_options",
            "options": [{"option_id": "ABSTENTION_FIRST_STATIC_HOLD_ROUTER"}],
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
    head: str = "architecture-head",
    origin_main: str = "architecture-head",
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


def test_architecture_contract_selects_afsh_without_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    contract = _load(reports / tranche.OUTPUTS["architecture_contract"])
    receipt = _load(reports / tranche.OUTPUTS["architecture_receipt"])
    rationale = _load(reports / tranche.OUTPUTS["architecture_selection_rationale"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == tranche.OUTCOME_BOUND
    assert receipt["selected_architecture_id"] == tranche.SELECTED_ARCHITECTURE_ID
    assert receipt["candidate_generation_authorized"] is False
    assert receipt["new_shadow_screen_authorized"] is False
    assert contract["selected_architecture_contract"]["default_outcome"] == "STATIC_HOLD"
    assert contract["selected_architecture_contract"]["route_requires_positive_justification"] is True
    assert contract["major_redesign_definition"]["weight_or_threshold_only_patch_counts"] is False
    assert contract["new_blind_universe_requirement"]["six_row_second_screen_reuse_as_fresh_counted_proof_allowed"] is False
    assert rationale["why_not_pure_learned_selector"]
    assert next_receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_fails_closed_if_prior_scope_not_authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    scope = _load(reports / "b04_r6_major_router_redesign_scope_receipt.json")
    scope["selected_outcome"] = "R6_DEFERRED__REDESIGN_SCOPE_INSUFFICIENT"
    _write_json(reports / "b04_r6_major_router_redesign_scope_receipt.json", scope)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="previous scope court did not authorize architecture contract"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_candidate_generation_already_authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    scope = _load(reports / "b04_r6_major_router_redesign_scope_receipt.json")
    scope["candidate_generation_authorized"] = True
    _write_json(reports / "b04_r6_major_router_redesign_scope_receipt.json", scope)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="candidate generation must remain unauthorized"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_abstention_first_option_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    options = _load(reports / "b04_r6_major_router_architecture_options_matrix.json")
    options["options"] = [{"option_id": "PURE_LEARNED_SELECTOR"}]
    _write_json(reports / "b04_r6_major_router_architecture_options_matrix.json", options)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="abstention-first static-hold option must be present"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_prior_architecture_blocker_remains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    blockers = _load(reports / "b04_r6_major_redesign_blocker_ledger.json")
    blockers["no_blockers_to_architecture_contract"] = False
    _write_json(reports / "b04_r6_major_redesign_blocker_ledger.json", blockers)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="prior blocker ledger must clear architecture-contract entry"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_guard_collapse_evidence_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    guard = _load(reports / "b04_r6_candidate_v2_guard_failure_matrix.json")
    guard["rows"][0]["control_degradation"] = False
    _write_json(reports / "b04_r6_candidate_v2_guard_failure_matrix.json", guard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="missing control-degradation guard evidence"):
        tranche.run(reports_root=reports)


def test_runs_on_canonical_main_when_converged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    assert result["verdict"] == tranche.OUTCOME_BOUND
    assert _load(reports / tranche.OUTPUTS["architecture_receipt"])["current_git_head"] == "main-head"


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
