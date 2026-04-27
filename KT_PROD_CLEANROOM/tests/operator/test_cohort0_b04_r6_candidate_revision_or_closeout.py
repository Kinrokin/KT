from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_candidate_revision_or_closeout as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base() -> dict:
    return {
        "status": "PASS",
        "current_git_head": "screen-head",
        "subject_main_head": "subject-head",
        "r6_authorized": False,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "learned_router_activated": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _route_rows() -> list[dict]:
    return [
        {
            "case_id": "R01",
            "family": "math",
            "baseline_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
            "candidate_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
            "candidate_beats_static": False,
            "exact_order_match": True,
            "no_regression_pass": True,
            "order_advisory": False,
            "route_quality_delta": 0,
            "route_set_match": True,
        },
        {
            "case_id": "R02",
            "family": "poetry",
            "baseline_adapter_ids": ["lobe.muse.v1"],
            "candidate_adapter_ids": ["lobe.muse.v1"],
            "candidate_beats_static": False,
            "exact_order_match": True,
            "no_regression_pass": True,
            "order_advisory": False,
            "route_quality_delta": 0,
            "route_set_match": True,
        },
        {
            "case_id": "R03",
            "family": "governance",
            "baseline_adapter_ids": ["lobe.auditor.v1", "lobe.censor.v1"],
            "candidate_adapter_ids": ["lobe.censor.v1", "lobe.auditor.v1"],
            "candidate_beats_static": False,
            "exact_order_match": False,
            "no_regression_pass": True,
            "order_advisory": True,
            "route_quality_delta": 0,
            "route_set_match": True,
        },
        {
            "case_id": "R04",
            "family": "default",
            "baseline_adapter_ids": ["lobe.strategist.v1"],
            "candidate_adapter_ids": ["lobe.strategist.v1"],
            "candidate_beats_static": False,
            "exact_order_match": True,
            "no_regression_pass": True,
            "order_advisory": False,
            "route_quality_delta": 0,
            "route_set_match": True,
        },
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    receipt = {
        **_base(),
        "schema_id": "receipt",
        "verdict": tranche.EXPECTED_PREVIOUS_VERDICT,
        "candidate_win_count": 0,
        "case_count": 4,
        "disqualifier_count": 0,
        "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE,
    }
    scorecard = {
        **_base(),
        "schema_id": "scorecard",
        "screen_verdict": tranche.EXPECTED_PREVIOUS_VERDICT,
        "candidate_win_count": 0,
        "case_count": 4,
        "disqualifier_count": 0,
        "metrics": {
            "route_superiority": {
                "candidate_beats_static_count": 0,
                "order_advisory_count": 1,
                "route_set_match_rate": 1.0,
                "superiority_threshold_met": False,
            },
            "outcome_delta": {"result": "NO_USEFUL_OUTPUT_DELTA_EVIDENCE_BOUND", "signed_delta": 0},
            "control_preservation": {"result": "PASS"},
            "abstention_quality": {"result": "PASS"},
            "overrouting_penalty": {"result": "PASS"},
            "mirror_masked_invariance": {"result": "PASS"},
            "no_regression": {"result": "PASS"},
            "consequence_visibility": {"result": "PASS"},
        },
    }
    route_matrix = {**_base(), "schema_id": "route_matrix", "rows": _route_rows(), "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE}
    abstention_matrix = {
        **_base(),
        "schema_id": "abstention_matrix",
        "rows": [
            {"case_id": "R01", "candidate_abstained": False, "fallback_expected": False, "overrouting_detected": False, "static_hold_preserved": True},
            {"case_id": "R02", "candidate_abstained": False, "fallback_expected": False, "overrouting_detected": False, "static_hold_preserved": True},
            {"case_id": "R03", "candidate_abstained": False, "fallback_expected": False, "overrouting_detected": False, "static_hold_preserved": True},
            {"case_id": "R04", "candidate_abstained": True, "fallback_expected": True, "overrouting_detected": False, "static_hold_preserved": True},
        ],
        "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE,
    }
    invariance_matrix = {
        **_base(),
        "schema_id": "invariance_matrix",
        "rows": [
            {"case_id": case_id, "variant": variant, "invariance_pass": True}
            for case_id in ("R01", "R02", "R03", "R04")
            for variant in ("mirror", "masked")
        ],
        "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE,
    }
    simple = {
        "screen_receipt": receipt,
        "scorecard": scorecard,
        "route_matrix": route_matrix,
        "abstention_matrix": abstention_matrix,
        "invariance_matrix": invariance_matrix,
        "disqualifier_ledger": {**_base(), "schema_id": "disqualifier_ledger", "entries": [], "triggered_count": 0, "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE},
        "superiority_blocker_ledger": {**_base(), "schema_id": "blocker_ledger", "entries": [{"blocker_id": "superiority_not_earned"}], "live_blocker_count": 1, "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE},
        "previous_next_lawful_move": {**_base(), "schema_id": "next", "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE},
    }
    for role, payload in simple.items():
        _write_json(root / tranche.INPUTS[role], payload)
    return reports


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "revision-head")


def test_revision_or_closeout_defers_until_new_blind_input_universe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["authority_receipt"])
    blind = _load(reports / tranche.OUTPUTS["blind_input_requirement_receipt"])
    eligibility = _load(reports / tranche.OUTPUTS["revision_eligibility_receipt"])
    blockers = _load(reports / tranche.OUTPUTS["revision_blocker_ledger"])

    assert result["verdict"] == tranche.FINAL_VERDICT
    assert receipt["r6_open"] is False
    assert receipt["candidate_revision_allowed_next"] is True
    assert receipt["candidate_v2_generation_performed"] is False
    assert receipt["shadow_screen_execution_performed"] is False
    assert blind["new_blind_input_universe_required"] is True
    assert blind["r01_r04_closed_for_candidate_v2_counted_superiority_rerun"] is True
    assert eligibility["same_r01_r04_reuse_for_counted_superiority_screen_allowed"] is False
    assert blockers["live_blocker_count"] == 2


def test_revision_or_closeout_fails_closed_for_disqualified_screen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_shadow_router_superiority_screen_receipt.json")
    receipt["disqualifier_count"] = 1
    _write_json(reports / "b04_r6_shadow_router_superiority_screen_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="disqualified"):
        tranche.run(reports_root=reports)


def test_revision_or_closeout_fails_closed_if_previous_next_move_mismatches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_shadow_router_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write_json(reports / "b04_r6_shadow_router_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="next-lawful-move"):
        tranche.run(reports_root=reports)


def test_revision_or_closeout_fails_closed_if_candidate_had_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    scorecard = _load(reports / "b04_r6_shadow_router_superiority_scorecard.json")
    scorecard["candidate_win_count"] = 1
    _write_json(reports / "b04_r6_shadow_router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="zero-win"):
        tranche.run(reports_root=reports)
