from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_second_shadow_forensic_rerun_bar as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": "screen-head",
        "subject_main_head": "screen-head",
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


def _route_rows() -> list[dict]:
    rows = [
        ("R6B01", "math", False, False, ["lobe.censor.v1", "lobe.quant.v1"], ["lobe.censor.v1", "lobe.quant.v1"], 0),
        ("R6B02", "poetry", False, False, ["lobe.muse.v1"], ["lobe.muse.v1"], 0),
        ("R6B03", "governance", False, False, ["lobe.auditor.v1", "lobe.censor.v1"], ["lobe.auditor.v1", "lobe.censor.v1"], 0),
        ("R6B04", "default", True, True, ["lobe.strategist.v1"], ["lobe.strategist.v1"], 0),
        ("R6B05", "mixed_math_governance", True, False, ["lobe.auditor.v1", "lobe.quant.v1", "lobe.censor.v1"], ["lobe.strategist.v1"], -1),
        ("R6B06", "masked_ambiguous", True, True, ["lobe.strategist.v1"], ["lobe.strategist.v1"], 0),
    ]
    return [
        {
            "case_id": case_id,
            "family": family,
            "static_fallback_expected": fallback,
            "candidate_abstained": abstained,
            "candidate_adapter_ids": candidate,
            "static_adapter_ids": static,
            "candidate_beats_static": False,
            "route_quality_delta": delta,
        }
        for case_id, family, fallback, abstained, candidate, static, delta in rows
    ]


def _abstention_rows() -> list[dict]:
    return [
        {
            "case_id": row["case_id"],
            "fallback_expected": row["static_fallback_expected"],
            "candidate_abstained": row["candidate_abstained"],
            "static_hold_preserved": not (row["case_id"] == "R6B05"),
            "overrouting_detected": row["case_id"] == "R6B05",
        }
        for row in _route_rows()
    ]


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    route_rows = _route_rows()
    abstention_rows = _abstention_rows()
    common = {**_base(), "next_lawful_move": tranche.EXPECTED_PRIOR_NEXT_MOVE}
    disqualifiers = [
        {"disqualifier_id": "CONTROL_DEGRADATION", "triggered": True, "effect": "SCREEN_INVALIDATE"},
        {"disqualifier_id": "ABSTENTION_COLLAPSE", "triggered": True, "effect": "SCREEN_INVALIDATE"},
        {"disqualifier_id": "OVERRouting_COLLAPSE", "triggered": True, "effect": "SCREEN_INVALIDATE"},
    ]
    payloads = {
        "result_packet": {**common, "schema_id": "result_packet", "verdict": tranche.PRIOR_VERDICT},
        "result_receipt": {
            **common,
            "schema_id": "result_receipt",
            "verdict": tranche.PRIOR_VERDICT,
            "candidate_win_count": 0,
            "case_count": 6,
            "disqualifier_count": 3,
        },
        "scorecard": {
            **common,
            "schema_id": "scorecard",
            "screen_verdict": tranche.PRIOR_VERDICT,
            "candidate_win_count": 0,
            "case_count": 6,
            "disqualifier_count": 3,
        },
        "route_trace": {**common, "schema_id": "route_trace", "rows": route_rows},
        "abstention_overrouting": {**common, "schema_id": "abstention", "rows": abstention_rows},
        "mirror_masked_invariance": {**common, "schema_id": "invariance", "rows": []},
        "disqualifier_ledger": {**common, "schema_id": "ledger", "entries": disqualifiers, "triggered_count": 3},
        "screen_execution_packet": {**_base("FROZEN_PACKET"), "schema_id": "screen_packet"},
        "screen_execution_receipt": {**common, "schema_id": "screen_receipt"},
        "screen_disqualifier_contract": {
            **_base("FROZEN_PACKET"),
            "schema_id": "contract",
            "hard_disqualifiers": [
                {"id": "CONTROL_DEGRADATION", "effect": "SCREEN_INVALIDATE"},
                {"id": "ABSTENTION_COLLAPSE", "effect": "SCREEN_INVALIDATE"},
                {"id": "OVERRouting_COLLAPSE", "effect": "SCREEN_INVALIDATE"},
            ],
        },
        "candidate_v2_admissibility": {**common, "schema_id": "admissibility", "candidate_v2_admissible": True},
        "candidate_v2_manifest": {**common, "schema_id": "manifest"},
        "blind_contract": {**common, "schema_id": "blind", "row_count": 6, "candidate_rows": [{"case_id": f"R6B0{i}"} for i in range(1, 7)]},
        "metric_contract": {**common, "schema_id": "metric"},
        "static_baseline_guard": {**_base("PREP_ONLY"), "schema_id": "static_guard", "static_baseline_mutated": False},
    }
    for role, payload in payloads.items():
        _write_json(root / tranche.INPUTS[role], payload)
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = tranche.AUTHORITY_BRANCH,
    head: str = "forensic-head",
    origin_main: str = "forensic-head",
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


def test_forensic_confirms_candidate_behavior_and_bars_rerun(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["forensic_receipt"])
    rerun = _load(reports / tranche.OUTPUTS["rerun_bar_receipt"])
    guard = _load(reports / tranche.OUTPUTS["guard_failure_matrix"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == tranche.VERDICT_CANDIDATE_DISQUALIFIED
    assert result["cause_class"] == "CANDIDATE_BEHAVIOR_DEFECT"
    assert receipt["candidate_v2_disqualified_for_current_r6_screen_law"] is True
    assert rerun["rerun_allowed"] is False
    assert rerun["rerun_bar_active"] is True
    assert any(row["case_id"] == "R6B05" and row["overrouting_collapse"] for row in guard["rows"])
    assert next_receipt["next_lawful_move"] == tranche.NEXT_CANDIDATE_DISQUALIFIED


def test_forensic_runs_on_canonical_main_when_converged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    receipt = _load(reports / tranche.OUTPUTS["forensic_receipt"])
    assert result["verdict"] == tranche.VERDICT_CANDIDATE_DISQUALIFIED
    assert receipt["current_git_head"] == "main-head"


def test_forensic_fails_closed_on_noncanonical_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="local-main", origin_main="origin-main")

    with pytest.raises(RuntimeError, match="main replay requires local main converged with origin/main"):
        tranche.run(reports_root=reports)


def test_forensic_fails_closed_on_disallowed_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/not-authorized")

    with pytest.raises(RuntimeError, match="got: feature/not-authorized"):
        tranche.run(reports_root=reports)


def test_forensic_fails_closed_if_prior_verdict_is_not_invalidated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    result_receipt = _load(reports / "b04_r6_second_shadow_screen_result_receipt.json")
    result_receipt["verdict"] = "R6_SECOND_SHADOW_SUPERIORITY_FAILED__LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
    _write_json(reports / "b04_r6_second_shadow_screen_result_receipt.json", result_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="requires second shadow invalidation"):
        tranche.run(reports_root=reports)


def test_forensic_routes_contract_defect_when_disqualifier_id_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    contract = _load(reports / "b04_r6_second_shadow_screen_disqualifier_contract.json")
    contract["hard_disqualifiers"] = [
        row for row in contract["hard_disqualifiers"] if row["id"] != "OVERRouting_COLLAPSE"
    ]
    _write_json(reports / "b04_r6_second_shadow_screen_disqualifier_contract.json", contract)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    assert result["verdict"] == tranche.VERDICT_CONTRACT_DEFECT
    assert result["cause_class"] == "METRIC_OR_DISQUALIFIER_CONTRACT_DEFECT"
