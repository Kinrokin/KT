from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_shadow_router_candidate_input_manifest as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _pass(schema_id: str) -> dict:
    return {"schema_id": schema_id, "status": "PASS"}


def _base_boundaries() -> dict:
    return {
        "learned_router_superiority_earned": False,
        "r6_authorized": False,
    }


def _input_rows() -> list[dict]:
    return [
        {
            "baseline_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
            "baseline_domain_tag": "math",
            "best_static_provider_adapter_id": "council.openrouter.live_hashed.v1",
            "case_id": "R01",
            "fallback_engaged": False,
            "no_regression_pass": True,
            "shadow_adapter_ids": ["lobe.censor.v1", "lobe.quant.v1"],
            "shadow_domain_tag": "math",
        },
        {
            "baseline_adapter_ids": ["lobe.muse.v1"],
            "baseline_domain_tag": "poetry",
            "best_static_provider_adapter_id": "council.openrouter.live_hashed.v1",
            "case_id": "R02",
            "fallback_engaged": False,
            "no_regression_pass": True,
            "shadow_adapter_ids": ["lobe.muse.v1"],
            "shadow_domain_tag": "poetry",
        },
    ]


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "b04_r6_comparator_metric_contract_receipt.json",
        {
            **_pass("comparator_receipt"),
            **_base_boundaries(),
            "next_lawful_move": tranche.REQUIRED_PREVIOUS_MOVE,
            "screen_contract_authorized": True,
            "screen_executable_now": False,
        },
    )
    _write_json(
        reports / "b04_r6_shadow_screen_input_manifest_contract.json",
        {
            **_pass("input_contract"),
            **_base_boundaries(),
            "must_be_bound_before_screen": True,
            "required_fields": sorted(tranche.REQUIRED_INPUT_FIELDS),
        },
    )
    _write_json(
        reports / "b04_r6_shadow_superiority_screen_authorization_contract.json",
        {
            **_pass("shadow_auth"),
            **_base_boundaries(),
            "r6_open": False,
            "screen_contract_authorized": True,
            "screen_executable_now": False,
        },
    )
    _write_json(
        reports / "b04_r6_comparator_matrix_contract.json",
        {
            **_pass("comparator_matrix"),
            **_base_boundaries(),
            "rows": [
                {"row_id": "current_canonical_static_router"},
                {"row_id": "best_static_adapter_control"},
                {"row_id": "shadow_learned_router_candidate"},
                {"row_id": "abstention_static_hold_control"},
            ],
        },
    )
    _write_json(
        reports / "b04_r6_metric_thresholds_contract.json",
        {
            **_pass("metrics"),
            **_base_boundaries(),
            "metrics": {metric: {"scoring": "test"} for metric in sorted(tranche.REQUIRED_METRICS)},
        },
    )
    _write_json(
        reports / "b04_r6_hard_disqualifier_contract.json",
        {
            **_pass("hard_disqualifiers"),
            **_base_boundaries(),
            "hard_disqualifiers": [{"id": "CONTROL_DEGRADATION", "effect": "SCREEN_FAIL"}],
        },
    )
    _write_json(
        reports / "b04_r6_evidence_requirements_contract.json",
        {
            **_pass("evidence_requirements"),
            **_base_boundaries(),
            "missing_before_execution": ["candidate/input manifest"],
        },
    )
    _write_json(
        reports / "router_superiority_scorecard.json",
        {
            **_pass("scorecard"),
            "learned_router_candidate": {
                "candidate_id": "",
                "candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
                "eligibility_reason": "No candidate exists in test fixture.",
                "promotion_allowed": False,
            },
            "superiority_earned": False,
        },
    )
    _write_json(
        reports / "router_shadow_eval_matrix.json",
        {
            **_pass("shadow_matrix"),
            "learned_router_candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
            "rows": _input_rows(),
        },
    )
    _write_json(
        reports / "route_distribution_health.json",
        {
            **_pass("route_health"),
            "canonical_static_router_preserved": True,
            "fallback_case_ids": [],
            "route_collapse_detected": False,
            "route_quality_cost_latency_matrix": [
                {"case_id": "R01", "route_quality_score": 100, "route_quality_status": "MATCH_STATIC_BASELINE"},
                {"case_id": "R02", "route_quality_score": 100, "route_quality_status": "MATCH_STATIC_BASELINE"},
            ],
        },
    )
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical_scope"})
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "trust_zone_registry"})
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


def test_candidate_input_manifest_binds_inputs_but_blocks_without_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    receipt = _load(reports / tranche.OUTPUTS["receipt"])
    authority = _load(reports / tranche.OUTPUTS["authority_packet"])
    input_manifest = _load(reports / tranche.OUTPUTS["input_manifest"])
    blocker_ledger = _load(reports / tranche.OUTPUTS["blocker_ledger"])

    assert result["verdict"] == tranche.CANDIDATE_BLOCKED_VERDICT
    assert receipt["candidate_admissible"] is False
    assert receipt["input_manifest_ready"] is True
    assert receipt["screen_execution_authorized"] is False
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_IF_BLOCKED
    assert authority["input_case_count"] == 2
    assert authority["r6_open"] is False
    assert input_manifest["input_cases"][0]["mirror_variant_required"] is True
    assert blocker_ledger["entries"][0]["blocker_id"] == "B04_R6_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_NOT_BOUND"


def test_candidate_input_manifest_fails_if_shadow_auth_opens_r6(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    shadow_auth = _load(reports / "b04_r6_shadow_superiority_screen_authorization_contract.json")
    shadow_auth["r6_open"] = True
    _write_json(reports / "b04_r6_shadow_superiority_screen_authorization_contract.json", shadow_auth)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must not open R6"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_input_manifest_fails_if_comparator_row_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    comparator = _load(reports / "b04_r6_comparator_matrix_contract.json")
    comparator["rows"] = [{"row_id": "current_canonical_static_router"}]
    _write_json(reports / "b04_r6_comparator_matrix_contract.json", comparator)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="comparator matrix missing required R6 rows"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_input_manifest_fails_if_candidate_is_promotable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["learned_router_candidate"]["promotion_allowed"] = True
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must remain non-promotable before shadow screen"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_input_manifest_fails_on_route_collapse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    route_health = _load(reports / "route_distribution_health.json")
    route_health["route_collapse_detected"] = True
    _write_json(reports / "route_distribution_health.json", route_health)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must not detect route collapse"):
        tranche.run(reports_root=reports, governance_root=governance)
