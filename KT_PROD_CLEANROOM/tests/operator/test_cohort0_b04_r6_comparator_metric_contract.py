from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_comparator_metric_contract as tranche


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
        reports / "b04_r6_next_court_receipt.json",
        {
            **_pass("r6_next_court"),
            "learned_router_superiority_earned": False,
            "next_lawful_move": tranche.R6_BLOCKER_MOVE,
            "r6_authorized": False,
        },
    )
    _write_json(
        reports / "b04_r6_blocker_ledger.json",
        {
            **_pass("r6_blocker_ledger"),
            "entries": [{"blocker_id": "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"}],
            "live_blocker_count": 1,
            "r6_blocker_count": 1,
        },
    )
    _write_json(
        reports / "b04_r6_comparator_requirements_packet.json",
        {
            **_pass("r6_comparator_requirements"),
            "best_static_baseline": {"adapter_id": "static.best.v1"},
            "disqualifiers": ["CONTROL_DEGRADATION", "ABSTENTION_COLLAPSE"],
            "minimum_comparator_set": [
                {"row_id": "current_canonical_static_router"},
                {"row_id": "best_static_adapter_control"},
                {"row_id": "shadow_learned_router_candidate"},
            ],
            "r6_authorized": False,
            "required_thresholds": {"control_preservation": "PASS", "route_quality_delta": ">0"},
        },
    )
    _write_json(
        reports / "b04_r1_r5_active_revalidation_replay_receipt.json",
        {
            **_pass("active_replay"),
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
        governance / "b04_r5_router_vs_best_adapter_terminal_state.json",
        {
            "schema_id": "r5_terminal",
            "learned_router_authorized": False,
            "next_lawful_move": tranche.R6_HOLD_MOVE,
            "router_superiority_earned": False,
        },
    )
    _write_json(
        reports / "router_superiority_scorecard.json",
        {
            **_pass("scorecard"),
            "best_static_baseline": {"adapter_id": "static.best.v1"},
            "learned_router_candidate": {
                "candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
                "promotion_allowed": False,
            },
            "superiority_earned": False,
        },
    )
    _write_json(reports / "b04_r1_r5_replay_reproducibility_receipt.json", _pass("r1_r5_replay_reproducibility"))
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


def test_comparator_metric_contract_binds_screen_contract_without_opening_r6(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    contract = _load(reports / tranche.OUTPUTS["contract_packet"])
    receipt = _load(reports / tranche.OUTPUTS["receipt"])
    blocker_ledger = _load(reports / tranche.OUTPUTS["blocker_ledger"])
    shadow_auth = _load(reports / tranche.OUTPUTS["shadow_screen_authorization"])
    metric_thresholds = _load(reports / tranche.OUTPUTS["metric_thresholds"])

    assert result["outcome"] == tranche.OUTCOME
    assert contract["screen_executable_now"] is False
    assert contract["r6_authorized"] is False
    assert "R6_OPEN" in contract["explicitly_not_allowed"]
    assert receipt["screen_contract_authorized"] is True
    assert receipt["screen_executable_now"] is False
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE
    assert blocker_ledger["live_blocker_count"] == 1
    assert blocker_ledger["entries"][1]["blocker_id"] == "B04_R6_SHADOW_CANDIDATE_INPUT_MANIFEST_NOT_BOUND"
    assert shadow_auth["r6_open"] is False
    assert metric_thresholds["aggregation_rule"] == "Candidate superiority requires positive route/outcome movement and zero hard-stop failures."


def test_comparator_metric_contract_fails_if_r6_blocker_count_is_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    blocker_ledger = _load(reports / "b04_r6_blocker_ledger.json")
    blocker_ledger["live_blocker_count"] = 0
    blocker_ledger["r6_blocker_count"] = 0
    _write_json(reports / "b04_r6_blocker_ledger.json", blocker_ledger)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must honestly count one active R6 blocker"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_comparator_metric_contract_fails_if_r5_hold_is_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    active_replay = _load(reports / "b04_r1_r5_active_revalidation_replay_receipt.json")
    active_replay["r5_next_lawful_move"] = "AUTHORIZE_R6"
    _write_json(reports / "b04_r1_r5_active_revalidation_replay_receipt.json", active_replay)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="active replay must preserve R5 static-hold R6 blocker"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_comparator_metric_contract_fails_if_candidate_is_promotable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["learned_router_candidate"]["promotion_allowed"] = True
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must remain non-promotable before screen"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_comparator_metric_contract_fails_without_disqualifiers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    requirements = _load(reports / "b04_r6_comparator_requirements_packet.json")
    requirements["disqualifiers"] = []
    _write_json(reports / "b04_r6_comparator_requirements_packet.json", requirements)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must bind disqualifiers"):
        tranche.run(reports_root=reports, governance_root=governance)
