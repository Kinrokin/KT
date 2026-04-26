from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_upper_stack_ratification_readiness_authority_packet_tranche as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base_pass(schema_id: str) -> dict:
    return {"schema_id": schema_id, "status": "PASS"}


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    boundary_flags = {"package_promotion_remains_deferred": True, "truth_engine_derivation_law_unchanged": True}

    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical", "status": "ACTIVE"})
    _write_json(
        governance / "readiness_scope_manifest.json",
        {"schema_id": "readiness", "status": "ACTIVE", "current_authority_mode": "SETTLED_AUTHORITATIVE"},
    )
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "ACTIVE"})
    for filename in [
        "crucible_lifecycle_law.json",
        "crucible_registry.json",
        "pressure_response_taxonomy.json",
        "adapter_lifecycle_law.json",
        "adapter_registry.json",
        "tournament_law.json",
        "promotion_engine_law.json",
        "merge_law.json",
        "router_promotion_law.json",
        "lobe_role_registry.json",
        "lobe_promotion_law.json",
    ]:
        _write_json(governance / filename, {"schema_id": filename, "status": "ACTIVE"})
    _write_json(
        governance / "router_policy_registry.json",
        {
            "schema_id": "router_policy",
            "status": "ACTIVE",
            "multi_lobe_orchestration_policy": {"current_status": "BLOCKED_PENDING_LEARNED_ROUTER_WIN"},
        },
    )
    for filename in [
        "b04_r1_crucible_pressure_terminal_state.json",
        "b04_r2_adapter_lifecycle_terminal_state.json",
        "b04_r3_tournament_promotion_merge_terminal_state.json",
        "b04_r4_router_shadow_terminal_state.json",
    ]:
        _write_json(governance / filename, {"schema_id": filename, "status": "ACTIVE"})
    _write_json(
        governance / "b04_r5_router_vs_best_adapter_terminal_state.json",
        {
            "schema_id": "r5_terminal",
            "status": "ACTIVE",
            "router_vs_best_adapter_proof_ratified": True,
            "learned_router_authorized": False,
            "next_lawful_move": "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF",
        },
    )

    _write_json(
        reports / tranche.POST_BOUNDARY_REGRADE,
        {
            **_base_pass("post_boundary"),
            **boundary_flags,
            "next_lawful_move": "AUTHOR_UPPER_STACK_RATIFICATION_READINESS_AUTHORITY_PACKET",
            "truth_engine_blocking_contradictions": 0,
            "truth_engine_advisory_contradictions": 0,
            "unknown_zone_queue_count": 0,
            "live_blocker_count": 0,
        },
    )
    _write_json(
        reports / tranche.NEXT_LANE_RECOMMENDATION,
        {
            **_base_pass("recommendation"),
            **boundary_flags,
            "recommended_next_authoritative_lane": "upper_stack_ratification_readiness",
        },
    )
    _write_json(
        reports / tranche.UPPER_STACK_PREP_INVENTORY,
        {
            **_base_pass("prep_inventory"),
            "classes": {
                "crucibles_policy_c": {"tracked_path_count": 109},
                "adapters": {"tracked_path_count": 42},
                "forge_training": {"tracked_path_count": 86},
                "router_lobes": {"tracked_path_count": 121},
                "tournaments_promotion_merge": {"tracked_path_count": 132},
            },
        },
    )
    _write_json(reports / tranche.REMAINING_A_PLUS_GAPS, {**_base_pass("gaps"), "open_gap_count": 5})
    for filename, next_move in [
        (tranche.R1_RECEIPT, "B04_R2_ADAPTER_LIFECYCLE_LAW_RATIFICATION"),
        (tranche.R2_RECEIPT, "B04_R3_TOURNAMENT_PROMOTION_MERGE_LAW_RATIFICATION"),
        (tranche.R3_RECEIPT, "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"),
        (tranche.R4_RECEIPT, "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF"),
        (tranche.R5_RECEIPT, "HOLD_B04_R6_BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"),
    ]:
        _write_json(reports / filename, {**_base_pass(filename), "next_lawful_move": next_move})
    _write_json(
        reports / tranche.ROUTER_SUPERIORITY_SCORECARD,
        {
            **_base_pass("router_scorecard"),
            "superiority_earned": False,
            "multi_lobe_promotion_status": "BLOCKED_PENDING_LEARNED_ROUTER_WIN",
        },
    )
    for filename in [
        tranche.ROUTER_ORDERED_PROOF,
        tranche.UNIVERSAL_ADAPTER_RECEIPT,
        tranche.ROUTER_LOBE_GAP_MATRIX,
        tranche.ADAPTER_CIVILIZATION_GAP_MATRIX,
    ]:
        _write_json(reports / filename, {**_base_pass(filename), **boundary_flags})
    return reports, governance


def _patch_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tranche, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(tranche.common, "git_current_branch_name", lambda root: tranche.REQUIRED_BRANCH)
    monkeypatch.setattr(tranche.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(tranche.common, "git_rev_parse", lambda root, ref: "abc123")
    monkeypatch.setattr(tranche, "validate_trust_zones", lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{} for _ in range(24)], "failures": []})


def test_upper_stack_readiness_emits_authority_surfaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    receipt = _load(reports / tranche.OUTPUT_RECEIPT)
    inventory = _load(reports / tranche.OUTPUT_DOMAIN_INVENTORY)
    matrix = _load(reports / tranche.OUTPUT_STATUS_MATRIX)
    blockers = _load(reports / tranche.OUTPUT_BLOCKER_LEDGER)
    recommendation = _load(reports / tranche.OUTPUT_NEXT_RECOMMENDATION)
    packet = _load(reports / tranche.OUTPUT_PACKET)

    assert result["outcome"] == tranche.OUTCOME
    assert receipt["r6_authorization_status"] == "BLOCKED_PENDING_EARNED_ROUTER_SUPERIORITY_PROOF"
    assert receipt["ratification_blocker_count"] == 3
    assert inventory["domain_count"] >= 12
    assert "INTENDED_NOT_PROMOTED" in matrix["status_classes"]
    assert blockers["live_blocker_count"] == 0
    assert blockers["entries"][0]["blocker_id"] == "B04_R6_LEARNED_ROUTER_SUPERIORITY_NOT_EARNED"
    assert recommendation["recommended_next_move"] == tranche.NEXT_MOVE
    assert packet["non_claim_boundaries"]


def test_upper_stack_readiness_fails_without_post_boundary_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    payload = _load(reports / tranche.POST_BOUNDARY_REGRADE)
    payload["next_lawful_move"] = "SOMETHING_ELSE"
    _write_json(reports / tranche.POST_BOUNDARY_REGRADE, payload)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="authorize upper-stack readiness"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_upper_stack_readiness_fails_if_r5_no_longer_holds_r6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    payload = _load(reports / tranche.R5_RECEIPT)
    payload["next_lawful_move"] = "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
    _write_json(reports / tranche.R5_RECEIPT, payload)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="HOLD_B04_R6"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_upper_stack_readiness_fails_if_router_superiority_unexpectedly_earned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports, governance = _write_inputs(tmp_path)
    payload = _load(reports / tranche.ROUTER_SUPERIORITY_SCORECARD)
    payload["superiority_earned"] = True
    _write_json(reports / tranche.ROUTER_SUPERIORITY_SCORECARD, payload)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="superiority not yet earned"):
        tranche.run(reports_root=reports, governance_root=governance)
