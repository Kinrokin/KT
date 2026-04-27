from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_admissible_learned_router_candidate_source as tranche


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _pass(schema_id: str) -> dict:
    return {"schema_id": schema_id, "status": "PASS"}


def _base_boundaries() -> dict:
    return {
        "learned_router_cutover_authorized": False,
        "learned_router_superiority_earned": False,
        "r6_authorized": False,
    }


def _write_inputs(root: Path) -> tuple[Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    _write_json(
        reports / "b04_r6_shadow_router_candidate_input_manifest_receipt.json",
        {
            **_pass("candidate_input_receipt"),
            **_base_boundaries(),
            "candidate_admissible": False,
            "input_manifest_ready": True,
            "next_lawful_move": tranche.REQUIRED_PREVIOUS_MOVE,
            "screen_execution_authorized": False,
        },
    )
    _write_json(
        reports / "b04_r6_learned_router_candidate_manifest.json",
        {
            **_pass("candidate_manifest"),
            **_base_boundaries(),
            "candidate": {
                "admissibility_reason": "No candidate exists in fixture.",
                "admissible_for_shadow_screen": False,
                "candidate_id": "",
                "candidate_source_ref": None,
                "candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
                "promotion_allowed": False,
                "zone": "INTENDED_NOT_PROMOTED",
            },
        },
    )
    _write_json(
        reports / "b04_r6_shadow_router_input_manifest_bound.json",
        {
            **_pass("input_manifest"),
            **_base_boundaries(),
            "input_cases": [{"case_id": "R01"}, {"case_id": "R02"}],
            "input_manifest_ready": True,
        },
    )
    _write_json(
        reports / "b04_r6_shadow_router_execution_mode_contract.json",
        {
            **_pass("execution_mode"),
            **_base_boundaries(),
            "activation_allowed": False,
            "lobe_promotion_allowed": False,
            "package_promotion_allowed": False,
            "product_or_commercial_claim_allowed": False,
        },
    )
    _write_json(
        reports / "router_superiority_scorecard.json",
        {
            **_pass("scorecard"),
            "learned_router_candidate": {
                "candidate_id": "",
                "candidate_status": "NO_ELIGIBLE_LEARNED_ROUTER_CANDIDATE_PRESENT",
                "eligibility_reason": "No candidate exists in fixture.",
                "promotion_allowed": False,
            },
            "superiority_earned": False,
        },
    )
    _write_json(
        governance / "router_policy_registry.json",
        {
            "schema_id": "router_policy",
            "status": "ACTIVE",
            "learned_router_candidate_policy": {
                "current_status": "BLOCKED_PENDING_ELIGIBLE_CANDIDATE_AND_CLEAN_WIN",
                "eligibility_rule": "fixture rule",
            },
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


def test_candidate_source_packet_blocks_without_admissible_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance)

    receipt = _load(reports / tranche.OUTPUTS["receipt"])
    source_packet = _load(reports / tranche.OUTPUTS["source_packet"])
    inventory = _load(reports / tranche.OUTPUTS["inventory"])
    blocker_ledger = _load(reports / tranche.OUTPUTS["blocker_ledger"])
    fresh_generation = _load(reports / tranche.OUTPUTS["fresh_generation_contract"])

    assert result["verdict"] == tranche.NO_CANDIDATE_OUTCOME
    assert receipt["candidate_source_authorized"] is False
    assert receipt["screen_execution_authorized"] is False
    assert receipt["next_lawful_move"] == tranche.NEXT_MOVE_IF_BLOCKED
    assert source_packet["allowed_outcomes"] == [
        tranche.AUTHORIZED_OUTCOME,
        tranche.MISSING_PROVENANCE_OUTCOME,
        tranche.NO_CANDIDATE_OUTCOME,
    ]
    assert inventory["admissible_candidate_count"] == 0
    assert blocker_ledger["entries"][0]["blocker_id"] == "B04_R6_NO_ADMISSIBLE_LEARNED_ROUTER_CANDIDATE_SOURCE"
    assert fresh_generation["fresh_generation_lane_needed"] is True


def test_candidate_source_packet_fails_if_previous_receipt_authorizes_screen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_shadow_router_candidate_input_manifest_receipt.json")
    receipt["screen_execution_authorized"] = True
    _write_json(reports / "b04_r6_shadow_router_candidate_input_manifest_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must not authorize screen execution"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_source_packet_fails_if_existing_candidate_already_admissible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    candidate_manifest = _load(reports / "b04_r6_learned_router_candidate_manifest.json")
    candidate_manifest["candidate"]["admissible_for_shadow_screen"] = True
    _write_json(reports / "b04_r6_learned_router_candidate_manifest.json", candidate_manifest)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must not already be admissible"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_source_packet_fails_if_scorecard_claims_superiority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    scorecard = _load(reports / "router_superiority_scorecard.json")
    scorecard["superiority_earned"] = True
    _write_json(reports / "router_superiority_scorecard.json", scorecard)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="scorecard must not claim superiority"):
        tranche.run(reports_root=reports, governance_root=governance)


def test_candidate_source_packet_fails_if_policy_unblocks_candidate_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance = _write_inputs(tmp_path)
    policy = _load(governance / "router_policy_registry.json")
    policy["learned_router_candidate_policy"]["current_status"] = "UNBLOCKED"
    _write_json(governance / "router_policy_registry.json", policy)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="router policy must keep learned-router candidate blocked"):
        tranche.run(reports_root=reports, governance_root=governance)
