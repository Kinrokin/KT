from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_new_blind_input_universe_contract as tranche


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
        "router_generation_authorized": False,
        "candidate_generation_authorized": False,
        "shadow_screen_authorized": False,
        "new_shadow_screen_authorized": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "learned_router_activated": False,
        "learned_router_cutover_authorized": False,
        "multi_lobe_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    common = {**_base(), "next_lawful_move": tranche.EXPECTED_PREVIOUS_NEXT_MOVE}
    payloads = {
        "architecture_contract": {
            **common,
            "schema_id": "architecture_contract",
            "selected_architecture_contract": {
                "default_outcome": "STATIC_HOLD",
                "route_requires_positive_justification": True,
            },
            "new_blind_universe_requirement": {
                "r01_r04_reuse_as_counted_proof_allowed": False,
                "six_row_second_screen_reuse_as_fresh_counted_proof_allowed": False,
            },
            "comparator_metric_preservation_law": {
                "static_baseline_weakening_allowed": False,
                "metric_widening_allowed": False,
            },
        },
        "architecture_receipt": {
            **common,
            "schema_id": "architecture_receipt",
            "selected_outcome": tranche.EXPECTED_PREVIOUS_OUTCOME,
            "selected_architecture_id": tranche.SELECTED_ARCHITECTURE_ID,
            "selected_architecture_name": tranche.SELECTED_ARCHITECTURE_NAME,
            "architecture_contract_bound": True,
            "new_blind_universe_required": True,
            "old_blind_universes_diagnostic_only": True,
            "subject_main_head": "architecture-head",
        },
        "router_family_retirement": {
            **common,
            "schema_id": "retirement",
            "retired_for_r6": True,
            "quick_candidate_v3_forbidden": True,
            "old_screen_evidence_policy": {
                "r01_r04_diagnostic_only": True,
                "six_row_second_screen_diagnostic_only": True,
                "reuse_as_fresh_counted_proof_allowed": False,
            },
        },
        "architecture_options": {**common, "schema_id": "options", "options": []},
        "architecture_selection_rationale": {**common, "schema_id": "rationale"},
        "architecture_clean_state": {**common, "schema_id": "clean_state"},
        "blind_selection_risk": {
            **common,
            "schema_id": "risk",
            "status": "PREP_ONLY",
            "blind_universe_binding_authorized_by_this_packet": False,
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
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = tranche.AUTHORITY_BRANCH,
    head: str = "branch-head",
    origin_main: str = "main-head",
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


def test_binds_fresh_blind_universe_without_authorizing_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports)

    contract = _load(reports / tranche.OUTPUTS["contract"])
    manifest = _load(reports / tranche.OUTPUTS["case_manifest"])
    receipt = _load(reports / tranche.OUTPUTS["contract_receipt"])
    next_receipt = _load(reports / tranche.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == tranche.OUTCOME_BOUND
    assert receipt["blind_universe_contract_bound"] is True
    assert receipt["router_generation_authorized"] is False
    assert receipt["candidate_generation_authorized"] is False
    assert receipt["shadow_screen_authorized"] is False
    assert contract["current_main_head"] == "main-head"
    assert contract["architecture_binding_head"] == "architecture-head"
    assert contract["blind_universe_identity"]["case_count"] == 18
    assert manifest["case_manifest_sha256"]
    assert {row["family_id"] for row in manifest["cases"]}.issuperset(tranche.REQUIRED_FAMILIES)
    assert not any(row["case_id"].startswith(tranche.OLD_CASE_PREFIXES) for row in manifest["cases"])
    assert next_receipt["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_fails_closed_if_architecture_is_not_afsh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_major_router_architecture_contract_receipt.json")
    receipt["selected_architecture_id"] = "PURE-LEARNED-SELECTOR"
    _write_json(reports / "b04_r6_major_router_architecture_contract_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="selected architecture must be AFSH-2S-GUARD"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_old_universe_reuse_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    contract = _load(reports / "b04_r6_major_router_architecture_contract.json")
    contract["new_blind_universe_requirement"]["six_row_second_screen_reuse_as_fresh_counted_proof_allowed"] = True
    _write_json(reports / "b04_r6_major_router_architecture_contract.json", contract)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="second six-row screen reuse as fresh proof must be forbidden"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_prep_risk_prebinds_universe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    risk = _load(reports / "b04_r6_new_blind_universe_selection_risk_matrix.json")
    risk["blind_universe_binding_authorized_by_this_packet"] = True
    _write_json(reports / "b04_r6_new_blind_universe_selection_risk_matrix.json", risk)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must not pre-bind a blind universe"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_shadow_screen_authorized_too_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_major_router_architecture_contract_receipt.json")
    receipt["shadow_screen_authorized"] = True
    _write_json(reports / "b04_r6_major_router_architecture_contract_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="must keep shadow_screen_authorized=false"):
        tranche.run(reports_root=reports)


def test_authority_branch_rejects_already_validation_next_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = tranche.NEXT_LAWFUL_MOVE
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="previous next-lawful-move receipt mismatch"):
        tranche.run(reports_root=reports)


def test_main_replay_accepts_already_validation_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["next_lawful_move"] = tranche.NEXT_LAWFUL_MOVE
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = tranche.run(reports_root=reports)

    assert result["next_lawful_move"] == tranche.NEXT_LAWFUL_MOVE


def test_fails_closed_on_noncanonical_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="local-main", origin_main="origin-main")

    with pytest.raises(RuntimeError, match="main replay requires local main converged with origin/main"):
        tranche.run(reports_root=reports)


def test_fails_closed_if_trust_zone_validation_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        tranche,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "FAIL", "checks": [], "failures": ["boom"]},
    )

    with pytest.raises(RuntimeError, match="trust-zone validation must have status PASS"):
        tranche.run(reports_root=reports)
