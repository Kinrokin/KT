from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_fresh_learned_router_candidate_generation as tranche


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


def _write_inputs(root: Path) -> tuple[Path, Path, Path]:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    run_root = root / "KT_PROD_CLEANROOM" / "runs" / "b04_r6" / "candidate_generation"
    _write_json(
        reports / "b04_r6_candidate_source_receipt.json",
        {
            **_pass("candidate_source_receipt"),
            **_base_boundaries(),
            "candidate_source_authorized": False,
            "next_lawful_move": "AUTHOR_B04_R6_FRESH_LEARNED_ROUTER_CANDIDATE_GENERATION_PACKET",
            "screen_execution_authorized": False,
        },
    )
    _write_json(
        reports / "b04_r6_fresh_candidate_generation_lane_contract.json",
        {
            "schema_id": "fresh_generation_contract",
            "status": "PREP_ONLY",
            "fresh_generation_lane_needed": True,
        },
    )
    _write_json(
        reports / "b04_r6_shadow_router_input_manifest_bound.json",
        {
            **_pass("input_manifest"),
            "input_cases": [
                {"case_id": "R01", "family": "math"},
                {"case_id": "R02", "family": "poetry"},
                {"case_id": "R03", "family": "governance"},
                {"case_id": "R04", "family": "default"},
            ],
            "input_manifest_ready": True,
        },
    )
    _write_json(
        reports / "b04_r6_comparator_matrix_contract.json",
        {
            **_pass("comparator"),
            "rows": [{"row_id": "current_canonical_static_router"}, {"row_id": "best_static_adapter_control"}],
        },
    )
    _write_json(reports / "b04_r6_metric_thresholds_contract.json", _pass("metrics"))
    _write_json(reports / "b04_r6_hard_disqualifier_contract.json", _pass("hard_disqualifiers"))
    _write_json(
        reports / "b04_r6_shadow_router_execution_mode_contract.json",
        {
            **_pass("execution_mode"),
            "activation_allowed": False,
            "lobe_promotion_allowed": False,
            "package_promotion_allowed": False,
        },
    )
    _write_json(
        governance / "router_policy_registry.json",
        {
            "schema_id": "router_policy",
            "status": "ACTIVE",
            "default_adapter_ids": ["lobe.strategist.v1"],
            "learned_router_candidate_policy": {"current_status": "BLOCKED_PENDING_ELIGIBLE_CANDIDATE_AND_CLEAN_WIN"},
            "routes": [
                {
                    "adapter_ids": ["lobe.auditor.v1"],
                    "domain_tag": "governance",
                    "required_adapter_ids": ["lobe.censor.v1"],
                },
                {
                    "adapter_ids": ["lobe.quant.v1"],
                    "domain_tag": "math",
                    "required_adapter_ids": ["lobe.censor.v1"],
                },
                {"adapter_ids": ["lobe.muse.v1"], "domain_tag": "poetry", "required_adapter_ids": []},
            ],
        },
    )
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "canonical_scope"})
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "trust_zone_registry"})
    return reports, governance, run_root


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


def test_fresh_candidate_generation_admits_shadow_only_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance, run_root = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = tranche.run(reports_root=reports, governance_root=governance, run_root=run_root)

    receipt = _load(reports / tranche.REPORT_OUTPUTS["admissible_source_receipt"])
    candidate_manifest = _load(reports / tranche.REPORT_OUTPUTS["candidate_manifest"])
    readiness = _load(reports / tranche.REPORT_OUTPUTS["shadow_readiness_receipt"])
    blocker_ledger = _load(reports / tranche.REPORT_OUTPUTS["blocker_ledger"])
    generated_manifest = _load(run_root / tranche.RUN_OUTPUTS["candidate_manifest"])

    assert result["verdict"] == tranche.FINAL_VERDICT
    assert receipt["candidate_source_authorized"] is True
    assert receipt["screen_execution_authorized"] is True
    assert receipt["r6_authorized"] is False
    assert candidate_manifest["candidate"]["candidate_id"] == tranche.CANDIDATE_ID
    assert candidate_manifest["candidate"]["admissible_for_shadow_screen"] is True
    assert readiness["outcome"] == "R6_SHADOW_SCREEN_EXECUTION_AUTHORIZED"
    assert blocker_ledger["live_blocker_count"] == 0
    assert generated_manifest["candidate"]["promotion_allowed"] is False
    assert (run_root / tranche.RUN_OUTPUTS["candidate_source"]).is_file()


def test_fresh_candidate_generation_fails_if_not_authorized_by_previous_court(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance, run_root = _write_inputs(tmp_path)
    receipt = _load(reports / "b04_r6_candidate_source_receipt.json")
    receipt["next_lawful_move"] = "SOMETHING_ELSE"
    _write_json(reports / "b04_r6_candidate_source_receipt.json", receipt)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="does not authorize fresh generation"):
        tranche.run(reports_root=reports, governance_root=governance, run_root=run_root)


def test_fresh_candidate_generation_fails_if_activation_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance, run_root = _write_inputs(tmp_path)
    execution_mode = _load(reports / "b04_r6_shadow_router_execution_mode_contract.json")
    execution_mode["activation_allowed"] = True
    _write_json(reports / "b04_r6_shadow_router_execution_mode_contract.json", execution_mode)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="activation forbidden"):
        tranche.run(reports_root=reports, governance_root=governance, run_root=run_root)


def test_fresh_candidate_generation_fails_if_policy_unblocks_too_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports, governance, run_root = _write_inputs(tmp_path)
    policy = _load(governance / "router_policy_registry.json")
    policy["learned_router_candidate_policy"]["current_status"] = "UNBLOCKED"
    _write_json(governance / "router_policy_registry.json", policy)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="router policy must remain blocked"):
        tranche.run(reports_root=reports, governance_root=governance, run_root=run_root)
