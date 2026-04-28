from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_new_blind_input_universe_contract as bound
from tools.operator import cohort0_b04_r6_new_blind_input_universe_validation as validation


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _base(status: str = "PASS") -> dict:
    return {
        "status": status,
        "current_git_head": "bound-head",
        "current_main_head": "bound-head",
        "subject_main_head": "bound-head",
        "architecture_binding_head": "architecture-head",
        "selected_architecture_id": validation.SELECTED_ARCHITECTURE_ID,
        "selected_architecture_name": validation.SELECTED_ARCHITECTURE_NAME,
        "selected_outcome": validation.EXPECTED_PREVIOUS_OUTCOME,
        "authoritative_lane": validation.PREVIOUS_LANE,
        "blind_universe_contract_bound": True,
        "blind_universe_id": validation.UNIVERSE_ID,
        "candidate_generation_authorized": False,
        "router_generation_authorized": False,
        "shadow_screen_authorized": False,
        "new_shadow_screen_authorized": False,
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
        "old_blind_universes_diagnostic_only": True,
        "r01_r04_reuse_as_counted_proof_allowed": False,
        "six_row_v2_reuse_as_counted_proof_allowed": False,
        "case_count": validation.EXPECTED_CASE_COUNT,
        "next_lawful_move": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
    }


def _contract_payload(cases: list[dict]) -> dict:
    return {
        **_base(),
        "schema_id": "kt.operator.b04_r6_new_blind_input_universe_contract.v2",
        "branch_law": "bound universe only; R6 remains closed",
        "blind_universe_identity": {
            "universe_id": validation.UNIVERSE_ID,
            "case_count": validation.EXPECTED_CASE_COUNT,
            "case_id_prefix": validation.CASE_PREFIX.rstrip("-"),
            "selected_architecture_id": validation.SELECTED_ARCHITECTURE_ID,
        },
        "input_source_rules": {"untracked_sources_allowed": False},
        "input_provenance_rules": {"source_sha256_required": True},
        "blindness_rules": {
            "candidate_generation_can_see_outcomes": False,
            "candidate_generation_can_see_route_labels": False,
            "candidate_generation_can_see_static_labels": False,
        },
        "label_access_rules": {"route_labels_hidden_until_counted_screen": True},
        "outcome_access_rules": {"blind_screen_outcomes_hidden_before_screen": True},
        "no_tuning_rules": {"no_candidate_tuning_on_blind_outcomes": True},
        "prior_screen_contamination_rules": {
            "r01_r04_diagnostic_only": True,
            "six_row_v2_universe_diagnostic_only": True,
            "old_candidate_outputs_as_labels_forbidden": True,
            "old_disqualification_as_route_label_forbidden": True,
        },
        "stratification_axes": ["family_id", "variant_type", "balance_bucket", "trust_zone", "proof_burden", "route_value"],
        "family_balance_rules": {"static_hold_should_win_percent": "20-30"},
        "admissibility_rules": {"source_hash_required": True},
        "exclusion_rules": {"old_case_ids_excluded": list(validation.OLD_CASE_PREFIXES)},
        "holdout_lock": {
            "locked": True,
            "candidate_generation_may_not_use_blind_outcomes": True,
            "candidate_generation_may_not_use_blind_route_labels": True,
        },
        "case_manifest_binding": "b04_r6_blind_universe_case_manifest.json",
        "mirror_masked_sibling_map": "b04_r6_blind_universe_mirror_masked_map.json",
        "null_route_controls": ["B04R6-AFSH-BU1-0015", "B04R6-AFSH-BU1-0018"],
        "static_hold_controls": ["B04R6-AFSH-BU1-0001", "B04R6-AFSH-BU1-0002"],
        "boundary_abstention_controls": ["B04R6-AFSH-BU1-0008", "B04R6-AFSH-BU1-0009", "B04R6-AFSH-BU1-0010"],
        "static_comparator_binding": {"preserve_existing_contract": True, "static_baseline_weakening_allowed": False},
        "route_economics_basis": {"routing_allowed_only_above_threshold": True},
        "proof_burden_basis": {"route_must_reduce_or_justify_proof_burden": True},
        "wrong_route_cost_basis": {"wrong_route_must_be_expensive": True},
        "wrong_static_hold_cost_basis": {"static_hold_false_negative_tracked_but_not_disqualifying_by_default": True},
        "calibration_basis": {"confidence_to_error_monotonicity_required": True},
        "monotonicity_basis": {"confidence_increase_must_not_hide_error_risk": True},
        "trust_zone_bindings": {"logical_zone": "CANONICAL_EVAL_HOLDOUT", "registry_compatible_zone": "CANONICAL"},
        "no_runtime_import_guards": {"runtime_import_from_blind_outcomes_forbidden": True},
        "no_generation_surface_guards": {"candidate_generation_authorized": False, "router_generation_authorized": False},
        "no_screen_execution_guards": {"shadow_screen_authorized": False},
        "no_package_promotion_guards": {"package_promotion_remains_deferred": True},
        "required_receipts": [],
        "validation_commands": [],
        "pass_conditions": [],
        "fail_closed_conditions": validation.REASON_CODES,
        "allowed_outcomes": [
            validation.EXPECTED_PREVIOUS_OUTCOME,
            "R6_DEFERRED__BLIND_UNIVERSE_CONTRACT_DEFECT_REMAINS",
            "R6_CLOSEOUT__NO_LAWFUL_BLIND_UNIVERSE_AVAILABLE",
        ],
        "next_lawful_moves": [validation.EXPECTED_PREVIOUS_NEXT_MOVE],
    }


def _write_inputs(root: Path) -> Path:
    reports = root / "KT_PROD_CLEANROOM" / "reports"
    governance = root / "KT_PROD_CLEANROOM" / "governance"
    cases = bound._blind_cases()
    mirror_map = bound._mirror_masked_map(cases)
    trust_validation = {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]}

    payloads = {
        "bound_contract": _contract_payload(cases),
        "bound_contract_receipt": {
            **_base(),
            "schema_id": "contract_receipt",
            "blind_universe_contract_bound": True,
            "verdict": validation.EXPECTED_PREVIOUS_OUTCOME,
        },
        "case_manifest": {
            **_base(),
            "schema_id": "case_manifest",
            "cases": cases,
            "case_manifest_sha256": validation._stable_hash(cases),
        },
        "mirror_masked_map": {
            **_base(),
            "schema_id": "mirror_map",
            **mirror_map,
            "mirror_masked_map_sha256": validation._stable_hash(mirror_map),
            "status": "PASS",
        },
        "holdout_separation": {
            **_base(),
            "schema_id": "holdout",
            "holdout_status": "LOCKED",
            "case_ids_fresh": True,
            "old_r01_r04_cases_diagnostic_only": True,
            "old_six_row_v2_universe_diagnostic_only": True,
            "old_case_id_reuse_detected": False,
            "blind_outcomes_hidden_from_candidate_generation": True,
            "blind_route_labels_hidden_from_candidate_generation": True,
        },
        "leakage_guard": {
            **_base(),
            "schema_id": "leakage",
            "leakage_guard_status": "PASS",
            "old_r01_r04_cases_are_diagnostic_only": True,
            "old_six_row_v2_universe_is_diagnostic_only": True,
            "old_candidate_outputs_as_labels_forbidden": True,
            "old_disqualification_as_route_label_forbidden": True,
            "new_case_ids_are_fresh": True,
            "new_outcome_labels_inaccessible_before_screen": True,
            "new_route_value_labels_inaccessible_before_screen": True,
            "calibration_from_blind_screen_outcomes_forbidden": True,
        },
        "trust_zone_report": {
            **_base(),
            "schema_id": "trust_zone_report",
            "logical_case_zone": "CANONICAL_EVAL_HOLDOUT",
            "registry_compatible_zone": "CANONICAL",
            "case_zone_mismatches": [],
            "trust_zone_validation": trust_validation,
        },
        "parse_sweep": {**_base(), "schema_id": "parse", "artifact_count": 22},
        "family_balance": {**_base(), "schema_id": "balance", **bound._balance_report(cases)},
        "control_sibling_map": {**_base(), "schema_id": "control_map", **mirror_map, "status": "PASS"},
        "static_hold_draft": {**_base("PREP_ONLY"), "schema_id": "static_draft"},
        "abstention_registry_draft": {**_base("PREP_ONLY"), "schema_id": "abstention_draft"},
        "route_economics_draft": {**_base("PREP_ONLY"), "schema_id": "route_draft", "metric_widening_allowed": False},
        "afsh_interface_draft": {**_base("PREP_ONLY"), "schema_id": "interface_draft"},
        "afsh_trace_schema_draft": {
            **_base("PREP_ONLY"),
            "schema_id": "trace_draft",
            "required_trace_groups": sorted(validation.REQUIRED_TRACE_GROUPS),
        },
        "external_research_receipt": {
            **_base("PREP_ONLY"),
            "schema_id": "research",
            "external_research_as_authority_allowed": False,
        },
        "forbidden_claims_receipt": {**_base(), "schema_id": "forbidden"},
        "clean_state": {
            **_base(),
            "schema_id": "clean",
            "candidate_generation_detected": False,
            "shadow_screen_execution_detected": False,
            "old_blind_universe_reuse_detected": False,
            "metric_widening_detected": False,
            "comparator_weakening_detected": False,
            "package_promotion_drift": False,
            "truth_engine_mutation_detected": False,
            "trust_zone_mutation_detected": False,
        },
        "previous_next_lawful_move": {
            **_base(),
            "schema_id": "next",
            "authoritative_lane": validation.PREVIOUS_LANE,
            "next_lawful_move": validation.EXPECTED_PREVIOUS_NEXT_MOVE,
        },
    }
    for role, payload in payloads.items():
        _write_json(root / validation.INPUTS[role], payload)
    _write_json(governance / "trust_zone_registry.json", {"schema_id": "registry", "status": "PASS"})
    _write_json(governance / "canonical_scope_manifest.json", {"schema_id": "scope", "status": "PASS"})
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = "branch-head",
    origin_main: str = "main-head",
) -> None:
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        validation,
        "_git_blob_sha256",
        lambda root, commit, raw: validation.file_sha256(root / raw),
    )
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "PASS", "checks": [{}], "failures": []},
    )


def test_validates_bound_blind_universe_without_authorizing_downstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    result = validation.run(reports_root=reports)

    receipt = _load(reports / validation.OUTPUTS["validation_receipt"])
    next_receipt = _load(reports / validation.OUTPUTS["next_lawful_move"])

    assert result["verdict"] == validation.OUTCOME_VALIDATED
    assert receipt["bound_universe_validated"] is True
    assert receipt["candidate_generation_authorized"] is False
    assert receipt["shadow_screen_authorized"] is False
    assert receipt["failure_count"] == 0
    assert receipt["subject_main_head"] == receipt["bound_contract_subject_main_head"]
    assert next_receipt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_emits_subject_main_head_from_bound_contract_not_branch_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, head="different-branch-head", origin_main="different-main-head")

    result = validation.run(reports_root=reports)

    receipt = _load(reports / validation.OUTPUTS["validation_receipt"])

    assert result["verdict"] == validation.OUTCOME_VALIDATED
    assert receipt["subject_main_head"] == receipt["bound_contract_subject_main_head"]
    assert receipt["subject_main_head"] == "bound-head"
    assert receipt["subject_main_head"] != "different-branch-head"
    assert receipt["subject_main_head"] != "different-main-head"


def test_fails_closed_on_case_count_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    manifest = _load(reports / "b04_r6_blind_universe_case_manifest.json")
    manifest["cases"] = manifest["cases"][:-1]
    manifest["case_manifest_sha256"] = validation._stable_hash(manifest["cases"])
    _write_json(reports / "b04_r6_blind_universe_case_manifest.json", manifest)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_CASE_COUNT_MISMATCH"):
        validation.run(reports_root=reports)


def test_fails_closed_on_label_leakage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    manifest = _load(reports / "b04_r6_blind_universe_case_manifest.json")
    manifest["cases"][0]["blindness"]["labels_hidden_from_candidate_generation"] = False
    manifest["case_manifest_sha256"] = validation._stable_hash(manifest["cases"])
    _write_json(reports / "b04_r6_blind_universe_case_manifest.json", manifest)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_LABEL_LEAKAGE"):
        validation.run(reports_root=reports)


def test_fails_closed_on_old_case_namespace_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    manifest = _load(reports / "b04_r6_blind_universe_case_manifest.json")
    manifest["cases"][0]["case_id"] = "R01-REUSED"
    manifest["case_manifest_sha256"] = validation._stable_hash(manifest["cases"])
    _write_json(reports / "b04_r6_blind_universe_case_manifest.json", manifest)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_CASE_ID_NAMESPACE_DRIFT"):
        validation.run(reports_root=reports)


def test_fails_closed_on_manifest_hash_instability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    manifest = _load(reports / "b04_r6_blind_universe_case_manifest.json")
    manifest["case_manifest_sha256"] = "0" * 64
    _write_json(reports / "b04_r6_blind_universe_case_manifest.json", manifest)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_MANIFEST_HASH_UNSTABLE"):
        validation.run(reports_root=reports)


def test_fails_closed_on_family_balance_report_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    balance = _load(reports / "b04_r6_new_blind_universe_case_family_balance_report.json")
    balance["bucket_counts"]["STATIC_HOLD"] = 99
    _write_json(reports / "b04_r6_new_blind_universe_case_family_balance_report.json", balance)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_FAMILY_BALANCE_DEFECT"):
        validation.run(reports_root=reports)


def test_fails_closed_on_control_sibling_map_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    mirror_map = _load(reports / "b04_r6_blind_universe_mirror_masked_map.json")
    mirror_map["entries"][0]["masked_case_id"] = "B04R6-AFSH-BU1-0017"
    core = {
        "map_status": mirror_map["map_status"],
        "required": mirror_map["required"],
        "entries": mirror_map["entries"],
        "all_case_ids": mirror_map["all_case_ids"],
    }
    mirror_map["mirror_masked_map_sha256"] = validation._stable_hash(core)
    _write_json(reports / "b04_r6_blind_universe_mirror_masked_map.json", mirror_map)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_MASKED_SIBLING_MISSING"):
        validation.run(reports_root=reports)


def test_fails_closed_on_bound_input_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    contract = _load(reports / "b04_r6_new_blind_input_universe_contract.json")
    contract["input_bindings"] = [
        {
            "role": "canonical_scope_manifest",
            "path": "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "sha256": "0" * 64,
        }
    ]
    _write_json(reports / "b04_r6_new_blind_input_universe_contract.json", contract)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="bound input hash drift"):
        validation.run(reports_root=reports)


def test_fails_closed_on_replay_artifact_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)

    def _drift(root: Path, commit: str, raw: str) -> str:
        if raw.endswith("b04_r6_blind_universe_case_manifest.json"):
            return "0" * 64
        return validation.file_sha256(root / raw)

    monkeypatch.setattr(validation, "_git_blob_sha256", _drift)

    with pytest.raises(RuntimeError, match="bound replay artifact drift"):
        validation.run(reports_root=reports)


def test_fails_closed_on_prep_artifact_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    route = _load(reports / "b04_r6_route_economics_matrix_draft.json")
    route["status"] = "PASS"
    _write_json(reports / "b04_r6_route_economics_matrix_draft.json", route)
    _patch_env(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_PREP_ONLY_ARTIFACT_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_main_replay_accepts_same_lane_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    next_receipt = _load(reports / "b04_r6_next_lawful_move_receipt.json")
    next_receipt["authoritative_lane"] = validation.AUTHORITATIVE_LANE
    next_receipt["next_lawful_move"] = validation.NEXT_LAWFUL_MOVE
    _write_json(reports / "b04_r6_next_lawful_move_receipt.json", next_receipt)
    _patch_env(monkeypatch, tmp_path, branch="main", head="main-head", origin_main="main-head")

    result = validation.run(reports_root=reports)

    assert result["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_fails_closed_if_trust_zone_validation_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _write_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "validation", "status": "FAIL", "checks": [], "failures": ["boom"]},
    )

    with pytest.raises(RuntimeError, match="RC_B04R6_BUV_TRUST_ZONE_BINDING_MISSING"):
        validation.run(reports_root=reports)
