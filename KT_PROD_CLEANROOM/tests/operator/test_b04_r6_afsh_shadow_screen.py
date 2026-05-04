from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_afsh_shadow_screen as screen
from tools.operator import cohort0_b04_r6_afsh_shadow_screen_execution_packet_validation as packet_validation


SCREEN_HEAD = "1111111111111111111111111111111111111111"
SCREEN_MAIN_HEAD = "2222222222222222222222222222222222222222"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_afsh_shadow_screen_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_shadow_packet_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load packet-validation test helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _patch_screen_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = screen.AUTHORITY_BRANCH,
    head: str = SCREEN_HEAD,
    origin_main: str = SCREEN_MAIN_HEAD,
) -> None:
    monkeypatch.setattr(screen, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(screen.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(screen.common, "git_status_porcelain", lambda root: "")
    monkeypatch.setattr(screen.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        screen,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _case(case_id: int, family: str, balance: str, route_value: str, proof_burden: str, variant: str, *, siblings: dict | None = None) -> dict:
    suffix = f"{case_id:04d}"
    return {
        "case_id": f"B04R6-AFSH-BU1-{suffix}",
        "family_id": family,
        "balance_bucket": balance,
        "route_value": route_value,
        "proof_burden": proof_burden,
        "variant_type": variant,
        "trust_zone": "CANONICAL_EVAL_HOLDOUT",
        "registry_compatible_zone": "CANONICAL",
        "control_siblings": siblings or {"mirror_case_id": "", "masked_case_id": "", "null_route_case_id": "", "static_hold_case_id": ""},
        "blindness": {
            "labels_hidden_from_candidate_generation": True,
            "outcomes_hidden_from_candidate_generation": True,
            "route_labels_hidden_before_screen": True,
            "calibration_from_screen_outcomes_forbidden": True,
        },
        "admissibility": {"admitted": True, "exclusion_reason_codes": []},
        "source_ref": {"kind": "case_source", "path": f"hash-only://test/{suffix}", "sha256": f"{case_id:064x}"[-64:]},
    }


def _case_manifest() -> dict:
    cases = [
        _case(1, "STATIC_HOLD_SHOULD_WIN", "STATIC_HOLD", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "NORMAL", "CANONICAL", siblings={"mirror_case_id": "B04R6-AFSH-BU1-0013", "masked_case_id": "B04R6-AFSH-BU1-0014", "null_route_case_id": "B04R6-AFSH-BU1-0015", "static_hold_case_id": ""}),
        _case(2, "COMPARATOR_DOMINANCE_CASE", "STATIC_HOLD", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "NORMAL", "CONTROL", siblings={"mirror_case_id": "", "masked_case_id": "", "null_route_case_id": "", "static_hold_case_id": "B04R6-AFSH-BU1-0001"}),
        _case(3, "ROUTING_PLAUSIBLY_ADDS_VALUE", "ROUTE_VALUE", "POSITIVE_ROUTE_VALUE", "LIGHT", "CANONICAL", siblings={"mirror_case_id": "B04R6-AFSH-BU1-0016", "masked_case_id": "B04R6-AFSH-BU1-0017", "null_route_case_id": "B04R6-AFSH-BU1-0018", "static_hold_case_id": ""}),
        _case(4, "ROUTE_VALUE_CASE", "ROUTE_VALUE", "POSITIVE_ROUTE_VALUE", "LIGHT", "CANONICAL"),
        _case(5, "PROOF_BURDEN_LIGHT", "ROUTE_VALUE", "POSITIVE_ROUTE_VALUE", "LIGHT", "CANONICAL"),
        _case(6, "OVER_ROUTING_TRAP", "OVERROUTING_TRAP", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "NORMAL", "CANONICAL"),
        _case(7, "ADVERSARIAL_SELECTOR_TRAP", "OVERROUTING_TRAP", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "NORMAL", "CONTROL"),
        _case(8, "ABSTENTION_REQUIRED", "ABSTENTION_BOUNDARY", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "HEAVY", "CANONICAL"),
        _case(9, "BOUNDARY_REJECTION", "ABSTENTION_BOUNDARY", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "HEAVY", "CONTROL"),
        _case(10, "TRUST_ZONE_BOUNDARY_CASE", "ABSTENTION_BOUNDARY", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "HEAVY", "CONTROL"),
        _case(11, "PROOF_BURDEN_HEAVY", "ABSTENTION_BOUNDARY", "STATIC_OR_ABSTENTION_VALUE_DOMINANT", "HEAVY", "CANONICAL"),
        _case(12, "CALIBRATION_EDGE_CASE", "CALIBRATION_EDGE", "CALIBRATION_DEPENDENT", "NORMAL", "CANONICAL"),
        _case(13, "MIRROR_SURFACE_VARIANT", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "MIRROR"),
        _case(14, "MASKED_SURFACE_VARIANT", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "MASKED"),
        _case(15, "NULL_ROUTE_CONTROL", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "NULL_ROUTE"),
        _case(16, "MIRROR_SURFACE_VARIANT", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "MIRROR"),
        _case(17, "MASKED_SURFACE_VARIANT", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "MASKED"),
        _case(18, "NULL_ROUTE_CONTROL", "CONTROL_SIBLING", "CONTROL_VALUE", "NORMAL", "NULL_ROUTE"),
    ]
    return {
        "schema_id": "kt.operator.b04_r6_blind_universe_case_manifest.v1",
        "artifact_id": "B04_R6_BLIND_UNIVERSE_CASE_MANIFEST",
        "status": "PASS",
        "case_count": 18,
        "case_manifest_sha256": screen._canonical_hash(cases),
        "cases": cases,
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _control_map() -> dict:
    return {
        "schema_id": "kt.operator.b04_r6_new_blind_universe_control_sibling_candidate_map.v1",
        "artifact_id": "B04_R6_NEW_BLIND_UNIVERSE_CONTROL_SIBLING_CANDIDATE_MAP",
        "status": "PASS",
        "entries": [
            {
                "primary_case_id": "B04R6-AFSH-BU1-0001",
                "mirror_case_id": "B04R6-AFSH-BU1-0013",
                "masked_case_id": "B04R6-AFSH-BU1-0014",
                "null_route_case_id": "B04R6-AFSH-BU1-0015",
            },
            {
                "primary_case_id": "B04R6-AFSH-BU1-0003",
                "mirror_case_id": "B04R6-AFSH-BU1-0016",
                "masked_case_id": "B04R6-AFSH-BU1-0017",
                "null_route_case_id": "B04R6-AFSH-BU1-0018",
            },
        ],
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _reference_payload(artifact_id: str) -> dict:
    return {
        "schema_id": f"test.{artifact_id.lower()}.v1",
        "artifact_id": artifact_id,
        "status": "PASS",
        "r6_open": False,
        "learned_router_superiority_earned": False,
        "activation_review_authorized": False,
        "package_promotion_remains_deferred": True,
        "truth_engine_derivation_law_unchanged": True,
        "trust_zone_law_unchanged": True,
    }


def _write_screen_inputs(reports: Path) -> None:
    root = reports.parents[1]
    _write_json(root / screen.INPUTS["case_manifest"], _case_manifest())
    _write_json(root / screen.INPUTS["control_sibling_map"], _control_map())
    _write_json(root / screen.INPUTS["mirror_masked_map"], {**_control_map(), "artifact_id": "B04_R6_BLIND_UNIVERSE_MIRROR_MASKED_MAP"})
    _write_json(root / screen.INPUTS["court_contract"], _reference_payload("B04_R6_STATIC_HOLD_ABSTENTION_ROUTE_ECONOMICS_COURT_CONTRACT"))
    _write_json(root / screen.INPUTS["source_packet_contract"], _reference_payload("B04_R6_AFSH_IMPLEMENTATION_SOURCE_PACKET_CONTRACT"))


def _run_screen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    _patch_screen_env(monkeypatch, tmp_path)
    screen.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_screen(tmp_path, monkeypatch)


def _contract(outputs: Path) -> dict:
    return _load(outputs / screen.OUTPUTS["execution_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / screen.OUTPUTS["execution_receipt"])


def _result(outputs: Path) -> dict:
    return _load(outputs / screen.OUTPUTS["result"])


def _scorecard(outputs: Path) -> dict:
    return _load(outputs / screen.OUTPUTS["metric_scorecard"])["scorecard"]


def _next(outputs: Path) -> dict:
    return _load(outputs / screen.OUTPUTS["next_lawful_move"])


def _case_results(outputs: Path) -> list[dict]:
    return _load(outputs / screen.OUTPUTS["case_result_manifest"])["case_results"]


def _row_ids(outputs: Path) -> set[str]:
    return {row["check_id"] for row in _receipt(outputs)["validation_rows"]}


@pytest.mark.parametrize("filename", sorted(screen.OUTPUTS.values()))
def test_required_screen_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    if filename.endswith(".md"):
        assert (outputs / filename).read_text(encoding="utf-8").strip()
    else:
        assert _load(outputs / filename)


def test_screen_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == SCREEN_MAIN_HEAD


def test_screen_binds_validated_packet(outputs: Path) -> None:
    assert "screen_binds_validated_packet" in _row_ids(outputs)


def test_screen_binds_packet_validation_receipt(outputs: Path) -> None:
    assert _contract(outputs)["predecessor_outcome"] == packet_validation.SELECTED_OUTCOME


def test_screen_binds_admissible_candidate(outputs: Path) -> None:
    assert _contract(outputs)["candidate_id"] == screen.CANDIDATE_ID


@pytest.mark.parametrize(
    "hash_key",
    [
        "candidate_artifact_hash",
        "candidate_manifest_hash",
        "candidate_semantic_hash",
        "validated_blind_universe_hash",
        "validated_court_hash",
        "validated_source_packet_hash",
        "admissibility_receipt_hash",
        "numeric_triage_emit_core_hash",
        "trace_schema_hash",
    ],
)
def test_screen_binds_required_hashes(outputs: Path, hash_key: str) -> None:
    assert len(_contract(outputs)["binding_hashes"][hash_key]) == 64


def test_screen_executes_only_packet_bound_inputs(outputs: Path) -> None:
    assert "screen_executes_only_packet_bound_inputs" in _row_ids(outputs)


def test_screen_required_binding_hashes_anchor_to_input_bindings(outputs: Path) -> None:
    assert "screen_required_binding_hashes_anchor_to_input_bindings" in _row_ids(outputs)


def test_screen_candidate_envelope_hash_anchored_to_input_bindings(outputs: Path) -> None:
    assert "screen_candidate_envelope_hash_anchored_to_input_bindings" in _row_ids(outputs)


@pytest.mark.parametrize(
    "metric",
    [
        "route_eligible_delta_vs_static",
        "static_hold_preservation",
        "abstention_preservation",
        "null_route_preservation",
        "overrouting_containment",
        "mirror_masked_stability",
        "wrong_route_cost",
        "wrong_static_hold_cost",
        "proof_burden_delta",
        "trace_completeness",
    ],
)
def test_screen_metrics_pass(outputs: Path, metric: str) -> None:
    assert _scorecard(outputs)["metric_statuses"][metric] == "PASS"


def test_route_eligible_cases_scored_against_static_comparator(outputs: Path) -> None:
    assert _scorecard(outputs)["route_eligible_delta_vs_static"] > 0


def test_only_route_eligible_cases_enter_selector(outputs: Path) -> None:
    assert all(row["selector_entry_authorized"] == (row["top_level_verdict"] == "ROUTE_ELIGIBLE") for row in _case_results(outputs))


@pytest.mark.parametrize("verdict", ["STATIC_HOLD", "ABSTAIN", "NULL_ROUTE"])
def test_non_route_cases_do_not_enter_selector(outputs: Path, verdict: str) -> None:
    assert all(row["selector_entry_authorized"] is False for row in _case_results(outputs) if row["top_level_verdict"] == verdict)


def test_static_hold_cases_preserve_static_hold(outputs: Path) -> None:
    assert _scorecard(outputs)["static_hold_case_count"] == 6


def test_abstention_cases_preserve_abstention(outputs: Path) -> None:
    assert _scorecard(outputs)["abstain_case_count"] == 5


def test_null_route_controls_do_not_enter_selector(outputs: Path) -> None:
    assert _scorecard(outputs)["null_route_case_count"] == 2


def test_route_eligible_case_ids_are_expected(outputs: Path) -> None:
    assert _scorecard(outputs)["route_eligible_case_ids"] == [
        "B04R6-AFSH-BU1-0003",
        "B04R6-AFSH-BU1-0004",
        "B04R6-AFSH-BU1-0005",
        "B04R6-AFSH-BU1-0016",
        "B04R6-AFSH-BU1-0017",
    ]


@pytest.mark.parametrize("field", screen.REQUIRED_TRACE_FIELDS)
def test_trace_fields_present_on_every_case(outputs: Path, field: str) -> None:
    assert all(field in row for row in _case_results(outputs))


@pytest.mark.parametrize("name", screen.TERMINAL_DISQUALIFIERS)
def test_disqualifier_ledger_applied(outputs: Path, name: str) -> None:
    receipt = _load(outputs / screen.OUTPUTS["disqualifier_result_receipt"])
    assert name in receipt["terminal_disqualifiers"]
    assert receipt["disqualifiers"][name] is False


def test_no_terminal_disqualifiers_fire(outputs: Path) -> None:
    receipt = _load(outputs / screen.OUTPUTS["disqualifier_result_receipt"])
    assert receipt["disqualifier_ledger_clean"] is True
    assert receipt["terminal_disqualifier_fired"] is False


def test_partial_win_cannot_claim_superiority(outputs: Path) -> None:
    assert _contract(outputs)["partial_win_can_claim_superiority"] is False


def test_superiority_requires_all_success_conditions(outputs: Path) -> None:
    assert _scorecard(outputs)["all_success_conditions_pass"] is True


def test_success_outcome_routes_to_activation_review_packet_next(outputs: Path) -> None:
    assert _next(outputs)["selected_outcome"] == screen.OUTCOME_PASSED
    assert _next(outputs)["next_lawful_move"] == screen.NEXT_BY_OUTCOME[screen.OUTCOME_PASSED]


@pytest.mark.parametrize("outcome", [screen.OUTCOME_FAILED, screen.OUTCOME_INVALIDATED, screen.OUTCOME_DEFERRED])
def test_non_success_outcomes_have_distinct_routes(outcome: str) -> None:
    assert screen.NEXT_BY_OUTCOME[outcome] != screen.NEXT_BY_OUTCOME[screen.OUTCOME_PASSED]


def test_screen_result_records_shadow_superiority_only(outputs: Path) -> None:
    assert _result(outputs)["shadow_superiority_passed"] is True
    assert _contract(outputs)["shadow_superiority_earned"] is True
    assert _contract(outputs)["learned_router_superiority_earned"] is False


def test_screen_does_not_open_r6(outputs: Path) -> None:
    assert _contract(outputs)["r6_open"] is False


def test_screen_does_not_authorize_activation_cutover(outputs: Path) -> None:
    assert _contract(outputs)["activation_cutover_authorized"] is False


def test_screen_does_not_authorize_lobe_escalation(outputs: Path) -> None:
    assert _contract(outputs)["lobe_escalation_authorized"] is False


def test_screen_does_not_authorize_package_promotion(outputs: Path) -> None:
    assert _contract(outputs)["package_promotion_authorized"] is False


def test_truth_engine_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["truth_engine_derivation_law_unchanged"] is True


def test_trust_zone_law_unchanged(outputs: Path) -> None:
    assert _contract(outputs)["trust_zone_law_unchanged"] is True


def test_turboquant_artifacts_remain_prep_only(outputs: Path) -> None:
    assert "turboquant_artifacts_remain_prep_only" in _row_ids(outputs)


def test_compressed_index_cannot_be_source_of_truth(outputs: Path) -> None:
    assert "compressed_index_cannot_be_source_of_truth" in _row_ids(outputs)


def test_raw_hash_bound_artifact_required_after_compressed_retrieval(outputs: Path) -> None:
    assert "raw_hash_bound_artifact_required_after_compressed_retrieval" in _row_ids(outputs)


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _load(outputs / screen.OUTPUTS["no_authorization_drift_receipt"])
    assert receipt["status"] == "PASS"
    assert receipt["no_downstream_authorization_drift"] is True


def test_next_lawful_move_matches_selected_outcome(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == screen.NEXT_BY_OUTCOME[_next(outputs)["selected_outcome"]]


@pytest.mark.parametrize(
    "output_role",
    [
        "activation_review_packet_prep_only_draft",
        "activation_risk_register_prep_only_draft",
        "runtime_guard_requirements_prep_only_draft",
        "rollback_plan_prep_only_draft",
        "superiority_not_earned_closeout_prep_only_draft",
        "redesign_authorization_court_prep_only_draft",
        "forensic_invalidation_court_prep_only_draft",
    ],
)
def test_future_drafts_remain_prep_only(outputs: Path, output_role: str) -> None:
    payload = _load(outputs / screen.OUTPUTS[output_role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_activation_cutover"] is True
    assert payload["cannot_authorize_package_promotion"] is True


def test_screen_rejects_mutated_candidate_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    path = tmp_path / screen.INPUTS["candidate_artifact"]
    payload = _load(path)
    payload["candidate_id"] = "MUTATED"
    _write_json(path, payload)
    _patch_screen_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        screen.run(reports_root=reports)


@pytest.mark.parametrize(
    "hash_key",
    [
        "validated_blind_universe_hash",
        "validated_court_hash",
        "validated_source_packet_hash",
        "admissibility_receipt_hash",
    ],
)
def test_screen_rejects_mutated_bound_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hash_key: str) -> None:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    path = reports / packet_validation.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["binding_hashes"][hash_key] = "0" * 64
    _write_json(path, payload)
    _patch_screen_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        screen.run(reports_root=reports)


def test_screen_rejects_mutated_metric_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    path = tmp_path / screen.INPUTS["metric_contract"]
    payload = _load(path)
    payload["primary_metrics"] = []
    _write_json(path, payload)
    _patch_screen_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        screen.run(reports_root=reports)


def test_screen_rejects_mutated_static_comparator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    path = tmp_path / screen.INPUTS["static_comparator_contract"]
    payload = _load(path)
    payload["comparator_weakening_forbidden"] = False
    _write_json(path, payload)
    _patch_screen_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        screen.run(reports_root=reports)


def test_screen_copied_outcome_move_fields_without_lane_identity_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = validation_helpers._run_validation(tmp_path, monkeypatch)
    _write_screen_inputs(reports)
    path = tmp_path / screen.INPUTS["previous_next_lawful_move"]
    payload = _load(path)
    payload["authoritative_lane"] = "WRONG_LANE"
    payload["selected_outcome"] = screen.OUTCOME_PASSED
    payload["next_lawful_move"] = screen.NEXT_BY_OUTCOME[screen.OUTCOME_PASSED]
    _write_json(path, payload)
    _patch_screen_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="FAIL_CLOSED"):
        screen.run(reports_root=reports)


def test_metric_widening_disqualifies_unit() -> None:
    scorecard = {"metric_statuses": {metric: "PASS" for metric in _scorecard_from_statuses().keys()}}
    scorecard["metric_statuses"]["trace_completeness"] = "FAIL"
    assert screen._disqualifier_results(scorecard)["disqualifiers"]["trace_incompleteness"] is True


def _scorecard_from_statuses() -> dict:
    return {
        "static_hold_preservation": "PASS",
        "abstention_preservation": "PASS",
        "null_route_preservation": "PASS",
        "overrouting_containment": "PASS",
        "mirror_masked_stability": "PASS",
        "trace_completeness": "PASS",
    }
