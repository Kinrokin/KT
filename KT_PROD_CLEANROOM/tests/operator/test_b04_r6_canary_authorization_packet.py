from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_authorization_packet as canary
from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet as review
from tools.operator import cohort0_b04_r6_runtime_evidence_review_packet_validation as evidence_validation


CANARY_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CANARY_MAIN_HEAD = "211eea5e3eac82dee79b14ab7aac252541bfcfeb"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_evidence_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_evidence_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime evidence validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_canary_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = canary.AUTHORITY_BRANCH,
    head: str = CANARY_HEAD,
    origin_main: str = CANARY_MAIN_HEAD,
    dirty: str = "",
) -> None:
    git_blob_store = {
        (origin_main, raw): (tmp_path / raw).read_bytes()
        for raw in list(canary.ALL_JSON_INPUTS.values()) + list(canary.TEXT_INPUTS.values())
        if (tmp_path / raw).exists()
    }

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return git_blob_store.get((commit, raw), (root / raw).read_bytes())

    monkeypatch.setattr(canary, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(canary.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(canary.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(canary.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(canary, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(
        canary,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_canary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_canary_env(monkeypatch, tmp_path)
    canary.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("canary_authorization_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_canary(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["packet_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["packet_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["next_lawful_move"])


def _scope(outputs: Path) -> dict:
    return _load(outputs / canary.OUTPUTS["scope_manifest"])


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / canary.OUTPUTS[role])


def _json_roles() -> list[str]:
    return sorted(role for role, filename in canary.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(canary.OUTPUTS.values()))
def test_required_canary_authorization_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_canary_packet_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == CANARY_MAIN_HEAD


def test_canary_packet_binds_runtime_evidence_review_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == canary.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == evidence_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == evidence_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == evidence_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["runtime_evidence_validation_contract_hash"]
    assert contract["binding_hashes"]["runtime_evidence_validation_receipt_hash"]


def test_canary_packet_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == canary.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == canary.SELECTED_OUTCOME


def test_next_lawful_move_is_canary_authorization_validation(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == canary.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == canary.NEXT_LAWFUL_MOVE


def test_canary_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / canary.OUTPUTS["packet_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute canary" in text
    assert "does not authorize runtime cutover" in text
    assert "does not open r6" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(canary.ALL_JSON_INPUTS))
def test_binding_hashes_include_each_json_input(outputs: Path, role: str) -> None:
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"]


@pytest.mark.parametrize("role", sorted(canary.TEXT_INPUTS))
def test_binding_hashes_include_each_text_input(outputs: Path, role: str) -> None:
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"]


@pytest.mark.parametrize("key", canary.REQUIRED_SOURCE_EVIDENCE_HASHES)
def test_canary_packet_binds_required_source_evidence(outputs: Path, key: str) -> None:
    value = _contract(outputs)["source_evidence_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_shadow_runtime_result_hash_comes_from_evidence_inventory(outputs: Path) -> None:
    inventory = _load(outputs / review.OUTPUTS["evidence_inventory"])
    expected = next(row["sha256"] for row in inventory["artifacts"] if row["role"] == "shadow_result")
    assert _contract(outputs)["source_evidence_hashes"]["shadow_runtime_result_hash"] == expected


def test_canary_authorization_packet_is_authored_but_not_validated(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["canary_authorization_packet_authored"] is True
    assert contract["canary_authorization_packet_validated"] is False
    assert contract["canary_execution_packet_authored"] is False
    assert contract["canary_execution_packet_validated"] is False


@pytest.mark.parametrize(
    "flag",
    [
        "canary_runtime_authorized",
        "canary_runtime_executed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
        "metric_contract_mutated",
        "static_comparator_weakened",
    ],
)
def test_canary_packet_does_not_authorize_forbidden_boundaries(outputs: Path, flag: str) -> None:
    assert _contract(outputs)[flag] is False


def test_canary_scope_is_limited(outputs: Path) -> None:
    details = _scope(outputs)["details"]
    assert details["scope_status"] == "LIMITED_CANARY_SCOPE_DEFINED_NOT_AUTHORIZED"
    assert details["global_r6_scope_allowed"] is False
    assert details["runtime_cutover_allowed"] is False
    assert details["max_case_count_per_window"] == 12


def test_canary_allowed_case_classes_defined(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_case_class_contract")["details"]["allowed_case_classes"]
    assert {row["case_class"] for row in allowed} == {
        "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED",
        "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK",
        "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE",
    }


def test_canary_excluded_case_classes_defined(outputs: Path) -> None:
    excluded = _payload(outputs, "excluded_case_class_contract")["details"]["excluded_case_classes"]
    assert "GLOBAL_R6_TRAFFIC" in {row["case_class"] for row in excluded}
    assert "NULL_ROUTE_CONTROL" in {row["case_class"] for row in excluded}
    assert "COMMERCIAL_ACTIVATION_SURFACE" in {row["case_class"] for row in excluded}


@pytest.mark.parametrize("role", canary.CANARY_CONTRACT_ROLES)
def test_canary_operational_contracts_are_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["canary_runtime_authorized"] is False
    assert payload["canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize(
    "role,detail_key",
    [
        ("static_fallback_contract", "static_fallback_required"),
        ("abstention_fallback_contract", "abstention_fallback_required"),
        ("null_route_preservation_contract", "null_route_controls_excluded"),
        ("operator_override_contract", "operator_override_required"),
        ("kill_switch_contract", "kill_switch_required"),
        ("rollback_contract", "rollback_required"),
        ("external_verifier_requirements", "external_verifier_required"),
    ],
)
def test_required_canary_safety_controls_are_defined(outputs: Path, role: str, detail_key: str) -> None:
    assert _payload(outputs, role)["details"][detail_key] is True


def test_route_distribution_health_thresholds_defined(outputs: Path) -> None:
    details = _payload(outputs, "route_distribution_health_thresholds")["details"]
    assert details["max_selector_entry_rate_delta_vs_shadow"] == 0.05
    assert details["zero_null_route_selector_entries_required"] is True
    assert details["zero_abstention_override_required"] is True


def test_drift_thresholds_defined(outputs: Path) -> None:
    details = _payload(outputs, "drift_thresholds")["details"]
    assert details["max_unexplained_trace_delta"] == 0
    assert details["mirror_masked_instability_allowed"] is False
    assert details["metric_widening_allowed"] is False
    assert details["comparator_weakening_allowed"] is False


def test_runtime_receipt_schema_defined(outputs: Path) -> None:
    details = _payload(outputs, "runtime_receipt_schema")["details"]
    assert "case_id" in details["required_fields"]
    assert "rollback_receipt_id" in details["required_fields"]
    assert details["raw_hash_bound_artifacts_required"] is True
    assert details["compressed_index_source_of_truth"] is False


def test_commercial_claim_boundary_blocks_activation_claims(outputs: Path) -> None:
    details = _payload(outputs, "commercial_claim_boundary")["details"]
    assert details["commercial_activation_claim_authorized"] is False
    assert "canary not executed" in details["allowed_status_language"].lower()


def test_package_promotion_not_authorized(outputs: Path) -> None:
    details = _payload(outputs, "package_promotion_prohibition_receipt")["details"]
    assert details["package_promotion_authorized"] is False
    assert details["package_promotion"] == "DEFERRED"


@pytest.mark.parametrize("role", canary.PREP_ONLY_OUTPUT_ROLES)
def test_downstream_canary_and_promotion_scaffolds_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["canary_runtime_authorized"] is False
    assert payload["canary_runtime_executed"] is False


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _payload(outputs, "no_authorization_drift_receipt")
    assert payload["no_authorization_drift"] is True
    assert payload["canary_runtime_authorized"] is False
    assert payload["runtime_cutover_authorized"] is False
    assert payload["r6_open"] is False


def test_pipeline_board_advances_to_canary_validation_only(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert (
        lanes["VALIDATE_B04_R6_RUNTIME_EVIDENCE_REVIEW_PACKET"]["next_lane"]
        == "AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"
    )
    assert lanes["AUTHOR_B04_R6_CANARY_AUTHORIZATION_PACKET"]["status"] == "CURRENT_BOUND"
    assert lanes["VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET"]["status"] == "NEXT"
    assert lanes["RUN_B04_R6_LIMITED_RUNTIME_CANARY"]["status"] == "BLOCKED"


def test_future_blocker_register_keeps_runtime_and_promotion_blocked(outputs: Path) -> None:
    blockers = _payload(outputs, "future_blocker_register")["blockers"]
    descriptions = " ".join(row["description"] for row in blockers).lower()
    assert "canary runtime remains blocked" in descriptions
    assert "package promotion remains blocked" in descriptions
    assert "commercial activation claims remain blocked" in descriptions


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "flag",
    [
        "canary_runtime_authorized",
        "canary_runtime_executed",
        "runtime_cutover_authorized",
        "activation_cutover_executed",
        "r6_open",
        "lobe_escalation_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
        "truth_engine_law_changed",
        "trust_zone_law_changed",
    ],
)
def test_every_json_output_keeps_authority_closed(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", _json_roles())
def test_every_json_output_preserves_outcome_and_next_move(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["selected_outcome"] == canary.SELECTED_OUTCOME
    assert payload["next_lawful_move"] == canary.NEXT_LAWFUL_MOVE


def test_validation_plan_points_to_canary_authorization_validation(outputs: Path) -> None:
    plan = _payload(outputs, "validation_plan")
    assert plan["validation_lane"] == canary.NEXT_LAWFUL_MOVE
    assert "runtime_evidence_review_validation_bound" in plan["required_checks"]
    assert "canary_runtime_not_authorized" in plan["required_checks"]


def test_reason_codes_include_terminal_authority_drift_codes(outputs: Path) -> None:
    payload = _payload(outputs, "validation_reason_codes")
    assert "RC_B04R6_CANARY_AUTH_PACKET_CANARY_EXECUTED" in payload["reason_codes"]
    assert "CANARY_RUNTIME_EXECUTED" in payload["terminal_defects"]
    assert "R6_OPEN_DRIFT" in payload["terminal_defects"]


def test_lane_compiler_scaffold_is_prep_only_tooling(outputs: Path) -> None:
    payload = _payload(outputs, "lane_compiler_scaffold_receipt")
    assert payload["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert payload["scaffold_can_authorize"] is False
    assert payload["scaffold"]["authority"] == "PREP_ONLY_TOOLING"


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_canary_env(monkeypatch, tmp_path, dirty=" M suspicious.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        canary.run(reports_root=reports)


def test_wrong_previous_outcome_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    contract_path = reports / evidence_validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["selected_outcome"] = "WRONG"
    _write(contract_path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="outcome drift"):
        canary.run(reports_root=reports)


def test_scorecard_canary_runtime_cases_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    score_path = reports / review.OUTPUTS["evidence_scorecard"]
    payload = _load(score_path)
    payload["scorecard"]["canary_runtime_cases"] = 1
    _write(score_path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="canary_runtime_cases"):
        canary.run(reports_root=reports)


def test_missing_shadow_result_inventory_hash_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    inventory_path = reports / review.OUTPUTS["evidence_inventory"]
    payload = _load(inventory_path)
    payload["artifacts"] = [row for row in payload["artifacts"] if row.get("role") != "shadow_result"]
    payload["artifact_count"] = len(payload["artifacts"])
    _write(inventory_path, payload)
    _patch_canary_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="shadow_result"):
        canary.run(reports_root=reports)
