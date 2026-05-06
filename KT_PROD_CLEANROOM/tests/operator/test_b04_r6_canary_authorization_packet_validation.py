from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_authorization_packet as canary
from tools.operator import cohort0_b04_r6_canary_authorization_packet_validation as validation


VALIDATION_HEAD = "9999999999999999999999999999999999999999"
VALIDATION_MAIN_HEAD = "63559011785ddf29a5cffca43926ffb181dbec54"


def _load_canary_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_canary_authorization_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_canary_authorization_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load canary authorization helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canary_helpers = _load_canary_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = VALIDATION_MAIN_HEAD,
    dirty: str = "",
) -> None:
    commits = {origin_main, canary_helpers.CANARY_MAIN_HEAD}
    git_blob_store = {
        (commit, raw): (tmp_path / raw).read_bytes()
        for commit in commits
        for raw in list(validation.CANARY_JSON_INPUTS.values()) + list(validation.CANARY_TEXT_INPUTS.values())
        if (tmp_path / raw).exists()
    }

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return git_blob_store.get((commit, raw), (root / raw).read_bytes())

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        contract_path = root / "KT_PROD_CLEANROOM/reports" / canary.OUTPUTS["packet_contract"]
        if contract_path.exists():
            contract = _load(contract_path)
            for row in contract.get("input_bindings", []):
                if row.get("path") == raw and row.get("git_commit") == commit:
                    return row["sha256"]
        return hashlib.sha256(fake_git_blob_bytes(root, commit, raw)).hexdigest()

    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(validation, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(validation, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_canary_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return canary_helpers._run_canary(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_canary_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("canary_authorization_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _noauth(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["no_authorization_drift_validation"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_canary_authorization_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_canary_authorization_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == canary.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == canary.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == canary.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_canary_execution_packet(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_execution(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not authorize canary runtime" in text
    assert "does not execute canary" in text
    assert "does not authorize runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(validation.CANARY_JSON_INPUTS))
def test_validation_binding_hashes_include_each_canary_json_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.CANARY_TEXT_INPUTS))
def test_validation_binding_hashes_include_each_canary_text_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize(
    "role",
    [
        "packet_binding_validation",
        "runtime_evidence_validation_binding",
        "runtime_evidence_inventory_validation",
        "runtime_evidence_scorecard_validation",
        "shadow_runtime_result_validation",
        "static_authority_evidence_validation",
        "route_distribution_health_evidence_validation",
        "fallback_behavior_evidence_validation",
        "operator_override_validation",
        "kill_switch_validation",
        "rollback_validation",
        "drift_monitoring_validation",
        "incident_freeze_validation",
        "external_verifier_validation",
        "commercial_claim_boundary_validation",
        "package_promotion_prohibition_validation",
        "scope_validation",
        "allowed_case_class_validation",
        "excluded_case_class_validation",
        "sample_limit_validation",
        "static_fallback_validation",
        "abstention_fallback_validation",
        "null_route_preservation_validation",
        "runtime_receipt_schema_validation",
        "pipeline_board_validation",
    ],
)
def test_validation_receipts_bind_source_hashes(outputs: Path, role: str) -> None:
    receipt = _payload(outputs, role)
    for value in receipt["validated_hashes"].values():
        assert len(value) == 64
        assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("key", canary.REQUIRED_SOURCE_EVIDENCE_HASHES)
def test_authoring_packet_source_evidence_hashes_remain_bound(outputs: Path, key: str) -> None:
    author_contract = _load(outputs / canary.OUTPUTS["packet_contract"])
    value = author_contract["source_evidence_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize(
    "payload_role",
    [
        "validation_contract",
        "validation_receipt",
        "no_authorization_drift_validation",
        "next_lawful_move",
    ],
)
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
def test_validation_does_not_authorize_forbidden_boundaries(outputs: Path, payload_role: str, flag: str) -> None:
    payload = _payload(outputs, payload_role) if payload_role not in {"validation_contract", "validation_receipt", "next_lawful_move"} else {
        "validation_contract": _contract(outputs),
        "validation_receipt": _receipt(outputs),
        "next_lawful_move": _next(outputs),
    }[payload_role]
    assert payload[flag] is False


def test_validation_marks_packet_validated_but_canary_not_executed(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["canary_authorization_packet_authored"] is True
    assert contract["canary_authorization_packet_validated"] is True
    assert contract["canary_execution_packet_authored"] is False
    assert contract["canary_execution_packet_validated"] is False
    assert contract["canary_runtime_authorized"] is False
    assert contract["canary_runtime_executed"] is False


@pytest.mark.parametrize("role", canary.CANARY_CONTRACT_ROLES)
def test_authoring_operational_contracts_stay_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _load(outputs / canary.OUTPUTS[role])
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["canary_runtime_authorized"] is False
    assert payload["canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize("role", canary.CANARY_CONTRACT_ROLES)
@pytest.mark.parametrize("flag", ["canary_runtime_authorized", "canary_runtime_executed", "runtime_cutover_authorized"])
def test_authoring_operational_contracts_do_not_smuggle_authority(outputs: Path, role: str, flag: str) -> None:
    assert _load(outputs / canary.OUTPUTS[role])[flag] is False


@pytest.mark.parametrize(
    "role,detail_key,expected",
    [
        ("scope_manifest", "scope_status", "LIMITED_CANARY_SCOPE_DEFINED_NOT_AUTHORIZED"),
        ("scope_manifest", "global_r6_scope_allowed", False),
        ("scope_manifest", "runtime_cutover_allowed", False),
        ("scope_manifest", "operator_observed_required", True),
        ("scope_manifest", "max_case_count_per_window", 12),
        ("sample_limit_contract", "max_case_count_per_window", 12),
        ("static_fallback_contract", "static_fallback_required", True),
        ("abstention_fallback_contract", "abstention_fallback_required", True),
        ("null_route_preservation_contract", "null_route_controls_excluded", True),
        ("operator_override_contract", "operator_override_required", True),
        ("kill_switch_contract", "kill_switch_required", True),
        ("rollback_contract", "rollback_required", True),
        ("route_distribution_health_thresholds", "zero_null_route_selector_entries_required", True),
        ("drift_thresholds", "metric_widening_allowed", False),
        ("drift_thresholds", "comparator_weakening_allowed", False),
        ("incident_freeze_contract", "freeze_on_incident", True),
        ("runtime_receipt_schema", "raw_hash_bound_artifacts_required", True),
        ("runtime_receipt_schema", "compressed_index_source_of_truth", False),
        ("external_verifier_requirements", "external_verifier_required", True),
        ("external_verifier_requirements", "non_executing", True),
        ("commercial_claim_boundary", "commercial_activation_claim_authorized", False),
        ("package_promotion_prohibition_receipt", "package_promotion_authorized", False),
    ],
)
def test_canary_authorization_required_details_validate(outputs: Path, role: str, detail_key: str, expected: object) -> None:
    assert _load(outputs / canary.OUTPUTS[role])["details"][detail_key] == expected


def test_canary_allowed_case_classes_defined(outputs: Path) -> None:
    allowed = _load(outputs / canary.OUTPUTS["allowed_case_class_contract"])["details"]["allowed_case_classes"]
    assert {row["case_class"] for row in allowed} == {
        "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED",
        "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK",
        "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE",
    }


@pytest.mark.parametrize(
    "case_class",
    ["GLOBAL_R6_TRAFFIC", "NO_STATIC_FALLBACK_AVAILABLE", "NULL_ROUTE_CONTROL", "COMMERCIAL_ACTIVATION_SURFACE"],
)
def test_canary_excluded_case_classes_defined(outputs: Path, case_class: str) -> None:
    excluded = _load(outputs / canary.OUTPUTS["excluded_case_class_contract"])["details"]["excluded_case_classes"]
    assert case_class in {row["case_class"] for row in excluded}


@pytest.mark.parametrize("role", canary.PREP_ONLY_OUTPUT_ROLES)
def test_authoring_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / canary.OUTPUTS[role])
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["canary_runtime_authorized"] is False
    assert payload["canary_runtime_executed"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["can_authorize"] is False
    assert payload["canary_runtime_authorized"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize(
    "flag",
    [
        "canary_runtime_authorized",
        "canary_runtime_executed",
        "runtime_cutover_authorized",
        "package_promotion_authorized",
        "commercial_activation_claim_authorized",
    ],
)
def test_validation_prep_only_outputs_do_not_authorize(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("code", validation.REASON_CODES)
def test_validation_reason_codes_are_recorded(outputs: Path, code: str) -> None:
    assert code in _contract(outputs)["reason_codes"]


@pytest.mark.parametrize("defect", validation.TERMINAL_DEFECTS)
def test_validation_terminal_defects_are_recorded(outputs: Path, defect: str) -> None:
    assert defect in _contract(outputs)["terminal_defects"]


@pytest.mark.parametrize("row", range(1, 39))
def test_validation_rows_are_pass(outputs: Path, row: int) -> None:
    rows = {index: item for index, item in enumerate(_contract(outputs)["validation_rows"], start=1)}
    assert rows[row]["status"] == "PASS"


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _noauth(outputs)
    assert receipt["no_authorization_drift"] is True
    assert receipt["canary_runtime_authorized"] is False
    assert receipt["runtime_cutover_authorized"] is False


def test_pipeline_board_advances_to_canary_execution_packet(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET"]["status"] == "CURRENT_VALIDATED"
    assert lanes["AUTHOR_B04_R6_CANARY_EXECUTION_PACKET"]["status"] == "NEXT"
    assert lanes["RUN_B04_R6_CANARY_RUNTIME"]["status"] == "BLOCKED"


def test_paired_lane_compiler_scaffold_is_prep_only(outputs: Path) -> None:
    receipt = _payload(outputs, "paired_lane_compiler_scaffold_receipt")
    scaffold = receipt["scaffold"]
    assert receipt["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert receipt["scaffold_can_authorize"] is False
    assert scaffold["paired_lane_law"]["authoring_is_not_validation"] is True
    assert scaffold["paired_lane_law"]["canonical_validation_requires_separate_lane"] is True
    assert scaffold["paired_lane_law"]["compiler_can_authorize"] is False


def test_future_blocker_register_names_next_runtime_gates(outputs: Path) -> None:
    blockers = {row["blocker_id"] for row in _payload(outputs, "future_blocker_register")["blockers"]}
    assert "CANARY_EXECUTION_PACKET_NOT_AUTHORED" in blockers
    assert "CANARY_EXECUTION_PACKET_NOT_VALIDATED" in blockers
    assert "COMMERCIAL_ACTIVATION_CLAIMS_UNAUTHORIZED" in blockers


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M something")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_invalid_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_canary_runtime_authorization_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary_only(tmp_path, monkeypatch)
    path = reports / canary.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["canary_runtime_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CANARY_AUTH_VAL_CANARY_AUTHORIZED"):
        validation.run(reports_root=reports)


def test_missing_sample_limit_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary_only(tmp_path, monkeypatch)
    path = reports / canary.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["details"]["max_case_count_per_window"] = 999
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT"):
        validation.run(reports_root=reports)


def test_self_replay_pipeline_board_handoff_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_canary_only(tmp_path, monkeypatch)
    path = reports / canary.OUTPUTS["pipeline_board"]
    payload = _load(path)
    for row in payload["lanes"]:
        if row["lane"] == "VALIDATE_B04_R6_CANARY_AUTHORIZATION_PACKET":
            row["status"] = "CURRENT_VALIDATED"
        if row["lane"] == "AUTHOR_B04_R6_CANARY_EXECUTION_PACKET":
            row["status"] = "NEXT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)

    result = validation.run(reports_root=reports)

    assert result["selected_outcome"] == validation.SELECTED_OUTCOME
    assert result["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
