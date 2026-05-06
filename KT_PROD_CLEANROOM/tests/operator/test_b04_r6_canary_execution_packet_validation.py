from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_canary_execution_packet as execution
from tools.operator import cohort0_b04_r6_canary_execution_packet_validation as validation


VALIDATION_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
VALIDATION_MAIN_HEAD = "d72bf5dd1e025839afeb00eec4cb5e506789ee5c"


def _load_execution_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_canary_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_canary_execution_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load canary execution helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


execution_helpers = _load_execution_helpers()


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
    commits = {origin_main, execution_helpers.EXECUTION_MAIN_HEAD}
    raw_inputs = list(validation.EXECUTION_JSON_INPUTS.values()) + list(validation.EXECUTION_TEXT_INPUTS.values())
    git_blob_store = {
        (commit, raw): (tmp_path / raw).read_bytes()
        for commit in commits
        for raw in raw_inputs
        if (tmp_path / raw).exists()
    }

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        return git_blob_store.get((commit, raw), (root / raw).read_bytes())

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        contract_path = root / "KT_PROD_CLEANROOM/reports" / execution.OUTPUTS["packet_contract"]
        if contract_path.exists():
            contract = _load(contract_path)
            for row in contract.get("input_bindings", []):
                if row.get("path") == raw and row.get("git_commit") == commit:
                    return row["sha256"]
                if row.get("path") == raw and commit == contract.get("current_main_head"):
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


def _run_execution_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return execution_helpers._run_execution(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("canary_execution_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _contract(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_contract"])


def _receipt(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["validation_receipt"])


def _next(outputs: Path) -> dict:
    return _load(outputs / validation.OUTPUTS["next_lawful_move"])


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _json_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_canary_execution_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
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


def test_validation_binds_canary_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == execution.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == execution.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == execution.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_selects_expected_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME


def test_next_lawful_move_is_canary_runtime(outputs: Path) -> None:
    nxt = _next(outputs)
    assert nxt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert nxt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_runtime_next_but_not_run(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "next lawful lane" in text
    assert "does not execute canary" in text
    assert "does not authorize runtime cutover" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_JSON_INPUTS))
def test_validation_binding_hashes_include_each_execution_json_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.EXECUTION_TEXT_INPUTS))
def test_validation_binding_hashes_include_each_execution_text_input(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("row_index", range(0, 80))
def test_input_binding_rows_have_hash_shape(outputs: Path, row_index: int) -> None:
    rows = _contract(outputs)["input_bindings"]
    if row_index >= len(rows):
        pytest.skip("fewer input rows than parameterized guard")
    row = rows[row_index]
    assert len(row["sha256"]) == 64
    assert all(ch in "0123456789abcdef" for ch in row["sha256"])


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert payload["validated_hashes"]


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_bind_hashes(outputs: Path, role: str) -> None:
    receipt = _payload(outputs, role)
    for value in receipt["validated_hashes"].values():
        assert len(value) == 64
        assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("key", execution.REQUIRED_SOURCE_HASHES)
def test_authoring_packet_source_hashes_remain_bound(outputs: Path, key: str) -> None:
    author_contract = _load(outputs / execution.OUTPUTS["packet_contract"])
    value = author_contract["source_hashes"][key]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_validation_marks_packet_validated_runtime_next_not_executed(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["canary_execution_packet_authored"] is True
    assert contract["canary_execution_packet_validated"] is True
    assert contract["canary_runtime_next_lawful_lane"] is True
    assert contract["canary_runtime_authorized"] is False
    assert contract["canary_runtime_executed"] is False


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


@pytest.mark.parametrize("role", execution.CANARY_EXECUTION_CONTRACT_ROLES)
def test_authoring_operational_contracts_stay_bound_non_executing(outputs: Path, role: str) -> None:
    payload = _load(outputs / execution.OUTPUTS[role])
    assert payload["contract_status"] == "BOUND_NON_EXECUTING"
    assert payload["canary_runtime_executed"] is False
    assert payload["runtime_cutover_authorized"] is False


@pytest.mark.parametrize(
    "role,detail_key,expected",
    [
        ("mode_contract", "mode", "LIMITED_OPERATOR_OBSERVED_CANARY_PACKET_ONLY"),
        ("scope_manifest", "scope_status", "LIMITED_CANARY_EXECUTION_SCOPE_BOUND_NOT_VALIDATED"),
        ("scope_manifest", "global_r6_scope_allowed", False),
        ("scope_manifest", "runtime_cutover_allowed", False),
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
        ("incident_freeze_contract", "freeze_on_incident", True),
        ("runtime_receipt_schema", "raw_hash_bound_artifacts_required", True),
        ("runtime_receipt_schema", "compressed_index_source_of_truth", False),
        ("replay_manifest", "raw_hash_bound_artifacts_required", True),
        ("replay_manifest", "compressed_index_source_of_truth", False),
        ("external_verifier_requirements", "external_verifier_required", True),
        ("result_interpretation_contract", "pass_does_not_authorize_cutover", True),
    ],
)
def test_authoring_required_details_validate(outputs: Path, role: str, detail_key: str, expected: object) -> None:
    assert _load(outputs / execution.OUTPUTS[role])["details"][detail_key] == expected


def test_allowed_case_classes_validate(outputs: Path) -> None:
    allowed = _load(outputs / execution.OUTPUTS["allowed_case_class_contract"])["details"]["allowed_case_classes"]
    assert {row["case_class"] for row in allowed} == {
        "ROUTE_ELIGIBLE_LOW_RISK_SHADOW_CONFIRMED",
        "STATIC_FALLBACK_AVAILABLE_ROUTE_CHECK",
        "NON_COMMERCIAL_OPERATOR_OBSERVED_SAMPLE",
    }


def test_excluded_case_classes_validate(outputs: Path) -> None:
    excluded = _load(outputs / execution.OUTPUTS["excluded_case_class_contract"])["details"]["excluded_case_classes"]
    assert "GLOBAL_R6_TRAFFIC" in {row["case_class"] for row in excluded}
    assert "NULL_ROUTE_CONTROL" in {row["case_class"] for row in excluded}
    assert "COMMERCIAL_ACTIVATION_SURFACE" in {row["case_class"] for row in excluded}


def test_expected_artifacts_validate(outputs: Path) -> None:
    manifest = _load(outputs / execution.OUTPUTS["expected_artifact_manifest"])["details"]
    assert "b04_r6_canary_runtime_execution_receipt.json" in manifest["expected_artifacts"]
    assert "b04_r6_canary_runtime_result.json" in manifest["expected_artifacts"]


def test_replay_manifest_validate(outputs: Path) -> None:
    manifest = _load(outputs / execution.OUTPUTS["replay_manifest"])["details"]
    assert "b04_r6_canary_runtime_execution_receipt.json" in manifest["required_artifacts"]
    assert manifest["raw_hash_bound_artifacts_required"] is True


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_validation")
    assert receipt["no_authorization_drift"] is True
    assert receipt["canary_runtime_executed"] is False
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_prep_only_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["status"] == "PREP_ONLY"
    assert payload["authority"] == "PREP_ONLY_NON_AUTHORITY"
    assert payload["can_authorize"] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("flag", ["canary_runtime_executed", "runtime_cutover_authorized", "r6_open", "package_promotion_authorized", "commercial_activation_claim_authorized"])
def test_prep_only_outputs_do_not_authorize(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


def test_paired_lane_compiler_scaffold_is_non_authoritative(outputs: Path) -> None:
    scaffold = _payload(outputs, "paired_lane_compiler_scaffold_receipt")
    assert scaffold["scaffold_authority"] == "PREP_ONLY_TOOLING"
    assert scaffold["scaffold_can_authorize"] is False
    assert scaffold["scaffold"]["author_lane_id"] == "VALIDATE_B04_R6_CANARY_EXECUTION_PACKET"
    assert scaffold["scaffold"]["validation_lane_id"] == "RUN_B04_R6_LIMITED_RUNTIME_CANARY"


def test_pipeline_board_routes_to_canary_runtime_next(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row for row in board["lanes"]}
    assert lanes["VALIDATE_B04_R6_CANARY_EXECUTION_PACKET"]["status"] == "CURRENT_VALIDATED"
    assert lanes["RUN_B04_R6_LIMITED_RUNTIME_CANARY"]["status"] == "NEXT"
    assert lanes["AUTHOR_B04_R6_PACKAGE_PROMOTION_REVIEW_PACKET"]["status"] == "BLOCKED"


def test_future_blocker_register_blocks_promotion_and_claims(outputs: Path) -> None:
    blockers = {row["blocker_id"] for row in _payload(outputs, "future_blocker_register")["blockers"]}
    assert "CANARY_RUNTIME_NOT_EXECUTED" in blockers
    assert "CANARY_EVIDENCE_REVIEW_NOT_VALIDATED" in blockers
    assert "COMMERCIAL_ACTIVATION_CLAIMS_UNAUTHORIZED" in blockers


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_preserve_lane_identity(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert payload["selected_outcome"] == validation.SELECTED_OUTCOME
    assert payload["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize("field,expected", [("canary_execution_packet_validated", True), ("canary_runtime_next_lawful_lane", True), ("canary_runtime_executed", False), ("runtime_cutover_authorized", False), ("r6_open", False)])
def test_all_json_outputs_preserve_authority_state(outputs: Path, role: str, field: str, expected: object) -> None:
    payload = _payload(outputs, role)
    assert payload[field] == expected


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M changed.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        validation.run(reports_root=reports)


def test_execution_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "DRIFT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKET_BINDING_MISSING"):
        validation.run(reports_root=reports)


def test_runtime_receipt_schema_compressed_truth_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_only(tmp_path, monkeypatch)
    path = reports / execution.OUTPUTS["runtime_receipt_schema"]
    payload = _load(path)
    payload["details"]["compressed_index_source_of_truth"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="RUNTIME_RECEIPT_SCHEMA_MISSING"):
        validation.run(reports_root=reports)


def test_canary_execution_validation_self_replay_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    assert _load(reports / validation.OUTPUTS["next_lawful_move"])["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_malformed_self_replay_handoff_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["previous_next_lawful_move"] = "DRIFT"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)
