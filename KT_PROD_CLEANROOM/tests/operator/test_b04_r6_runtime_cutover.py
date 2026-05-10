from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_runtime_cutover as runtime
from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet as packet
from tools.operator import cohort0_b04_r6_runtime_cutover_execution_packet_validation as validation
from tools.operator.titanium_common import file_sha256


RUNTIME_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
RUNTIME_MAIN_HEAD = "aceb7c6bbe966a48a48207c4fb7b9fe34cc41013"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_runtime_cutover_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_runtime_cutover_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load runtime cutover execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_runtime_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = runtime.AUTHORITY_BRANCH,
    head: str = RUNTIME_HEAD,
    origin_main: str = RUNTIME_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(runtime, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(runtime.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(runtime.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(runtime.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        runtime,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_runtime_env(monkeypatch, tmp_path)
    runtime.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("runtime_cutover")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_runtime(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / runtime.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "execution_contract")


def _result(outputs: Path) -> dict:
    return _payload(outputs, "result")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _case_manifest(outputs: Path) -> dict:
    return _payload(outputs, "case_manifest")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in runtime.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(runtime.OUTPUTS.values()))
def test_required_runtime_cutover_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "runtime cutover" in text
        assert "does not open r6" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_runtime_cutover_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == RUNTIME_MAIN_HEAD


def test_runtime_cutover_binds_validated_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_validation_contract_hash"]
    assert contract["binding_hashes"]["packet_packet_contract_hash"]
    assert contract["binding_hashes"]["validated_runtime_cutover_execution_packet_hash"]


def test_runtime_cutover_selects_success_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == runtime.SELECTED_OUTCOME
    assert _result(outputs)["selected_outcome"] == runtime.SELECTED_OUTCOME


def test_success_routes_to_post_cutover_evidence_review(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == runtime.NEXT_LAWFUL_MOVE
    assert _contract(outputs)["outcome_routing"][runtime.OUTCOME_PASSED] == runtime.NEXT_LAWFUL_MOVE


def test_runtime_cutover_executes_but_does_not_open_r6(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["runtime_cutover_executed"] is True
    assert contract["runtime_cutover_performed_under_validated_execution_packet"] is True
    assert contract["activation_cutover_executed"] is False
    assert contract["r6_open"] is False
    assert contract["package_promotion_authorized"] is False
    assert contract["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("runtime_cutover_executed", True),
        ("runtime_cutover_performed_under_validated_execution_packet", True),
        ("activation_cutover_executed", False),
        ("r6_open", False),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("cutover_result_treated_as_r6_opening", False),
        ("cutover_result_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_post_cutover_authority_state(
    outputs: Path, role: str, field: str, expected: object
) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", sorted(runtime.ALL_JSON_INPUTS))
def test_runtime_cutover_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(runtime.ALL_TEXT_INPUTS))
def test_runtime_cutover_binds_all_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role, raw", sorted(runtime.ALL_JSON_INPUTS.items()))
def test_runtime_cutover_binding_hashes_match_json_inputs(outputs: Path, role: str, raw: str) -> None:
    if role in _contract(outputs)["overwritten_input_roles"]:
        pytest.skip("input was intentionally overwritten by runtime-cutover output after pre-run binding")
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", sorted(runtime.ALL_JSON_INPUTS))
def test_overwritten_inputs_are_marked_as_pre_overwrite_bindings(outputs: Path, role: str) -> None:
    bindings = {binding["role"]: binding for binding in _contract(outputs)["input_bindings"]}
    binding = bindings[role]
    if role in _contract(outputs)["overwritten_input_roles"]:
        assert binding["overwritten_by_runtime_cutover_output"] is True
        assert binding["binding_kind"] == "pre_overwrite_file_sha256_at_runtime_cutover"
    else:
        assert binding["overwritten_by_runtime_cutover_output"] is False
        assert binding["binding_kind"] == "file_sha256_at_runtime_cutover"


def test_case_manifest_respects_runtime_cutover_limits(outputs: Path) -> None:
    cases = _case_manifest(outputs)["cases"]
    assert len(cases) == runtime.MAX_CASES
    route_observations = sum(1 for row in cases if row["afsh_verdict"] == "ROUTE")
    assert route_observations <= runtime.MAX_ROUTE_OBSERVATIONS


@pytest.mark.parametrize("case_class", ("validated_r6_routing_cases", "fallback_preserved_cases", "operator_observed_cases"))
def test_allowed_case_classes_appear(outputs: Path, case_class: str) -> None:
    assert case_class in {row["case_class"] for row in _case_manifest(outputs)["cases"]}


@pytest.mark.parametrize("row_index", range(runtime.MAX_CASES))
def test_each_case_preserves_cutover_controls(outputs: Path, row_index: int) -> None:
    row = _case_manifest(outputs)["cases"][row_index]
    assert row["operator_observed"] is True
    assert row["static_fallback_available"] is True
    assert row["abstention_fallback_available"] is True
    assert row["null_route_preserved"] is True
    assert row["operator_override_ready"] is True
    assert row["kill_switch_status"] == "READY_NOT_INVOKED"
    assert row["rollback_status"] == "READY_NOT_INVOKED"
    assert row["trace_complete"] is True
    assert row["activation_cutover_executed"] is False
    assert row["r6_open"] is False


@pytest.mark.parametrize(
    "role,field,expected",
    [
        ("route_distribution_receipt", "route_distribution_health", "PASS"),
        ("fallback_behavior_receipt", "fallback_failures", 0),
        ("static_fallback_receipt", "static_fallback_preserved", True),
        ("abstention_fallback_receipt", "abstention_fallback_preserved", True),
        ("null_route_preservation_receipt", "null_route_preserved", True),
        ("operator_override_receipt", "operator_override_ready", True),
        ("kill_switch_receipt", "kill_switch_ready", True),
        ("rollback_receipt", "rollback_ready", True),
        ("drift_monitoring_receipt", "drift_status", "PASS"),
        ("replay_receipt", "replay_status", "PASS"),
        ("external_verifier_readiness_receipt", "external_verifier_ready", True),
    ],
)
def test_runtime_cutover_receipts_pass(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", runtime.PREP_ONLY_ROLES)
def test_downstream_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_pipeline_board_routes_to_post_cutover_evidence_review(outputs: Path) -> None:
    lanes = {row["lane"]: row["status"] for row in _payload(outputs, "pipeline_board")["lanes"]}
    assert lanes["RUN_B04_R6_RUNTIME_CUTOVER"] == "CURRENT_EXECUTED"
    assert lanes["AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"] == "NEXT"
    assert lanes["R6_OPENING_REVIEW"] == "BLOCKED_PENDING_POST_CUTOVER_REVIEW"


def test_no_authorization_drift_receipt_preserves_boundaries(outputs: Path) -> None:
    payload = _payload(outputs, "no_authorization_drift_receipt")
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["r6_open"] is False
    assert payload["package_promotion_authorized"] is False


@pytest.mark.parametrize("code", runtime.AUTHORITY_DRIFT_KEYS.values())
def test_all_authority_drift_reason_codes_are_published(code: str) -> None:
    assert code in runtime.REASON_CODES


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_runtime_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        runtime.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_runtime_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(runtime.LaneFailure, match="branch"):
        runtime.run(reports_root=reports)


def test_validation_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_RUNTIME_CUTOVER_EXECUTION_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(runtime.LaneFailure, match="OUTCOME_DRIFT"):
        runtime.run(reports_root=reports)


def test_validation_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_POST_CUTOVER_EVIDENCE_REVIEW_PACKET"
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(runtime.LaneFailure, match="NEXT_MOVE_DRIFT"):
        runtime.run(reports_root=reports)


def test_packet_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["global_runtime_surface"] = True
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(runtime.LaneFailure, match="GLOBAL_SURFACE_DRIFT|PACKET_HASH_DRIFT|SCOPE_VIOLATION"):
        runtime.run(reports_root=reports)


def test_activation_cutover_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["activation_cutover_executed"] = True
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(runtime.LaneFailure, match="ACTIVATION_CUTOVER_EXECUTED"):
        runtime.run(reports_root=reports)


def test_r6_open_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["r6_open"] = True
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(runtime.LaneFailure, match="R6_OPEN_DRIFT"):
        runtime.run(reports_root=reports)
