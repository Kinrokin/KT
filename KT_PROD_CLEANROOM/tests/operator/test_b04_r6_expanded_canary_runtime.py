from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet as packet
from tools.operator import cohort0_b04_r6_expanded_canary_execution_packet_validation as packet_validation
from tools.operator import cohort0_b04_r6_expanded_canary_runtime as runtime


RUNTIME_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
RUNTIME_MAIN_HEAD = "69e9ec5d0796acfaf56b14b3ce4c2860e98323fa"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_expanded_canary_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_expanded_canary_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load expanded canary execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_candidate_binding(reports: Path) -> None:
    path = reports / "b04_r6_activation_review_candidate_binding_validation_receipt.json"
    if path.exists():
        return
    payload = {
        "schema_id": "test.seed.b04_r6.activation_review_candidate_binding_validation_receipt.v1",
        "artifact_id": "B04_R6_ACTIVATION_REVIEW_CANDIDATE_BINDING_VALIDATION_RECEIPT",
        "candidate_hash": "0" * 63 + "1",
        "candidate_manifest_hash": "0" * 63 + "2",
        "candidate_semantic_hash": "0" * 63 + "3",
        "runtime_cutover_authorized": False,
        "activation_cutover_executed": False,
        "r6_open": False,
        "global_runtime_surface_authorized": False,
        "lobe_escalation_authorized": False,
        "package_promotion": "DEFERRED",
        "package_promotion_authorized": False,
        "commercial_activation_claim_authorized": False,
        "truth_engine_law_changed": False,
        "trust_zone_law_changed": False,
        "metric_contract_mutated": False,
        "static_comparator_weakened": False,
    }
    _write(path, payload)


def _patch_runtime_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = runtime.AUTHORITY_BRANCH,
    head: str = RUNTIME_HEAD,
    origin_main: str = RUNTIME_MAIN_HEAD,
    dirty: str = "",
) -> None:
    monkeypatch.setattr(runtime, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(runtime.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(runtime.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(runtime.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)
    monkeypatch.setattr(
        runtime,
        "validate_trust_zones",
        lambda root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    _patch_runtime_env(monkeypatch, tmp_path)
    runtime.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("expanded_canary_runtime")
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
def test_required_expanded_canary_runtime_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert path.read_text(encoding="utf-8").strip()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_runtime_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == RUNTIME_MAIN_HEAD


def test_runtime_binds_validated_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == packet_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == packet_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == packet_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_validation_contract_hash"]
    assert contract["binding_hashes"]["packet_packet_contract_hash"]


def test_runtime_selects_success_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == runtime.SELECTED_OUTCOME
    assert _result(outputs)["selected_outcome"] == runtime.SELECTED_OUTCOME


def test_success_routes_to_expanded_canary_evidence_review(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == runtime.NEXT_LAWFUL_MOVE
    assert _contract(outputs)["outcome_routing"][runtime.OUTCOME_PASSED] == runtime.NEXT_LAWFUL_MOVE


def test_report_states_runtime_without_cutover(outputs: Path) -> None:
    text = (outputs / runtime.OUTPUTS["report"]).read_text(encoding="utf-8").lower()
    assert "expanded canary ran" in text
    assert "does not authorize runtime cutover" in text
    assert "package promotion" in text
    assert "commercial activation claims" in text


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("expanded_canary_runtime_authorized", True),
        ("expanded_canary_runtime_executed", True),
        ("runtime_cutover_authorized", False),
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
        ("expanded_canary_result_treated_as_package_promotion", False),
    ],
)
def test_all_json_outputs_preserve_authority_state(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", sorted(runtime.ALL_JSON_INPUTS))
def test_runtime_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(runtime.ALL_TEXT_INPUTS))
def test_runtime_binds_all_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize(
    "carried_hash",
    [
        "validated_expanded_canary_execution_packet_hash",
        "validated_expanded_canary_execution_packet_receipt_hash",
        "validated_expanded_canary_authorization_hash",
        "canary_evidence_review_validation_hash",
        "afsh_candidate_hash",
        "afsh_candidate_manifest_hash",
        "afsh_candidate_semantic_hash",
    ],
)
def test_runtime_carries_required_hashes(outputs: Path, carried_hash: str) -> None:
    value = _contract(outputs)["binding_hashes"][carried_hash]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_case_manifest_respects_expanded_sample_limit(outputs: Path) -> None:
    cases = _case_manifest(outputs)["cases"]
    assert len(cases) == runtime.MAX_CASES
    assert _contract(outputs)["scorecard"]["sample_limit_respected"] is True


def test_route_observations_respect_limit(outputs: Path) -> None:
    assert _contract(outputs)["scorecard"]["route_observations"] <= runtime.MAX_ROUTE_OBSERVATIONS


@pytest.mark.parametrize("case_class", runtime.CASE_CLASSES)
def test_all_allowed_case_classes_appear(outputs: Path, case_class: str) -> None:
    observed = {row["case_class"] for row in _case_manifest(outputs)["cases"]}
    assert case_class in observed


@pytest.mark.parametrize("case_class", runtime.EXCLUDED_CASE_CLASS_BLOCKS)
def test_excluded_case_classes_are_blocked(outputs: Path, case_class: str) -> None:
    manifest = _case_manifest(outputs)
    assert case_class in manifest["excluded_case_class_blocks"]
    assert all(row["case_class"] != case_class for row in manifest["cases"])


@pytest.mark.parametrize("case_index", range(0, runtime.MAX_CASES))
def test_each_case_preserves_controls(outputs: Path, case_index: int) -> None:
    row = _case_manifest(outputs)["cases"][case_index]
    assert row["operator_observed"] is True
    assert row["static_fallback_available"] is True
    assert row["abstention_fallback_available"] is True
    assert row["null_route_control"] is False
    assert row["trace_complete"] is True
    assert row["runtime_cutover_authorized"] is False
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
        ("trace_completeness_receipt", "trace_complete_cases", runtime.MAX_CASES),
        ("replay_receipt", "replay_status", "PASS"),
        ("external_verifier_readiness_receipt", "external_verifier_ready", True),
        ("commercial_claim_boundary_receipt", "commercial_activation_claim_authorized", False),
        ("no_authorization_drift_receipt", "no_downstream_authorization_drift", True),
    ],
)
def test_runtime_receipts_pass(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", runtime.PREP_ONLY_ROLES)
def test_downstream_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["can_authorize"] is False
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_pipeline_board_routes_to_evidence_review(outputs: Path) -> None:
    lanes = {row["lane"]: row for row in _payload(outputs, "pipeline_board")["lanes"]}
    assert lanes["RUN_B04_R6_EXPANDED_CANARY_RUNTIME"]["status"] == "CURRENT_EXECUTED"
    assert lanes["AUTHOR_B04_R6_EXPANDED_CANARY_EVIDENCE_REVIEW_PACKET"]["status"] == "NEXT"
    assert lanes["RUNTIME_CUTOVER_REVIEW"]["status"] == "BLOCKED"


def test_no_authorization_drift_receipt_preserves_boundaries(outputs: Path) -> None:
    receipt = _payload(outputs, "no_authorization_drift_receipt")
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False
    assert receipt["package_promotion_authorized"] is False
    assert receipt["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize("code", runtime.AUTHORITY_DRIFT_KEYS.values())
def test_all_authority_drift_reason_codes_are_published(code: str) -> None:
    assert code in runtime.REASON_CODES


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    _patch_runtime_env(monkeypatch, tmp_path, dirty=" M changed.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        runtime.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    _patch_runtime_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(RuntimeError, match="must run on one of"):
        runtime.run(reports_root=reports)


def test_validation_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "DRIFT"
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="VALIDATION_MISSING"):
        runtime.run(reports_root=reports)


def test_validation_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    path = reports / packet_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "DRIFT"
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="NEXT_MOVE_DRIFT"):
        runtime.run(reports_root=reports)


def test_execution_packet_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    path = reports / packet.OUTPUTS["sample_limit_contract"]
    payload = _load(path)
    payload["details"]["max_cases"] = runtime.MAX_CASES + 1
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="SAMPLE_LIMIT_EXCEEDED|EXECUTION_PACKET_BINDING_MISSING"):
        runtime.run(reports_root=reports)


def test_runtime_cutover_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["runtime_cutover_authorized"] = True
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="CUTOVER_AUTHORIZED"):
        runtime.run(reports_root=reports)


def test_package_promotion_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _seed_candidate_binding(reports)
    path = reports / packet_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    _write(path, payload)
    _patch_runtime_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PACKAGE_PROMOTION_DRIFT"):
        runtime.run(reports_root=reports)
