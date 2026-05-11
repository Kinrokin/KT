from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening as opening
from tools.operator import cohort0_b04_r6_r6_opening_execution_packet as packet
from tools.operator import cohort0_b04_r6_r6_opening_execution_packet_validation as validation
from tools.operator.titanium_common import file_sha256


OPENING_HEAD = "8888888888888888888888888888888888888888"
OPENING_MAIN_HEAD = "1ce70b1a5553d28dad24a083fb16cbd4e066167c"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_opening_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = opening.AUTHORITY_BRANCH,
    head: str = OPENING_HEAD,
    origin_main: str = OPENING_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(opening, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(opening.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(opening.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(opening.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        opening,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_opening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_opening_env(monkeypatch, tmp_path)
    opening.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_opening(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / opening.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "execution_contract")


def _result(outputs: Path) -> dict:
    return _payload(outputs, "result")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _case_manifest(outputs: Path) -> dict:
    return _payload(outputs, "case_manifest")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in opening.OUTPUTS.items() if filename.endswith(".json"))


@pytest.mark.parametrize("filename", sorted(opening.OUTPUTS.values()))
def test_required_r6_opening_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "r6 opening" in text
        assert "does not promote package" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_r6_opening_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == OPENING_MAIN_HEAD


def test_r6_opening_binds_validated_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_validation_contract_hash"]
    assert contract["binding_hashes"]["packet_packet_contract_hash"]
    assert contract["binding_hashes"]["validated_r6_opening_execution_packet_hash"]


def test_r6_opening_selects_success_outcome(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == opening.SELECTED_OUTCOME
    assert _result(outputs)["selected_outcome"] == opening.SELECTED_OUTCOME


def test_success_routes_to_r6_opening_evidence_review(outputs: Path) -> None:
    assert _next(outputs)["next_lawful_move"] == opening.NEXT_LAWFUL_MOVE
    assert _contract(outputs)["outcome_routing"][opening.OUTCOME_PASSED] == opening.NEXT_LAWFUL_MOVE


def test_r6_opening_executes_and_opens_r6_without_downstream_authority(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["r6_opening_authorized"] is True
    assert contract["r6_opening_executed"] is True
    assert contract["r6_open"] is True
    assert contract["global_runtime_surface_authorized"] is False
    assert contract["lobe_escalation_authorized"] is False
    assert contract["package_promotion_authorized"] is False
    assert contract["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize("role", _json_roles())
@pytest.mark.parametrize(
    "field,expected",
    [
        ("r6_opening_authorized", True),
        ("r6_opening_executed", True),
        ("r6_open", True),
        ("global_runtime_surface_authorized", False),
        ("lobe_escalation_authorized", False),
        ("package_promotion_authorized", False),
        ("commercial_activation_claim_authorized", False),
        ("truth_engine_law_changed", False),
        ("trust_zone_law_changed", False),
        ("metric_contract_mutated", False),
        ("static_comparator_weakened", False),
        ("r6_open_treated_as_package_promotion", False),
        ("r6_open_treated_as_commercial_activation", False),
    ],
)
def test_all_json_outputs_preserve_post_opening_authority_state(
    outputs: Path, role: str, field: str, expected: object
) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", sorted(opening.ALL_JSON_INPUTS))
def test_r6_opening_binds_all_json_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role", sorted(opening.ALL_TEXT_INPUTS))
def test_r6_opening_binds_all_text_inputs(outputs: Path, role: str) -> None:
    assert f"{role}_hash" in _contract(outputs)["binding_hashes"]


@pytest.mark.parametrize("role, raw", sorted(opening.ALL_JSON_INPUTS.items()))
def test_r6_opening_binding_hashes_match_json_inputs(outputs: Path, role: str, raw: str) -> None:
    if role in _contract(outputs)["overwritten_input_roles"]:
        pytest.skip("input was intentionally overwritten by R6 opening output after pre-run binding")
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", sorted(opening.ALL_JSON_INPUTS))
def test_overwritten_inputs_are_marked_as_pre_overwrite_bindings(outputs: Path, role: str) -> None:
    bindings = {binding["role"]: binding for binding in _contract(outputs)["input_bindings"]}
    binding = bindings[role]
    if role in _contract(outputs)["overwritten_input_roles"]:
        assert binding["overwritten_by_r6_opening_output"] is True
        assert binding["binding_kind"] == "pre_overwrite_file_sha256_at_r6_opening"
    else:
        assert binding["overwritten_by_r6_opening_output"] is False
        assert binding["binding_kind"] == "file_sha256_at_r6_opening"


def test_case_manifest_respects_r6_opening_limits(outputs: Path) -> None:
    cases = _case_manifest(outputs)["cases"]
    assert len(cases) == opening.MAX_CASES
    route_observations = sum(1 for row in cases if row["afsh_verdict"] == "ROUTE")
    assert route_observations <= opening.MAX_ROUTE_OBSERVATIONS


@pytest.mark.parametrize(
    "case_class",
    ("bounded_r6_operational_surface", "fallback_preserved_surface", "operator_observed_surface"),
)
def test_allowed_case_classes_appear(outputs: Path, case_class: str) -> None:
    assert case_class in {row["case_class"] for row in _case_manifest(outputs)["cases"]}


@pytest.mark.parametrize("row_index", range(opening.MAX_CASES))
def test_each_case_preserves_opening_controls(outputs: Path, row_index: int) -> None:
    row = _case_manifest(outputs)["cases"][row_index]
    assert row["operator_observed"] is True
    assert row["static_fallback_available"] is True
    assert row["abstention_fallback_available"] is True
    assert row["null_route_preserved"] is True
    assert row["operator_override_ready"] is True
    assert row["kill_switch_status"] == "READY_NOT_INVOKED"
    assert row["rollback_status"] == "READY_NOT_INVOKED"
    assert row["trace_complete"] is True
    assert row["r6_opening_applied"] is True
    assert row["r6_open"] is True
    assert row["package_promotion_authorized"] is False


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
def test_r6_opening_receipts_pass(outputs: Path, role: str, field: str, expected: object) -> None:
    assert _payload(outputs, role)[field] == expected


@pytest.mark.parametrize("role", opening.PREP_ONLY_ROLES)
def test_downstream_artifacts_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


def test_no_authorization_drift_receipt_passes(outputs: Path) -> None:
    payload = _payload(outputs, "no_authorization_drift_receipt")
    assert payload["no_downstream_authorization_drift"] is True
    assert payload["package_promotion_authorized"] is False
    assert payload["commercial_activation_claim_authorized"] is False


def test_pipeline_board_marks_evidence_review_next(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")
    lanes = {row["lane"]: row["status"] for row in board["lanes"]}
    assert lanes["RUN_B04_R6_R6_OPENING"] == "CURRENT_EXECUTED"
    assert lanes[opening.NEXT_LAWFUL_MOVE] == "NEXT"
    assert board["claim_ceiling"] == "R6_OPENING_PASSED_ONLY__OPENING_EVIDENCE_REVIEW_NEXT"


def test_report_preserves_downstream_boundaries(outputs: Path) -> None:
    text = (outputs / opening.OUTPUTS["report"]).read_text(encoding="utf-8").lower()
    assert "r6 opening" in text
    assert "does not promote package" in text
    assert "does not authorize commercial activation claims" in text
    assert "does not mutate truth/trust law" in text


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_opening_env(monkeypatch, tmp_path, dirty=" M reports/x.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        opening.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_opening_env(monkeypatch, tmp_path, branch="feature/nope")
    with pytest.raises(opening.LaneFailure, match="NEXT_MOVE_DRIFT"):
        opening.run(reports_root=reports)


def test_validation_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_EXECUTION_PACKET_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
    _write(path, payload)
    _patch_opening_env(monkeypatch, tmp_path)
    with pytest.raises(opening.LaneFailure, match="VALIDATION_OUTCOME_DRIFT"):
        opening.run(reports_root=reports)


def test_validation_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_R6_OPENING_EVIDENCE_REVIEW_PACKET"
    _write(path, payload)
    _patch_opening_env(monkeypatch, tmp_path)
    with pytest.raises(opening.LaneFailure, match="NEXT_MOVE_DRIFT"):
        opening.run(reports_root=reports)


@pytest.mark.parametrize("field,reason", [("r6_opening_executed", "PRE_RUN_EXECUTION_DRIFT"), ("r6_open", "PRE_RUN_R6_OPEN_DRIFT")])
def test_pre_run_opening_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, reason: str
) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload[field] = True
    _write(path, payload)
    _patch_opening_env(monkeypatch, tmp_path)
    with pytest.raises(opening.LaneFailure, match=reason):
        opening.run(reports_root=reports)


def test_packet_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
    _write(path, payload)
    _patch_opening_env(monkeypatch, tmp_path)
    with pytest.raises(opening.LaneFailure, match="CONTROL_CONTRACT_MISSING|PACKET_HASH_DRIFT"):
        opening.run(reports_root=reports)


def test_scope_widening_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["scope_manifest"]
    payload = _load(path)
    payload["global_runtime_surface"] = True
    _write(path, payload)
    _patch_opening_env(monkeypatch, tmp_path)
    with pytest.raises(opening.LaneFailure, match="SCOPE_VIOLATION|GLOBAL_SURFACE_DRIFT|PACKET_HASH_DRIFT"):
        opening.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_validation_only(tmp_path, monkeypatch)
    _patch_opening_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        opening,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(opening.LaneFailure, match="TRUST_ZONE_FAILED"):
        opening.run(reports_root=reports)
