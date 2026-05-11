from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_r6_opening_execution_packet as packet
from tools.operator import cohort0_b04_r6_r6_opening_execution_packet_validation as validation
from tools.operator.titanium_common import file_sha256


VALIDATION_HEAD = "7777777777777777777777777777777777777777"
VALIDATION_MAIN_HEAD = "c74481582d9332e08583ed12bde0def7e04970fb"


def _load_packet_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_r6_opening_execution_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_r6_opening_execution_packet_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load R6 opening execution packet helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packet_helpers = _load_packet_helpers()


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
    refs = {"HEAD": head, "origin/main": origin_main}

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        contract_path = root / "KT_PROD_CLEANROOM/reports" / packet.OUTPUTS["packet_contract"]
        contract = _load(contract_path)
        for row in contract["input_bindings"]:
            if row["path"] == raw and row.get("binding_kind") == "git_object_before_overwrite":
                return row["sha256"]
        return file_sha256(validation.common.resolve_path(root, raw))

    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(validation, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_packet_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return packet_helpers._run_exec_packet(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_packet_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("r6_opening_execution_packet_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "validation_receipt")


def _next(outputs: Path) -> dict:
    return _payload(outputs, "next_lawful_move")


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


GUARD_FALSE_FIELDS = [
    "r6_opening_authorized",
    "r6_opening_executed",
    "r6_open",
    "global_runtime_surface_authorized",
    "lobe_escalation_authorized",
    "package_promotion_authorized",
    "commercial_activation_claim_authorized",
    "truth_engine_law_changed",
    "trust_zone_law_changed",
    "metric_contract_mutated",
    "static_comparator_weakened",
]


PREP_ONLY_GUARDS = [
    "cannot_execute_r6_opening",
    "cannot_open_r6",
    "cannot_authorize_lobe_escalation",
    "cannot_authorize_package_promotion",
    "cannot_authorize_commercial_activation_claims",
    "cannot_mutate_truth_engine_law",
    "cannot_mutate_trust_zone_law",
    "cannot_authorize_global_runtime_surface",
]


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_r6_opening_execution_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert "does not execute r6 opening" in path.read_text(encoding="utf-8").lower()
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_selects_r6_opening_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _next(outputs)["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD
    assert _contract(outputs)["current_git_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_execution_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["previous_authoritative_lane"] == packet.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == packet.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == packet.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


@pytest.mark.parametrize("role", sorted(validation.PACKET_JSON_INPUTS))
def test_validation_binds_all_packet_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.PACKET_TEXT_INPUTS))
def test_validation_binds_all_packet_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role, raw", sorted(validation.PACKET_JSON_INPUTS.items()))
def test_validation_binding_hashes_match_on_disk_packet_json_inputs(outputs: Path, role: str, raw: str) -> None:
    expected = file_sha256(outputs.parent.parent / raw)
    assert _contract(outputs)["binding_hashes"][f"{role}_hash"] == expected


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["validation_status"] == "PASS"
    assert len(payload["validated_hash"]) == 64


def test_validation_marks_packet_validated_but_no_r6_opening_execution(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["r6_opening_execution_packet_authored"] is True
    assert contract["r6_opening_execution_packet_validated"] is True
    assert contract["r6_opening_authorized"] is False
    assert contract["r6_opening_executed"] is False
    assert contract["r6_open"] is False


@pytest.mark.parametrize("role", _json_output_roles())
@pytest.mark.parametrize("flag", GUARD_FALSE_FIELDS)
def test_all_json_outputs_keep_hard_negative_flags(outputs: Path, role: str, flag: str) -> None:
    assert _payload(outputs, role)[flag] is False


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
@pytest.mark.parametrize("guard", PREP_ONLY_GUARDS)
def test_validation_prep_only_outputs_keep_guards(outputs: Path, role: str, guard: str) -> None:
    assert _payload(outputs, role)[guard] is True


def test_no_authorization_drift_validation_passes(outputs: Path) -> None:
    payload = _payload(outputs, "no_authorization_drift_validation")
    assert payload["validation_status"] == "PASS"
    assert payload["drift_detected"] is False


def test_validation_report_preserves_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "does not execute r6 opening" in text
    assert "does not open r6" in text
    assert "does not promote package" in text
    assert "commercial activation claims" in text


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M reports/x.json")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/nope")
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_missing_execution_packet_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    (reports / packet.OUTPUTS["packet_contract"]).unlink()
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="packet_contract"):
        validation.run(reports_root=reports)


def test_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "B04_R6_R6_OPENING_EXECUTION_PACKET_DEFERRED__NAMED_PACKET_DEFECT_REMAINS"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_packet_lane_identity_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["authoritative_lane"] = "B04_R6_UNRELATED_PACKET"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_MISSING"):
        validation.run(reports_root=reports)


def test_packet_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "RUN_B04_R6_R6_OPENING"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_empty_input_bindings_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"] = []
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="INPUT_BINDINGS_EMPTY"):
        validation.run(reports_root=reports)


def test_packet_input_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    row = next(item for item in payload["input_bindings"] if item["binding_kind"].startswith("file_sha256"))
    row["sha256"] = "0" * 64
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="INPUT_HASH_DRIFT"):
        validation.run(reports_root=reports)


def test_git_object_binding_commit_must_match_packet_main_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    row = next(item for item in payload["input_bindings"] if item["binding_kind"] == "git_object_before_overwrite")
    row["git_commit"] = "1" * 40
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="INPUT_HASH_DRIFT"):
        validation.run(reports_root=reports)


def test_input_already_claims_validation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["r6_opening_execution_packet_validated"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_missing_control_contract_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["kill_switch_contract"]
    payload = _load(path)
    payload["control_status"] = "MISSING"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CONTROL_CONTRACT_MISSING"):
        validation.run(reports_root=reports)


def test_missing_expected_execution_contract_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["expected_artifact_manifest"]
    payload = _load(path)
    payload["expected_artifacts"].remove("b04_r6_r6_opening_execution_contract.json")
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CONTROL_CONTRACT_MISSING"):
        validation.run(reports_root=reports)


def test_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["r6_opening_run_result_schema_prep_only"]
    payload = _load(path)
    payload["authority"] = "AUTHORITY"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PREP_ONLY_DRIFT"):
        validation.run(reports_root=reports)


@pytest.mark.parametrize(
    "field, value, reason",
    [
        ("r6_opening_authorized", True, "AUTHORIZATION_DRIFT"),
        ("r6_opening_executed", True, "EXECUTION_DRIFT"),
        ("r6_open", True, "R6_OPEN_DRIFT"),
        ("package_promotion_authorized", True, "PACKAGE_PROMOTION_DRIFT"),
        ("commercial_activation_claim_authorized", True, "COMMERCIAL_CLAIM_DRIFT"),
        ("global_runtime_surface_authorized", True, "GLOBAL_SURFACE_DRIFT"),
    ],
)
def test_authority_drift_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object, reason: str
) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload[field] = value
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match=reason):
        validation.run(reports_root=reports)


def test_claim_bearing_authorized_token_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["commercial_claim_boundary"]
    payload = _load(path)
    payload["commercial_claim_state"] = "AUTHORIZED"
    payload["commercial_activation_claim_authorized"] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)


@pytest.mark.parametrize("token, reason", [("R6_OPEN", "R6_OPEN_DRIFT"), ("PACKAGE_PROMOTION_AUTHORIZED", "PACKAGE_PROMOTION_DRIFT")])
def test_text_artifact_forbidden_claim_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str, reason: str
) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    path = reports / packet.OUTPUTS["packet_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + f"\n{token}\n", encoding="utf-8")
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match=reason):
        validation.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_packet_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(validation.LaneFailure, match="TRUST_ZONE_FAILED"):
        validation.run(reports_root=reports)
