from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import kt_e2e_follow_up_audit_readiness_packet as packet
from tools.operator import kt_e2e_follow_up_audit_readiness_packet_validation as validation


VALIDATION_HEAD = "edededededededededededededededededededed"
REPLAY_BOUND_MAIN = "b482459e53eb410239e01075c568432db743cbc4"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_inputs(tmp_path: Path) -> Path:
    source_root = Path.cwd()
    reports = tmp_path / "KT_PROD_CLEANROOM/reports"
    reports.mkdir(parents=True, exist_ok=True)
    for raw in {**validation.PACKET_JSON_INPUTS, **validation.PACKET_TEXT_INPUTS}.values():
        source = source_root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = REPLAY_BOUND_MAIN,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    contract_path = tmp_path / "KT_PROD_CLEANROOM/reports" / packet.OUTPUTS["packet_contract"]
    fallback_hashes = {}
    if contract_path.exists():
        contract = _load(contract_path)
        fallback_hashes = {row["path"]: row["sha256"] for row in contract.get("input_bindings", [])}
    monkeypatch.setattr(validation, "_git_blob_hash", lambda root, commit, raw_path: fallback_hashes.get(raw_path))
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("kt_e2e_follow_up_audit_readiness_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _packet_payload(outputs: Path, role: str) -> dict:
    return _load(outputs / packet.OUTPUTS[role])


def _json_output_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "follow-up audit readiness is validated" in text
        assert "commercial activation claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_binds_replayed_follow_up_audit_packet(outputs: Path) -> None:
    contract = _payload(outputs, "validation_contract")
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == packet.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == packet.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == packet.NEXT_LAWFUL_MOVE
    assert contract["current_main_head"] == REPLAY_BOUND_MAIN
    assert contract["current_git_head"] == VALIDATION_HEAD
    assert contract["current_branch_head"] == VALIDATION_HEAD


def test_validation_reaches_final_reaudit_target(outputs: Path) -> None:
    assert _payload(outputs, "validation_contract")["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "validation_receipt")["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert _payload(outputs, "next_lawful_move")["ready_for_reaudit_or_external_review"] is True


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_passed", True),
        ("commercial_activation_executed", True),
        ("commercial_activation_passed", True),
        ("commercial_activation_evidence_review_validated", True),
        ("follow_up_audit_readiness_packet_authored", True),
        ("follow_up_audit_readiness_validated", True),
        ("ready_for_reaudit_or_external_review", True),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_validation_preserves_final_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _payload(outputs, "validation_contract")[flag] == expected


@pytest.mark.parametrize("role", sorted(validation.PACKET_JSON_INPUTS))
def test_validation_binds_all_packet_json_inputs(outputs: Path, role: str) -> None:
    value = _payload(outputs, "validation_contract")["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(validation.PACKET_TEXT_INPUTS))
def test_validation_binds_all_packet_text_inputs(outputs: Path, role: str) -> None:
    value = _payload(outputs, "validation_contract")["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_packet_source_bindings_are_recomputed(outputs: Path) -> None:
    packet_contract = _packet_payload(outputs, "packet_contract")
    for row in packet_contract["input_bindings"]:
        assert packet_contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_claim_ceiling_and_forbidden_claims_are_validated(outputs: Path) -> None:
    allowed = _packet_payload(outputs, "allowed_claims_current_state")["allowed_claims"]
    forbidden = _packet_payload(outputs, "forbidden_claims_current_state")["forbidden_claims"]
    assert "Commercial activation evidence review is validated." in allowed
    assert "Commercial activation claims are authorized." in forbidden
    assert _payload(outputs, "allowed_claims_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "forbidden_claims_validation")["validation_status"] == "PASS"


def test_audit_readiness_artifacts_are_validated(outputs: Path) -> None:
    assert _payload(outputs, "canonical_state_board_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "proof_replay_bundle_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "external_verifier_manifest_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "truth_trust_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "boundary_state_validation")["validation_status"] == "PASS"
    assert _payload(outputs, "open_blocker_validation")["validation_status"] == "PASS"


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_are_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_packet_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / validation.PACKET_JSON_INPUTS["packet_contract"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_KT_E2E_COMMERCIAL_CLAIM_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT"


def test_packet_input_binding_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / validation.PACKET_JSON_INPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code in {
        "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISSING",
        "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISMATCH",
    }


def test_preoverwrite_fallback_requires_replay_bound_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / validation.PACKET_JSON_INPUTS["packet_contract"]
    payload = _load(path)
    payload["current_branch_head"] = "f" * 40
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_VAL_INPUT_HASH_MISMATCH"


def test_claim_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / validation.PACKET_JSON_INPUTS["allowed_claims_current_state"]
    payload = _load(path)
    payload["allowed_claims"].append("Commercial activation claims authorized.")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_VAL_CLAIM_TOKEN_DRIFT"


def test_benchmark_prep_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / validation.PACKET_JSON_INPUTS["packet_contract"]
    payload = _load(path)
    payload["benchmark_prep_authorizes_commercial_activation"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_VAL_BENCHMARK_AUTHORITY_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_VAL_NEXT_MOVE_DRIFT"


def test_custom_reports_root_writes_report_and_cli_reads_selected_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    assert validation.main(["--reports-root", "custom_validation_reports"]) == 0
    captured = capsys.readouterr()
    custom_root = tmp_path / "custom_validation_reports"
    assert validation.SELECTED_OUTCOME in captured.out
    assert (custom_root / validation.OUTPUTS["validation_contract"]).exists()
    assert (custom_root / validation.OUTPUTS["validation_report"]).exists()
    assert not (tmp_path / "KT_PROD_CLEANROOM/reports" / validation.OUTPUTS["validation_report"]).exists()


@pytest.mark.parametrize("role", _json_output_roles())
def test_all_json_outputs_record_expected_heads(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["current_main_head"] == REPLAY_BOUND_MAIN
    assert payload["current_git_head"] == VALIDATION_HEAD
    assert payload["current_branch_head"] == VALIDATION_HEAD
