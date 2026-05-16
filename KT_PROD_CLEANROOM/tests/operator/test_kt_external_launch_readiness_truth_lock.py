from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import kt_external_launch_readiness_truth_lock as packet
from tools.operator import kt_external_launch_readiness_truth_lock_validation as validation


AUTHOR_HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VALIDATION_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MAIN_HEAD = "2591d6f1d3401778b6d0f2fdcdc52b0c6dea1af6"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_inputs(tmp_path: Path) -> None:
    source_root = Path.cwd()
    for raw in packet.INPUTS.values():
        source = source_root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _patch_packet_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = packet.AUTHORITY_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(packet.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(packet.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(packet.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        packet,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_packet_env(monkeypatch, tmp_path)
    packet.run(output_root=tmp_path)
    return tmp_path


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def packet_outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("truth_lock_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_packet(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


@pytest.fixture(scope="module")
def validation_outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("truth_lock_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        _run_packet(tmp_path, monkeypatch)
        monkeypatch.undo()
        monkeypatch = pytest.MonkeyPatch()
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _json_payload(root: Path, role: str) -> dict:
    return _load(root / packet.JSON_OUTPUTS[role])


def _validation_payload(root: Path, role: str) -> dict:
    return _load(root / validation.OUTPUTS[role])


def test_packet_reason_codes_are_unique() -> None:
    assert len(packet.REASON_CODES) == len(set(packet.REASON_CODES))


def test_validation_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(packet.OUTPUTS.values()))
def test_truth_lock_required_outputs_exist(packet_outputs: Path, raw: str) -> None:
    path = packet_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "commercial activation" in text.lower() or "claim" in text.lower() or "audit" in text.lower()


def test_current_truth_head_preserves_canonical_truth(packet_outputs: Path) -> None:
    head = _json_payload(packet_outputs, "current_truth_head")
    assert head["selected_outcome"] == packet.SELECTED_OUTCOME
    assert head["next_lawful_move"] == packet.NEXT_LAWFUL_MOVE
    assert head["predecessor_outcome"] == packet.EXPECTED_PREVIOUS_OUTCOME
    assert head["ready_for_reaudit_or_external_review"] is True
    assert head["commercial_activation_claim_authorized"] is False
    assert head["external_audit_completed"] is False
    assert head["seven_b_amplification_claimed_proven"] is False
    assert head["truth_engine_law_unchanged"] is True
    assert head["trust_zone_law_unchanged"] is True


def test_truth_lock_external_claims_are_bounded(packet_outputs: Path) -> None:
    head = _json_payload(packet_outputs, "current_truth_head")
    truth = head["current_truth"]
    assert "KT is ready for re-audit or external review." in truth["allowed_claims"]
    assert "Commercial activation claims are authorized." in truth["forbidden_claims"]
    one_page = (packet_outputs / packet.TEXT_OUTPUTS["kt_current_state_one_page"]).read_text(encoding="utf-8")
    assert "Commercial activation claims are not authorized." in one_page
    assert "7B amplification is not proven." in one_page


def test_claim_authority_matrix_blocks_overclaims(packet_outputs: Path) -> None:
    text = (packet_outputs / packet.TEXT_OUTPUTS["claim_authority_matrix"]).read_text(encoding="utf-8")
    assert "commercial_activation_claims_authorized: FORBIDDEN_REQUIRES_SEPARATE_CLAIM_AUTHORITY" in text
    assert "seven_b_amplification_proven: FORBIDDEN_NOT_PROVEN" in text
    assert "external_audit_complete: FORBIDDEN_NOT_YET_RUN" in text


def test_hard_refusal_tokens_cover_launch_overclaims(packet_outputs: Path) -> None:
    text = (packet_outputs / packet.TEXT_OUTPUTS["hard_refusal_tokens"]).read_text(encoding="utf-8")
    assert "commercial activation claims authorized" in text
    assert "7B amplification proven" in text
    assert "external audit complete" in text
    assert "beyond-SOTA" in text


def test_artifact_authority_classification_demotes_history(packet_outputs: Path) -> None:
    payload = _json_payload(packet_outputs, "artifact_authority_classification")
    assert payload["classifications"]["KT_PROD_CLEANROOM/reports"] == "SOURCE_EVIDENCE_AND_HISTORICAL_PROOF"
    assert payload["classifications"]["benchmark/provider/7B prep"] == "PREP_ONLY"


def test_packet_records_expected_heads(packet_outputs: Path) -> None:
    head = _json_payload(packet_outputs, "current_truth_head")
    assert head["current_git_head"] == AUTHOR_HEAD
    assert head["current_branch_head"] == AUTHOR_HEAD
    assert head["current_main_head"] == MAIN_HEAD


def test_packet_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.INPUTS["follow_up_audit_validation_contract"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_packet_env(monkeypatch, tmp_path)
    with pytest.raises(packet.LaneFailure) as excinfo:
        packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_TRUTH_LOCK_COMMERCIAL_CLAIM_DRIFT"


def test_packet_previous_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.INPUTS["follow_up_audit_validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "KT_E2E_FOLLOW_UP_AUDIT_READINESS_VALIDATED__COMMERCIAL_CLAIM_AUTHORIZATION_PACKET_NEXT"
    _write(path, payload)
    _patch_packet_env(monkeypatch, tmp_path)
    with pytest.raises(packet.LaneFailure) as excinfo:
        packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_TRUTH_LOCK_PREVIOUS_OUTCOME_DRIFT"


@pytest.mark.parametrize("raw", sorted(validation.OUTPUTS.values()))
def test_validation_outputs_exist(validation_outputs: Path, raw: str) -> None:
    path = validation_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Truth Lock is validated" in path.read_text(encoding="utf-8")


def test_validation_reaches_detached_verifier_next(validation_outputs: Path) -> None:
    contract = _validation_payload(validation_outputs, "validation_contract")
    assert contract["selected_outcome"] == validation.SELECTED_OUTCOME
    assert contract["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert contract["truth_lock_validated"] is True
    assert contract["commercial_activation_claim_authorized"] is False
    assert contract["seven_b_amplification_claimed_proven"] is False


def test_validation_binds_all_truth_lock_outputs(validation_outputs: Path) -> None:
    contract = _validation_payload(validation_outputs, "validation_contract")
    roles = {row["role"] for row in contract["artifact_bindings"]}
    assert set(packet.OUTPUTS) <= roles
    for row in contract["artifact_bindings"]:
        assert len(row["sha256"]) == 64


def test_validation_source_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _run_packet(tmp_path, monkeypatch)
    monkeypatch.undo()
    path = tmp_path / packet.INPUTS["known_limitations_ledger"]
    payload = _load(path)
    payload["tamper"] = "changed after Truth Lock authoring"
    _write(path, payload)
    monkeypatch = pytest.MonkeyPatch()
    _patch_validation_env(monkeypatch, tmp_path)
    try:
        with pytest.raises(validation.LaneFailure) as excinfo:
            validation.run(output_root=tmp_path)
        assert excinfo.value.code == "RC_KT_TRUTH_LOCK_VAL_SOURCE_HASH_MISMATCH"
    finally:
        monkeypatch.undo()


def test_validation_claim_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _run_packet(tmp_path, monkeypatch)
    monkeypatch.undo()
    text_path = tmp_path / packet.TEXT_OUTPUTS["reviewer_readme"]
    text_path.write_text("Commercial activation claims are authorized.\n", encoding="utf-8")
    monkeypatch = pytest.MonkeyPatch()
    _patch_validation_env(monkeypatch, tmp_path)
    try:
        with pytest.raises(validation.LaneFailure) as excinfo:
            validation.run(output_root=tmp_path)
        assert excinfo.value.code == "RC_KT_TRUTH_LOCK_VAL_CLAIM_TOKEN_DRIFT"
    finally:
        monkeypatch.undo()
