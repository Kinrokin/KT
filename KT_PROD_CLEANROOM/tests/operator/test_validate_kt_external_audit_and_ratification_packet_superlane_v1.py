from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_external_audit_and_ratification_packet_superlane_v1 as packet
from tools.operator import validate_kt_external_audit_and_ratification_packet_superlane_v1 as validator
from tools.operator.titanium_common import repo_root


VALIDATION_HEAD = "b" * 40
MAIN_HEAD = "3fc29eeda491fd9356b41725189723d1336de3c9"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_file(source_root: Path, tmp_path: Path, raw: str) -> None:
    source = source_root / raw
    if source.is_file():
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _copy_inputs(tmp_path: Path) -> None:
    source_root = repo_root()
    for raw in packet.OUTPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    for raw in packet.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validator.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(validator, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validator.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validator.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validator.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        validator,
        "validate_trust_zones",
        lambda *, root: {
            "schema_id": "trust",
            "status": trust_status,
            "failures": [] if trust_status == "PASS" else ["forced failure"],
            "checks": [{"status": trust_status}],
        },
    )


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    validator.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def validation_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("external_audit_ratification_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / validator.OUTPUTS[role])


def _drop_packet_binding_role(root: Path, role_to_drop: str) -> None:
    for raw in validator.PACKET_JSON_OUTPUTS.values():
        path = root / raw
        payload = _load(path)
        payload["input_bindings"] = [row for row in payload["input_bindings"] if row["role"] != role_to_drop]
        payload["binding_hashes"].pop(f"{role_to_drop}_hash", None)
        _write(path, payload)


def test_reason_codes_are_unique() -> None:
    assert len(validator.REASON_CODES) == len(set(validator.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(validator.OUTPUTS.values()))
def test_outputs_exist(validation_outputs: Path, raw: str) -> None:
    path = validation_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "External reaudit attempt executed: false" in text
        assert "External audit completed: false" in text


def test_validation_selects_external_reaudit_attempt_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["selected_outcome"] == validator.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == validator.NEXT_LAWFUL_MOVE
    assert receipt["external_audit_and_ratification_packet_validated"] is True
    assert receipt["external_reaudit_attempt_next"] is True
    assert receipt["external_reaudit_attempt_executed"] is False


def test_validation_preserves_boundaries(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "external_reaudit_attempt_gate_decision")
    assert decision["external_reaudit_attempt_next"] is True
    assert decision["external_reaudit_attempt_authorized"] is False
    assert decision["external_reaudit_attempt_executed"] is False
    assert decision["external_reaudit_accepted"] is False
    assert decision["external_audit_completed"] is False
    assert decision["commercial_activation_claim_authorized"] is False


def test_scorecard_all_pass(validation_outputs: Path) -> None:
    scorecard = _payload(validation_outputs, "validation_scorecard")
    assert scorecard["fail_count"] == 0
    assert all(row["status"] == "PASS" for row in scorecard["score_rows"])


def test_rejects_packet_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_OUTCOME_DRIFT"


def test_rejects_packet_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_NEXT_MOVE_DRIFT"


def test_rejects_bound_source_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.INPUTS["detached_verifier_clean_room_replay_result"]
    payload = _load(path)
    payload["clean_room_replay_passed"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_packet_input_binding_role_set_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _drop_packet_binding_role(tmp_path, "external_audit_packet_manifest")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_INPUT_BINDING_ROLE_SET_DRIFT"


def test_rejects_external_audit_completion_in_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["claim_boundary_receipt"]
    payload = _load(path)
    payload["external_audit_completed"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_PREMATURE_AUTHORITY"


def test_rejects_external_reaudit_acceptance_in_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["ratification_decision_matrix"]
    payload = _load(path)
    payload["external_reaudit_accepted"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_PREMATURE_AUTHORITY"


def test_rejects_selected_external_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["ratification_decision_matrix"]
    payload = _load(path)
    payload["decision_rows"][0]["selected_now"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_PREMATURE_AUTHORITY"


def test_rejects_missing_expected_validation_outcome_from_allowed_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["validation_plan"]
    payload = _load(path)
    payload["allowed_external_reaudit_outcomes"] = list(packet.DECISION_OUTCOMES)
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_DECISION_MATRIX_INVALID"


def test_rejects_incomplete_audit_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["audit_scope_manifest"]
    payload = _load(path)
    payload["scope_rows"] = [row for row in payload["scope_rows"] if row["scope_id"] != "supply_chain_release_integrity"]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_SCOPE_INCOMPLETE"


def test_rejects_external_audit_completion_claim_in_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_report"]
    path.write_text(path.read_text(encoding="utf-8") + "\nExternal audit is complete.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_duplicate_reason_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"].append(payload["reason_codes"][0])
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_REASON_CODE_DUPLICATE"


def test_rejects_reason_code_catalog_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"] = list(packet.REASON_CODES[:-1]) + ["RC_KT_EXTERNAL_AUDIT_RATIFICATION_FAKE"]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_REASON_CODE_CATALOG_DRIFT"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_VAL_TRUST_ZONE_FAILED"
