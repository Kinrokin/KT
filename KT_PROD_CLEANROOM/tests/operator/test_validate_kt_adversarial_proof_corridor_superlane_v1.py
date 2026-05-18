from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_adversarial_proof_corridor_superlane_v1 as corridor
from tools.operator import validate_kt_adversarial_proof_corridor_superlane_v1 as validator
from tools.operator.titanium_common import repo_root


VALIDATION_HEAD = "f" * 40
MAIN_HEAD = "1506ebbff9557f89999a7db149af192ecbfacd28"


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
    for raw in corridor.OUTPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    for raw in corridor.INPUTS.values():
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
    tmp_path = tmp_path_factory.mktemp("adversarial_proof_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / validator.OUTPUTS[role])


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
        assert "External audit completed: false" in path.read_text(encoding="utf-8")


def test_validation_selects_external_audit_ratification_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["selected_outcome"] == validator.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "AUTHOR_KT_EXTERNAL_AUDIT_AND_RATIFICATION_PACKET_SUPERLANE_V1"
    assert receipt["adversarial_proof_corridor_validated"] is True
    assert receipt["external_audit_ratification_packet_next"] is True
    assert receipt["external_audit_ratification_packet_authorized"] is False


def test_validation_preserves_boundaries(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "external_audit_ratification_gate_decision")
    assert decision["external_audit_ratification_packet_next"] is True
    assert decision["external_audit_ratification_packet_authorized"] is False
    assert decision["external_audit_completed"] is False
    assert decision["external_reaudit_accepted"] is False
    assert decision["commercial_activation_claim_authorized"] is False
    assert decision["seven_b_amplification_claimed_proven"] is False


def test_scorecard_all_pass(validation_outputs: Path) -> None:
    scorecard = _payload(validation_outputs, "validation_scorecard")
    assert scorecard["fail_count"] == 0
    assert all(row["status"] == "PASS" for row in scorecard["score_rows"])


def test_rejects_packet_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_OUTCOME_DRIFT"


def test_rejects_packet_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_NEXT_MOVE_DRIFT"


def test_rejects_bound_source_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_attack_execution_in_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["attack_matrix"]
    payload = _load(path)
    payload["attack_execution_performed"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY"


def test_rejects_missing_attack_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["attack_matrix"]
    payload = _load(path)
    payload["attack_rows"] = payload["attack_rows"][:-1]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_ATTACK_MATRIX_INCOMPLETE"


def test_rejects_external_audit_completion_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["claim_boundary_receipt"]
    payload = _load(path)
    payload["external_audit_completed"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_PREMATURE_AUTHORITY"


def test_rejects_external_reaudit_accepted_claim_in_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["packet_report"]
    path.write_text(path.read_text(encoding="utf-8") + "\nExternal reaudit is accepted.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_duplicate_reason_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"].append(payload["reason_codes"][0])
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_REASON_CODE_DUPLICATE"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_VAL_TRUST_ZONE_FAILED"
