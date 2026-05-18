from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as packet
from tools.operator import validate_kt_detached_verifier_clean_room_replay_evidence_review_packet as validation


AUTHOR_HEAD = "e" * 40
MAIN_HEAD = "972c1c0054b3ca781083c72048be9d1c6e0d65f7"


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
    source_root = Path.cwd()
    for raw in validation.JSON_PACKET_OUTPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    for raw in packet.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        validation,
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
    validation.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def validation_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_clean_room_replay_evidence_review_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / validation.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(validation.OUTPUTS.values()))
def test_validation_outputs_exist(validation_outputs: Path, raw: str) -> None:
    path = validation_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Validation verdict" in path.read_text(encoding="utf-8")


def test_validation_selects_supply_chain_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert receipt["supply_chain_release_corridor_next"] is True
    assert receipt["supply_chain_release_corridor_authorized"] is False


def test_validation_recomputes_bound_source_hashes(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["source_hashes_recomputed"] is True
    assert receipt["binding_hashes"]
    assert len(receipt["input_bindings"]) == len(packet.INPUTS)


def test_rejects_packet_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_OUTCOME_DRIFT"


def test_rejects_source_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_non_contract_artifact_input_binding_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "1" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_changed_bound_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    source = tmp_path / packet.INPUTS["execution_report"]
    source.write_text(source.read_text(encoding="utf-8") + "\nmutated\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_failed_evidence_scorecard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["scorecard"]["overall_grade"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SCORECARD_FAILED"


def test_rejects_positive_claim_with_nearby_negative_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is complete and commercial activation is not authorized."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_nested_authority_drift_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["external_audit_completed"] = {"value": False}
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_supply_chain_premature_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["supply_chain_readiness_matrix"]
    payload = _load(path)
    payload["authorized_now"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_SUPPLY_CHAIN_PREMATURE_AUTHORITY"


def test_rejects_duplicate_packet_reason_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"].append(payload["reason_codes"][0])
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_REASON_CODE_DUPLICATE"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/not-this-lane")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_validation_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_VAL_BRANCH_DRIFT"
