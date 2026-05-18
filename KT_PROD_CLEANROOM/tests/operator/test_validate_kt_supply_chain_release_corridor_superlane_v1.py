from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_supply_chain_release_corridor_superlane_v1 as packet
from tools.operator import validate_kt_supply_chain_release_corridor_superlane_v1 as validation
from tools.operator.titanium_common import file_sha256


AUTHOR_HEAD = "e" * 40
MAIN_HEAD = "da78c86e8cac1652cf56388699b29ebcf15c4fb9"


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


def _rebind_input_hash(tmp_path: Path, role: str) -> None:
    raw = packet.INPUTS[role]
    digest = file_sha256(tmp_path / raw)
    for output_raw in validation.JSON_PACKET_OUTPUTS.values():
        path = tmp_path / output_raw
        payload = _load(path)
        if isinstance(payload.get("input_bindings"), list):
            for row in payload["input_bindings"]:
                if row.get("role") == role:
                    row["sha256"] = digest
            if isinstance(payload.get("binding_hashes"), dict):
                payload["binding_hashes"][f"{role}_hash"] = digest
        if output_raw == packet.OUTPUTS["spdx_sbom"]:
            for package_row in payload.get("packages", []):
                if package_row.get("name") == raw:
                    package_row["checksums"][0]["checksumValue"] = digest
        if output_raw == packet.OUTPUTS["tuf_metadata_set"]:
            for target in payload.get("targets", {}).get("targets", []):
                if target.get("path") == raw:
                    target["sha256"] = digest
        _write(path, payload)


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
    tmp_path = tmp_path_factory.mktemp("supply_chain_release_corridor_validation")
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


def test_validation_selects_claim_compiler_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert receipt["claim_compiler_commercial_language_gate_next"] is True
    assert receipt["claim_compiler_authorized"] is False


def test_validation_recomputes_bound_source_hashes(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["source_hashes_recomputed"] is True
    assert receipt["binding_hashes"]
    assert len(receipt["input_bindings"]) == len(packet.INPUTS)


def test_validation_preserves_authority_boundaries(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["release_execution_authorized"] is False
    assert receipt["release_executed"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False
    assert receipt["beyond_sota_claimed"] is False


def test_rejects_packet_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_OUTCOME_DRIFT"


def test_rejects_source_hash_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_non_contract_artifact_input_binding_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["input_bindings"][0]["sha256"] = "1" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_changed_bound_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    source = tmp_path / packet.INPUTS["rekor_inclusion_receipt"]
    source.write_text(source.read_text(encoding="utf-8") + "\nmutated\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_missing_cyclonedx_components_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.SUPPLY_CHAIN_INPUTS["cyclonedx_sbom"]
    payload = _load(path)
    payload.pop("components", None)
    _write(path, payload)
    _rebind_input_hash(tmp_path, "cyclonedx_sbom")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_SBOM_INVALID"


def test_rejects_failed_build_provenance_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.SUPPLY_CHAIN_INPUTS["build_provenance_dsse"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _rebind_input_hash(tmp_path, "build_provenance_dsse")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_STATUS_FAILED"


def test_rejects_failed_in_toto_layout_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.SUPPLY_CHAIN_INPUTS["in_toto_layout"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _rebind_input_hash(tmp_path, "in_toto_layout")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ARTIFACT_STATUS_FAILED"


def test_rejects_tuf_generated_timestamp_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["tuf_metadata_set"]
    payload = _load(path)
    payload["generated_utc"] = "2000-01-01T00:00:00Z"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID"


def test_rejects_tuf_target_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["tuf_metadata_set"]
    payload = _load(path)
    payload["targets"]["targets"][0]["sha256"] = "0" * 64
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_TUF_METADATA_INVALID"


def test_rejects_missing_attack_matrix_scenario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["attack_test_matrix"]
    payload = _load(path)
    payload["attack_scenarios"] = payload["attack_scenarios"][:1]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_ATTACK_MATRIX_INCOMPLETE"


def test_rejects_duplicate_packet_reason_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"].append(payload["reason_codes"][0])
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_REASON_CODE_DUPLICATE"


def test_rejects_positive_commercial_claim_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is complete and commercial activation is not authorized."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_release_execution_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / packet.OUTPUTS["release_integrity_receipt"]
    payload = _load(path)
    payload["release_execution_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_PREMATURE_AUTHORITY"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/not-this-lane")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_validation_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_VAL_BRANCH_DRIFT"
