from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_supply_chain_release_corridor_superlane_v1 as corridor


AUTHOR_HEAD = "e" * 40
MAIN_HEAD = "d03d5c2a7cfe36228d0ab08d36139269c5c759d8"


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
    for raw in corridor.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = corridor.AUTHOR_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(corridor, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(corridor.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(corridor.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(corridor.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        corridor,
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
    corridor.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def corridor_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("supply_chain_release_corridor")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / corridor.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(corridor.REASON_CODES) == len(set(corridor.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(corridor.OUTPUTS.values()))
def test_outputs_exist(corridor_outputs: Path, raw: str) -> None:
    path = corridor_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        if raw.endswith("spdx_sbom.json"):
            assert payload["spdxVersion"] == "SPDX-2.3"
        else:
            assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "Release execution authorized: false" in text


def test_corridor_selects_validation_next(corridor_outputs: Path) -> None:
    receipt = _payload(corridor_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == corridor.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "VALIDATE_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"
    assert receipt["supply_chain_release_corridor_packet_authored"] is True
    assert receipt["supply_chain_release_corridor_validated"] is False


def test_corridor_preserves_claim_boundary(corridor_outputs: Path) -> None:
    receipt = _payload(corridor_outputs, "packet_receipt")
    assert receipt["release_execution_authorized"] is False
    assert receipt["release_executed"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False
    assert receipt["beyond_sota_claimed"] is False
    assert receipt["claim_compiler_authorized"] is False


def test_artifact_manifest_binds_supply_chain_evidence(corridor_outputs: Path) -> None:
    manifest = _payload(corridor_outputs, "artifact_manifest")
    paths = {row["path"] for row in manifest["artifacts"]}
    assert "KT_PROD_CLEANROOM/reports/kt_slsa_provenance_receipt.json" in paths
    assert "KT_PROD_CLEANROOM/reports/kt_rekor_inclusion_receipt.json" in paths
    assert "KT_PROD_CLEANROOM/reports/sbom_cyclonedx.json" in paths


def test_spdx_and_tuf_artifacts_are_authored_without_execution(corridor_outputs: Path) -> None:
    spdx = _payload(corridor_outputs, "spdx_sbom")
    tuf = _payload(corridor_outputs, "tuf_metadata_set")
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["external_audit_completed"] is False
    assert tuf["metadata_mode"] == "PRE_RELEASE_CORRIDOR_AUTHORING_ONLY"
    assert set(tuf) >= {"root", "targets", "snapshot", "timestamp"}
    assert tuf["release_execution_authorized"] is False


def test_committed_packet_artifacts_share_generation_timestamp() -> None:
    source_root = Path.cwd()
    contract = _load(source_root / corridor.OUTPUTS["packet_contract"])
    expected_generated_utc = contract["generated_utc"]
    mismatches = []
    for role, raw in corridor.OUTPUTS.items():
        if raw.endswith(".json"):
            payload = _load(source_root / raw)
            if role == "tuf_metadata_set":
                assert payload.get("generated_utc") == expected_generated_utc
            if "generated_utc" in payload and payload.get("generated_utc") != expected_generated_utc:
                mismatches.append((role, raw, payload.get("generated_utc")))
    assert mismatches == []


def test_attack_matrix_contains_required_negative_scenarios(corridor_outputs: Path) -> None:
    matrix = _payload(corridor_outputs, "attack_test_matrix")
    scenarios = {row["scenario_id"] for row in matrix["attack_scenarios"]}
    assert {"artifact_swap_test", "tuf_rollback_test", "tuf_freeze_test", "expired_metadata_test", "missing_sbom_test"} <= scenarios


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.PREDECESSOR_INPUTS["h01_validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_missing_supply_chain_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    (tmp_path / corridor.SUPPLY_CHAIN_INPUTS["rekor_inclusion_receipt"]).unlink()
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_MISSING"


def test_rejects_failed_supply_chain_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SUPPLY_CHAIN_INPUTS["slsa_provenance_receipt"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED"


def test_rejects_missing_cyclonedx_sbom_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SUPPLY_CHAIN_INPUTS["cyclonedx_sbom"]
    payload = _load(path)
    payload["bomFormat"] = "NotCycloneDX"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID"


def test_rejects_missing_cyclonedx_components_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SUPPLY_CHAIN_INPUTS["cyclonedx_sbom"]
    payload = _load(path)
    payload.pop("components", None)
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SBOM_INVALID"


def test_rejects_failed_in_toto_layout_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SUPPLY_CHAIN_INPUTS["in_toto_layout"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED"


def test_rejects_failed_build_provenance_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SUPPLY_CHAIN_INPUTS["build_provenance_dsse"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_ARTIFACT_STATUS_FAILED"


def test_rejects_external_audit_claim_in_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.PREDECESSOR_INPUTS["h01_validation_receipt"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is complete and commercial activation is not authorized."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_CLAIM_BOUNDARY_BREACH"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_BRANCH_DRIFT"
