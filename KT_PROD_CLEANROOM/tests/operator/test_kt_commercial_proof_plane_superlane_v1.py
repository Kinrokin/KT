from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_commercial_proof_plane_superlane_v1 as plane
from tools.operator import validate_kt_claim_compiler_commercial_language_gate_superlane_v1 as predecessor


AUTHOR_HEAD = "c" * 40
MAIN_HEAD = "3f367e99c969fb039a4041060da8c53e189353a5"


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
    for raw in plane.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = plane.AUTHOR_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(plane, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(plane.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(plane.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(plane.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        plane,
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
    plane.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def authored_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("commercial_proof_plane")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / plane.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(plane.REASON_CODES) == len(set(plane.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(plane.OUTPUTS.values()))
def test_outputs_exist(authored_outputs: Path, raw: str) -> None:
    path = authored_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "Documentary-only commercial proof surface." in text
        assert "Commercial activation claims authorized: false" in text


def test_authoring_selects_validation_next(authored_outputs: Path) -> None:
    receipt = _payload(authored_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == plane.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == plane.NEXT_LAWFUL_MOVE
    assert receipt["commercial_proof_plane_packet_authored"] is True
    assert receipt["commercial_proof_plane_validated"] is False


def test_claim_boundaries_preserved(authored_outputs: Path) -> None:
    boundary = _payload(authored_outputs, "claim_boundary_receipt")
    assert boundary["no_claim_expansion"] is True
    assert boundary["commercial_activation_claim_authorized"] is False
    assert boundary["external_audit_completed"] is False
    assert boundary["seven_b_amplification_claimed_proven"] is False
    assert boundary["fp0_or_highway_promoted_to_authority"] is False


def test_deliverables_are_declared(authored_outputs: Path) -> None:
    manifest = _payload(authored_outputs, "evidence_pack_manifest")
    contract = _payload(authored_outputs, "packet_contract")
    assert manifest["evidence_pack_authorizes_commercial_activation_claims"] is False
    assert plane.OUTPUTS["quickstart"] in contract["deliverables"]
    assert plane.OUTPUTS["customer_safe_language"] in contract["deliverables"]


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_predecessor_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_PREDECESSOR_NEXT_MOVE_DRIFT"


def test_rejects_commercial_activation_allowed_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / plane.SOURCE_INPUTS["h03_allowed_claims"]
    payload = _load(path)
    payload["allowed_claims"].append("Commercial activation claims are authorized.")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH"


def test_rejects_external_audit_claim_in_source_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / plane.SOURCE_INPUTS["product_operator_runbook"]
    path.write_text(path.read_text(encoding="utf-8") + "\nExternal audit is complete.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_CLAIM_BOUNDARY_BREACH"


def test_rejects_premature_commercial_proof_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["commercial_proof_plane_gate_decision"]
    payload = _load(path)
    payload["commercial_proof_plane_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_PREMATURE_AUTHORITY"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(plane.LaneFailure) as excinfo:
        plane.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_COMMERCIAL_PROOF_PLANE_TRUST_ZONE_FAILED"
