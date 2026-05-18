from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_adversarial_proof_corridor_superlane_v1 as corridor
from tools.operator import validate_kt_commercial_proof_plane_superlane_v1 as predecessor
from tools.operator.titanium_common import repo_root


AUTHOR_HEAD = "e" * 40
MAIN_HEAD = "339d0d5bc670553dafad062dac0dd636ecb0cfeb"


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
def authored_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("adversarial_proof_corridor")
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
def test_outputs_exist(authored_outputs: Path, raw: str) -> None:
    path = authored_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "Adversarial attacks executed: false" in text
        assert "Commercial activation claims authorized: false" in text


def test_authoring_selects_validation_next(authored_outputs: Path) -> None:
    receipt = _payload(authored_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == corridor.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == corridor.NEXT_LAWFUL_MOVE
    assert receipt["adversarial_proof_corridor_packet_authored"] is True
    assert receipt["adversarial_proof_corridor_validated"] is False
    assert receipt["adversarial_attacks_executed"] is False


def test_attack_matrix_covers_required_classes(authored_outputs: Path) -> None:
    matrix = _payload(authored_outputs, "attack_matrix")
    rows = matrix["attack_rows"]
    assert len(rows) == len(corridor.ATTACK_CLASSES)
    assert {row["attack_class"] for row in rows} == set(corridor.ATTACK_CLASSES)
    assert all(row["status"] == "PLANNED_NOT_EXECUTED" for row in rows)


def test_claim_boundaries_preserved(authored_outputs: Path) -> None:
    boundary = _payload(authored_outputs, "claim_boundary_receipt")
    assert boundary["no_claim_expansion"] is True
    assert boundary["commercial_activation_claim_authorized"] is False
    assert boundary["external_audit_completed"] is False
    assert boundary["seven_b_amplification_claimed_proven"] is False
    assert boundary["fp0_or_highway_promoted_to_authority"] is False


def test_deliverables_are_declared(authored_outputs: Path) -> None:
    contract = _payload(authored_outputs, "packet_contract")
    assert corridor.OUTPUTS["attack_matrix"] in contract["deliverables"]
    assert corridor.OUTPUTS["claim_boundary_attack_plan"] in contract["deliverables"]


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_predecessor_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_NEXT_MOVE_DRIFT"


def test_rejects_missing_commercial_proof_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["commercial_proof_plane_validated"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREDECESSOR_MISSING"


def test_rejects_commercial_activation_authority_from_claim_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SOURCE_INPUTS["commercial_proof_plane_claim_boundary_receipt"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY"


def test_rejects_external_audit_completion_from_security_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SOURCE_INPUTS["commercial_proof_plane_security_review_packet"]
    payload = _load(path)
    payload["external_audit_completed"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY"


def test_rejects_claim_ceiling_benchmark_prep_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SOURCE_INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["benchmark_prep_authorizes_commercial_activation"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_PREMATURE_AUTHORITY"


def test_rejects_beyond_sota_claim_in_customer_language(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / corridor.SOURCE_INPUTS["commercial_proof_plane_customer_safe_language"]
    path.write_text(path.read_text(encoding="utf-8") + "\nBeyond-SOTA is proven.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_CLAIM_BOUNDARY_BREACH"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(corridor.LaneFailure) as excinfo:
        corridor.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_ADVERSARIAL_PROOF_TRUST_ZONE_FAILED"
