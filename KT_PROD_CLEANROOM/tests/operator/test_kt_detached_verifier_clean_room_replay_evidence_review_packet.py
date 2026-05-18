from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_detached_verifier_clean_room_replay_evidence_review_packet as review


AUTHOR_HEAD = "d" * 40
MAIN_HEAD = "57be8267a52775ac2158d604a5dbc6f1dbb3acf9"


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
    for raw in review.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = review.AUTHOR_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(review.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        review,
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
    review.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def review_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_clean_room_replay_evidence_review")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / review.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(review.REASON_CODES) == len(set(review.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(review.OUTPUTS.values()))
def test_review_outputs_exist(review_outputs: Path, raw: str) -> None:
    path = review_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Clean-room replay executed: true" in path.read_text(encoding="utf-8")


def test_review_packet_selects_validation_next(review_outputs: Path) -> None:
    receipt = _payload(review_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == review.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"
    assert receipt["supply_chain_release_corridor_authorized"] is False


def test_review_preserves_claim_boundary(review_outputs: Path) -> None:
    receipt = _payload(review_outputs, "packet_receipt")
    assert receipt["clean_room_replay_executed"] is True
    assert receipt["external_audit_claimed_complete"] is False
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False
    assert receipt["beyond_sota_claimed"] is False
    assert receipt["fp0_or_highway_promoted_to_authority"] is False


def test_external_audit_matrix_uses_consistent_completion_key(review_outputs: Path) -> None:
    matrix = _payload(review_outputs, "external_audit_readiness_matrix")
    assert matrix["external_audit_completed"] is False
    assert "external_audit_complete" not in matrix


def test_evidence_inventory_binds_detached_runtime_artifacts(review_outputs: Path) -> None:
    inventory = _payload(review_outputs, "evidence_inventory")
    paths = {row["path"] for row in inventory["evidence_artifacts"]}
    assert "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/reports/detached_runtime_receipt.json" in paths
    assert "KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/WS19_detached_public_verifier_proof/reports/detached_public_verifier_report.json" in paths


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / review.INPUTS["execution_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_public_verifier_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / review.INPUTS["public_verifier_detached_receipt"]
    payload = _load(path)
    payload["status"] = "BLOCKED"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PUBLIC_VERIFIER_NOT_PASS"


def test_rejects_forbidden_claim_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / review.INPUTS["result"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is not complete, but commercial activation claims are authorized."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH"


def test_rejects_positive_claim_with_nearby_unrelated_negative_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / review.INPUTS["result"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is complete and commercial activation is not authorized."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH"


def test_rejects_nested_authority_drift_object(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / review.INPUTS["result"]
    payload = _load(path)
    payload["external_audit_completed"] = {"value": False}
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_CLAIM_BOUNDARY_BREACH"


def test_rejects_dirty_workspace_before_authoring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_BRANCH_DRIFT"
