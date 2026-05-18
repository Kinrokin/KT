from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import run_kt_detached_verifier_clean_room_replay_gate_v1 as replay


RUN_HEAD = "a" * 40
MAIN_HEAD = "9ca2ae25b806183d2b50a6a754fd547e71228365"


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
    for raw in replay.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    validation_receipt = _load(tmp_path / replay.INPUTS["validation_receipt"])
    for row in validation_receipt["input_bindings"]:
        _copy_file(source_root, tmp_path, row["path"])


def _fake_public_verifier_outputs(root: Path, *, status: str = "PASS") -> None:
    for role, raw in replay.PUBLIC_VERIFIER_OUTPUTS.items():
        path = root / raw
        payload = {
            "schema_id": f"test.{role}",
            "artifact_id": Path(raw).name,
            "status": status,
            "pass_verdict": "DETACHED_PUBLIC_VERIFIER_PACKAGE_PROVEN" if status == "PASS" else "DETACHED_PUBLIC_VERIFIER_PACKAGE_BLOCKED",
            "stronger_claim_not_made": "WS19 does not claim independent external reproduction, third-party detached replay, or public horizon opening.",
        }
        if role == "detached_runtime_receipt":
            payload["detached_environment"] = {"detached_root_detected": True, "git_head_available": False}
            payload["checks"] = [
                {"check": "detached_root_without_git_checkout", "status": status},
                {"check": "trust_root_resolved_from_packaged_policy", "status": status},
                {"check": "source_and_build_provenance_resolved", "status": status},
                {"check": "rekor_and_sigstore_bundle_resolved", "status": status},
                {"check": "authority_state_resolved", "status": status},
            ]
        path.parent.mkdir(parents=True, exist_ok=True)
        _write(path, payload)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = replay.RUN_BRANCH,
    head: str = RUN_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
    public_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(replay, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(replay.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(replay.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(replay.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        replay,
        "validate_trust_zones",
        lambda *, root: {
            "schema_id": "trust",
            "status": trust_status,
            "failures": [] if trust_status == "PASS" else ["forced failure"],
            "checks": [{"status": trust_status}],
        },
    )

    def fake_run(root: Path) -> dict:
        _fake_public_verifier_outputs(root, status=public_status)
        return {"command": "fake detached verifier", "returncode": 0 if public_status == "PASS" else 1, "stdout_tail": "", "stderr_tail": ""}

    monkeypatch.setattr(replay, "_run_detached_public_verifier", fake_run)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    replay.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def replay_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_clean_room_replay")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / replay.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(replay.REASON_CODES) == len(set(replay.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(replay.OUTPUTS.values()))
def test_run_outputs_exist(replay_outputs: Path, raw: str) -> None:
    path = replay_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Clean-room replay executed: true" in path.read_text(encoding="utf-8")


def test_run_executes_clean_room_replay_without_claim_expansion(replay_outputs: Path) -> None:
    receipt = _payload(replay_outputs, "execution_receipt")
    assert receipt["selected_outcome"] == replay.SELECTED_OUTCOME
    assert receipt["clean_room_replay_executed"] is True
    assert receipt["clean_room_replay_passed"] is True
    assert receipt["external_audit_claimed_complete"] is False
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False
    assert receipt["fp0_or_highway_promoted_to_authority"] is False


def test_next_lawful_move_is_evidence_review(replay_outputs: Path) -> None:
    receipt = _payload(replay_outputs, "next_lawful_move")
    assert receipt["next_lawful_move"] == "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"


def test_evidence_manifest_binds_public_verifier_outputs(replay_outputs: Path) -> None:
    manifest = _payload(replay_outputs, "evidence_manifest")
    roles = {row.get("role") for row in manifest["evidence_artifacts"]}
    assert set(replay.PUBLIC_VERIFIER_OUTPUTS).issubset(roles)


def test_rejects_validation_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / replay.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload["selected_outcome"] = "WRONG"
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_wrong_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / replay.INPUTS["validation_next_lawful_move"]
    payload = _load(receipt_path)
    payload["next_lawful_move"] = "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_EVIDENCE_REVIEW_PACKET"
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_NEXT_MOVE_DRIFT"


def test_rejects_premature_replay_execution_in_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / replay.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload["clean_room_replay_executed"] = True
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_CLAIM_BOUNDARY_BREACH"


def test_rejects_forbidden_claim_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    contract_path = tmp_path / replay.INPUTS["run_gate_contract"]
    payload = _load(contract_path)
    payload["claim_boundary"] = "External audit is not complete, but commercial activation claims are authorized."
    _write(contract_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_CLAIM_BOUNDARY_BREACH"


def test_recomputes_validation_bindings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / replay.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_SOURCE_HASH_MISMATCH"


def test_requires_complete_validation_binding_coverage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / replay.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    omitted_path = replay.validation.INPUTS["author_receipt"]
    payload["input_bindings"] = [row for row in payload["input_bindings"] if row["path"] != omitted_path]
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_SOURCE_HASH_MISMATCH"


def test_rejects_public_verifier_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, public_status="BLOCKED")
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_EXECUTION_FAILED"


def test_rejects_dirty_workspace_before_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(replay.LaneFailure) as excinfo:
        replay.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_CLEAN_ROOM_REPLAY_BRANCH_DRIFT"
