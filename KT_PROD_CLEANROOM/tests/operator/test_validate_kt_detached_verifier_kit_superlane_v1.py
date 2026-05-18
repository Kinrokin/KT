from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import validate_kt_detached_verifier_kit_superlane_v1 as validation


VALIDATION_HEAD = "dddddddddddddddddddddddddddddddddddddddd"
MAIN_HEAD = "cad7a59e27e92fef840714113cb83e35567dd911"


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
    for raw in validation.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    author_receipt = _load(tmp_path / validation.INPUTS["author_receipt"])
    for row in author_receipt["input_bindings"]:
        _copy_file(source_root, tmp_path, row["path"])


def _patch_env(
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


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    validation.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def validation_outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_validation")
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
        assert "Clean-room replay executed: false" in path.read_text(encoding="utf-8")


def test_validation_refuses_to_run_clean_room_replay(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["clean_room_replay_executed"] is False
    assert receipt["cannot_execute_clean_room_replay"] is True
    assert receipt["next_lawful_move"] == "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"


def test_validation_emits_expected_to_actual_path_map(validation_outputs: Path) -> None:
    payload = _payload(validation_outputs, "expected_to_actual_path_map")
    rows = payload["path_map"]
    expected = {row["expected_path"]: row for row in rows}
    assert "verifier/kt-verify" in expected
    assert expected["verifier/kt-verify"]["actual_path"] == "KT_PROD_CLEANROOM/tools/operator/public_verifier.py"
    assert expected["external/clean_room_replay_report.md"]["status"] == "NOT_EXECUTED_BY_DESIGN"


def test_missing_expected_artifact_requires_blocker_or_lawful_substitution(validation_outputs: Path) -> None:
    path_map = _payload(validation_outputs, "expected_to_actual_path_map")["path_map"]
    assert all(row["validation_status"] == "PASS" for row in path_map)
    assert all(row["status"] in {"LAWFUL_SUBSTITUTION", "NOT_EXECUTED_BY_DESIGN"} for row in path_map)


def test_validation_requires_detached_verifier_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    (tmp_path / validation.INPUTS["public_verifier"]).unlink()
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_VALIDATION_ARTIFACT_MISSING"


def test_validation_requires_replay_manifest_schema(validation_outputs: Path) -> None:
    path_map = _payload(validation_outputs, "expected_to_actual_path_map")["path_map"]
    row = next(item for item in path_map if item["expected_path"] == "proof/replay_manifest.schema.json")
    assert row["actual_path"] == "governance/detached_verifier_replay_protocol_v1.json"
    assert row["substitute_exists"] is True


def test_validation_requires_evidence_bundle_schema(validation_outputs: Path) -> None:
    path_map = _payload(validation_outputs, "expected_to_actual_path_map")["path_map"]
    row = next(item for item in path_map if item["expected_path"] == "proof/evidence_bundle.schema.json")
    assert row["actual_path"] == "governance/detached_verifier_evidence_bundle_v1.json"
    assert row["actual_exists"] is True


def test_validation_requires_claim_board_schema(validation_outputs: Path) -> None:
    path_map = _payload(validation_outputs, "expected_to_actual_path_map")["path_map"]
    row = next(item for item in path_map if item["expected_path"] == "proof/claim_board.schema.json")
    assert row["actual_path"] == "governance/detached_verifier_claim_limiter_v1.json"
    assert row["actual_exists"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commercial_activation_claimed", True),
        ("external_audit_claimed_complete", True),
        ("seven_b_amplification_claimed", True),
        ("beyond_sota_claimed", True),
        ("fp0_or_highway_promoted_to_authority", True),
        ("clean_room_replay_executed", True),
    ],
)
def test_validation_rejects_authority_boolean_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: bool
) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / validation.INPUTS["claim_limiter"]
    payload = _load(path)
    payload[field] = value
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_VALIDATION_CLAIM_BOUNDARY_BREACH"


@pytest.mark.parametrize(
    "unsafe_claim",
    [
        "Commercial activation claims are authorized.",
        "External audit is complete.",
        "7B amplification is proven.",
        "Beyond-SOTA.",
        "Highway or FP0 has canonical authority.",
        "Clean-room replay completed.",
    ],
)
def test_validation_rejects_forbidden_claim_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_claim: str
) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / validation.INPUTS["claim_limiter"]
    payload = _load(path)
    payload["unsafe_claim"] = unsafe_claim
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_VALIDATION_CLAIM_BOUNDARY_BREACH"


def test_clean_room_replay_ready_does_not_claim_external_audit_complete(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "clean_room_replay_gate_decision")
    assert decision["decision"] == "CLEAN_ROOM_REPLAY_GATE_NEXT"
    assert decision["external_audit_claimed_complete"] is False
    assert decision["clean_room_replay_executed"] is False


def test_validation_emits_clean_room_replay_gate_decision(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "clean_room_replay_gate_decision")
    assert decision["validation_executed"] is True
    assert decision["claim_boundary_passed"] is True
    assert decision["decision"] == "CLEAN_ROOM_REPLAY_GATE_NEXT"


def test_next_lawful_move_is_exact_not_author_or_run_ambiguous(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["next_lawful_move"] == "AUTHOR_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
    assert "AUTHOR_OR_RUN" not in receipt["next_lawful_move"]


def test_blocked_validation_emits_blockers_instead_of_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / validation.INPUTS["author_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "KT_DETACHED_VERIFIER_KIT_SUPERLANE_V1_DEFERRED__NAMED_AUTHORING_DEFECT_REMAINS"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_VALIDATION_PREDECESSOR_OUTCOME_DRIFT"


def test_validation_recomputes_author_replay_bindings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    tamper_path = tmp_path / "governance/truth_lock_validation_contract.json"
    payload = _load(tamper_path)
    payload["tampered_after_h01_authoring"] = True
    _write(tamper_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_VALIDATION_SOURCE_HASH_MISMATCH"
