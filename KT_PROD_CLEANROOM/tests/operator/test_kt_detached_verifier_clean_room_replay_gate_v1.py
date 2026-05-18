from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_detached_verifier_clean_room_replay_gate_v1 as gate


GATE_HEAD = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
MAIN_HEAD = "01e9ab0f36655b5161c9ed0e42cab885cce4e795"


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
    for raw in gate.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    validation_receipt = _load(tmp_path / gate.INPUTS["validation_receipt"])
    for row in validation_receipt["input_bindings"]:
        _copy_file(source_root, tmp_path, row["path"])


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = gate.AUTHOR_BRANCH,
    head: str = GATE_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(gate, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(gate.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(gate.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(gate.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        gate,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    gate.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def gate_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_clean_room_replay_gate")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / gate.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(gate.REASON_CODES) == len(set(gate.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(gate.OUTPUTS.values()))
def test_authoring_outputs_exist(gate_outputs: Path, raw: str) -> None:
    path = gate_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Clean-room replay executed: false" in path.read_text(encoding="utf-8")


def test_gate_authors_but_does_not_run_clean_room_replay(gate_outputs: Path) -> None:
    receipt = _payload(gate_outputs, "author_receipt")
    assert receipt["clean_room_replay_gate_authored"] is True
    assert receipt["clean_room_replay_executed"] is False
    assert receipt["clean_room_replay_completed"] is False
    assert receipt["cannot_execute_clean_room_replay"] is True


def test_next_lawful_move_is_validation_not_run(gate_outputs: Path) -> None:
    receipt = _payload(gate_outputs, "next_lawful_move")
    assert receipt["selected_outcome"] == gate.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "VALIDATE_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
    assert "RUN_" not in receipt["next_lawful_move"]


def test_gate_binds_validation_predecessor(gate_outputs: Path) -> None:
    receipt = _payload(gate_outputs, "author_receipt")
    assert receipt["predecessor_outcome"] == gate.EXPECTED_PREVIOUS_OUTCOME
    assert receipt["predecessor_next_lawful_move"] == gate.EXPECTED_PREVIOUS_NEXT_MOVE
    assert receipt["binding_hashes"]["validation_receipt_hash"]
    assert receipt["binding_hashes"]["gate_decision_hash"]


def test_gate_scope_excludes_claim_expansion(gate_outputs: Path) -> None:
    scope = _payload(gate_outputs, "execution_scope")
    assert scope["can_prepare_replay_inputs"] is True
    assert scope["can_run_replay"] is False
    assert scope["can_claim_replay_complete"] is False
    for key in (
        "external_audit_claimed_complete",
        "commercial_activation_claimed",
        "commercial_activation_claim_authorized",
        "seven_b_amplification_claimed",
        "seven_b_amplification_claimed_proven",
        "beyond_sota_claimed",
        "s_tier_claimed",
        "fp0_or_highway_promoted_to_authority",
    ):
        assert scope[key] is False


def test_validation_plan_must_not_execute_replay(gate_outputs: Path) -> None:
    plan = _payload(gate_outputs, "validation_plan")
    assert plan["validation_lane"] == gate.NEXT_LAWFUL_MOVE
    assert plan["validation_must_not_execute_replay"] is True
    assert any("execution remains false" in check for check in plan["validation_checks"])


def test_rejects_validation_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / gate.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload["selected_outcome"] = "WRONG"
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_ambiguous_or_wrong_validation_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    decision_path = tmp_path / gate.INPUTS["gate_decision"]
    payload = _load(decision_path)
    payload["next_lawful_move"] = "AUTHOR_OR_RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
    _write(decision_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("clean_room_replay_executed", True),
        ("commercial_activation_claimed", True),
        ("external_audit_claimed_complete", True),
        ("seven_b_amplification_claimed", True),
        ("beyond_sota_claimed", True),
        ("fp0_or_highway_promoted_to_authority", True),
        ("truth_engine_law_changed", True),
        ("trust_zone_law_changed", True),
    ],
)
def test_rejects_authority_boolean_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str, value: bool) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / gate.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload[key] = value
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH"


@pytest.mark.parametrize(
    "claim",
    [
        "External audit is complete.",
        "Commercial activation claims are authorized.",
        "7B amplification is proven.",
        "Beyond-SOTA is proven.",
        "Detached verifier clean-room replay has run.",
        "Highway or FP0 has canonical authority.",
    ],
)
def test_rejects_forbidden_claim_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claim: str) -> None:
    _copy_inputs(tmp_path)
    gate_path = tmp_path / gate.INPUTS["validation_gate"]
    payload = _load(gate_path)
    payload["claim_boundary"] = claim
    _write(gate_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH"


def test_rejects_mixed_negative_and_affirmative_forbidden_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    gate_path = tmp_path / gate.INPUTS["validation_gate"]
    payload = _load(gate_path)
    payload["claim_boundary"] = "External audit is not complete; commercial activation claims are authorized."
    _write(gate_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_CLAIM_BOUNDARY_BREACH"


def test_allows_separately_negated_forbidden_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    gate_path = tmp_path / gate.INPUTS["validation_gate"]
    payload = _load(gate_path)
    payload["claim_boundary"] = "External audit is not complete. Commercial activation claims remain unauthorized."
    _write(gate_path, payload)
    _patch_env(monkeypatch, tmp_path)
    gate.run(output_root=tmp_path)


def test_recomputes_validation_bindings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / gate.INPUTS["validation_receipt"]
    payload = _load(receipt_path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_SOURCE_HASH_MISMATCH"


def test_rejects_dirty_out_of_scope_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(gate.LaneFailure) as excinfo:
        gate.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_BRANCH_DRIFT"
