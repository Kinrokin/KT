from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import validate_kt_detached_verifier_clean_room_replay_gate_v1 as validation


VALIDATION_HEAD = "f" * 40
MAIN_HEAD = "bba56b82bba56b82bba56b82bba56b82bba56b82"


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
    tmp_path = tmp_path_factory.mktemp("detached_verifier_clean_room_replay_gate_validation")
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
    assert receipt["clean_room_replay_gate_validated"] is True
    assert receipt["validation_must_not_execute_replay"] is True
    assert receipt["clean_room_replay_executed"] is False
    assert receipt["clean_room_replay_completed"] is False


def test_validation_selects_exact_run_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "next_lawful_move")
    assert receipt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
    assert "AUTHOR_OR_RUN" not in receipt["next_lawful_move"]


def test_run_decision_is_ready_to_run_but_not_completed(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "run_decision")
    assert decision["decision"] == validation.DECISION
    assert decision["can_run_clean_room_replay_next"] is True
    assert decision["clean_room_replay_executed"] is False
    assert decision["external_audit_claimed_complete"] is False


def test_run_gate_contract_preserves_claim_boundary(validation_outputs: Path) -> None:
    contract = _payload(validation_outputs, "run_gate_contract")
    assert contract["run_authorized_next"] is True
    assert contract["run_authorized_inside_validation"] is False
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
        assert contract[key] is False


def test_excluded_surfaces_are_not_treated_as_affirmative_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    contract_path = tmp_path / validation.INPUTS["authoring_contract"]
    payload = _load(contract_path)
    payload["excluded_clean_room_replay_surface"] = ["beyond-SOTA claim", "commercial activation claim authorization"]
    _write(contract_path, payload)
    _patch_env(monkeypatch, tmp_path)
    validation.run(output_root=tmp_path)


def test_rejects_missing_gate_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    (tmp_path / validation.INPUTS["authoring_contract"]).unlink()
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_ARTIFACT_MISSING"


def test_rejects_gate_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / validation.INPUTS["author_receipt"]
    payload = _load(receipt_path)
    payload["selected_outcome"] = "WRONG"
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_ambiguous_gate_next_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / validation.INPUTS["author_next_lawful_move"]
    payload = _load(receipt_path)
    payload["next_lawful_move"] = "AUTHOR_OR_RUN_KT_DETACHED_VERIFIER_CLEAN_ROOM_REPLAY_GATE_V1"
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("clean_room_replay_executed", True),
        ("clean_room_replay_completed", True),
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
    receipt_path = tmp_path / validation.INPUTS["author_receipt"]
    payload = _load(receipt_path)
    payload[key] = value
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH"


@pytest.mark.parametrize(
    "claim",
    [
        "External audit is complete.",
        "Commercial activation claims are authorized.",
        "7B amplification is proven.",
        "Beyond-SOTA is proven.",
        "Detached verifier clean-room replay has run.",
        "Clean-room replay completed.",
        "Highway or FP0 has canonical authority.",
    ],
)
def test_rejects_forbidden_claim_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claim: str) -> None:
    _copy_inputs(tmp_path)
    contract_path = tmp_path / validation.INPUTS["authoring_contract"]
    payload = _load(contract_path)
    payload["claim_boundary"] = claim
    _write(contract_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH"


def test_rejects_mixed_negative_and_affirmative_forbidden_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    contract_path = tmp_path / validation.INPUTS["authoring_contract"]
    payload = _load(contract_path)
    payload["claim_boundary"] = "External audit is not complete; commercial activation claims are authorized."
    _write(contract_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_CLAIM_BOUNDARY_BREACH"


def test_allows_separately_negated_forbidden_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    contract_path = tmp_path / validation.INPUTS["authoring_contract"]
    payload = _load(contract_path)
    payload["claim_boundary"] = "External audit is not complete. Commercial activation claims remain unauthorized."
    _write(contract_path, payload)
    _patch_env(monkeypatch, tmp_path)
    validation.run(output_root=tmp_path)


def test_recomputes_author_bindings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    receipt_path = tmp_path / validation.INPUTS["author_receipt"]
    payload = _load(receipt_path)
    payload["input_bindings"][0]["sha256"] = "0" * 64
    _write(receipt_path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_SOURCE_HASH_MISMATCH"


def test_rejects_dirty_out_of_scope_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(validation.LaneFailure) as excinfo:
        validation.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DV_REPLAY_GATE_VALIDATION_TRUST_ZONE_FAILED"
