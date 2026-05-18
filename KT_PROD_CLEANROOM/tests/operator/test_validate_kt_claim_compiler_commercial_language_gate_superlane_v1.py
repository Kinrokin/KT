from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_claim_compiler_commercial_language_gate_superlane_v1 as gate
from tools.operator import validate_kt_claim_compiler_commercial_language_gate_superlane_v1 as validator


VALIDATION_HEAD = "b" * 40
MAIN_HEAD = "b2e862e470759d7349e3cce36a4c5ad1f09562b6"


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
    for raw in gate.OUTPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    for raw in gate.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validator.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(validator, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validator.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validator.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validator.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        validator,
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
    validator.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def validation_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("claim_gate_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / validator.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(validator.REASON_CODES) == len(set(validator.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(validator.OUTPUTS.values()))
def test_outputs_exist(validation_outputs: Path, raw: str) -> None:
    path = validation_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        assert "Commercial activation claims authorized: false" in path.read_text(encoding="utf-8")


def test_validation_selects_commercial_proof_plane_next(validation_outputs: Path) -> None:
    receipt = _payload(validation_outputs, "validation_receipt")
    assert receipt["selected_outcome"] == validator.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == "AUTHOR_KT_COMMERCIAL_PROOF_PLANE_SUPERLANE_V1"
    assert receipt["claim_compiler_commercial_language_gate_validated"] is True
    assert receipt["commercial_proof_plane_next"] is True


def test_validation_preserves_boundaries(validation_outputs: Path) -> None:
    decision = _payload(validation_outputs, "commercial_proof_plane_gate_decision")
    assert decision["commercial_proof_plane_next"] is True
    assert decision["commercial_proof_plane_authorized"] is False
    assert decision["commercial_activation_claim_authorized"] is False
    assert decision["external_audit_completed"] is False
    assert decision["seven_b_amplification_claimed_proven"] is False
    assert decision["fp0_or_highway_promoted_to_authority"] is False


def test_scorecard_all_pass(validation_outputs: Path) -> None:
    scorecard = _payload(validation_outputs, "validation_scorecard")
    assert scorecard["fail_count"] == 0
    assert all(row["status"] == "PASS" for row in scorecard["score_rows"])


def test_rejects_packet_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_OUTCOME_DRIFT"


def test_rejects_packet_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_NEXT_MOVE_DRIFT"


def test_rejects_bound_source_hash_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["claim_compiler_policy"]
    payload = _load(path)
    payload["purpose"] = "tampered"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_missing_markdown_scan_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["recursive_claim_scanner_contract"]
    payload = _load(path)
    payload["scanned_shapes"].remove("markdown_text")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_SCANNER_CONTRACT_INCOMPLETE"


def test_rejects_allowed_commercial_activation_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["allowed_claims_current_state"]
    payload = _load(path)
    payload["allowed_claims"].append("Commercial activation claims are authorized.")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_CLAIM_BOUNDARY_BREACH"


def test_rejects_affirmative_markdown_claim_in_bound_doc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.CLAIM_INPUTS["operator_factory_sku_catalog"]
    path.write_text(path.read_text(encoding="utf-8") + "\nExternal audit is complete.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_SOURCE_HASH_MISMATCH"


def test_rejects_premature_commercial_proof_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["commercial_proof_plane_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_CLAIM_BOUNDARY_BREACH"


def test_machine_routing_outcome_ids_do_not_fail_claim_scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["packet_receipt"]
    payload = _load(path)
    payload["allowed_outcomes"] = ["KT_S_TIER_READJUDICATED__BOUNDED_GOVERNED_EXECUTION_S_TIER_CLAIM_ALLOWED"]
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    outputs = validator.run(output_root=tmp_path)
    assert outputs["validation_receipt"]["claim_boundary_passed"] is True


def test_rejects_duplicate_packet_reason_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / gate.OUTPUTS["validation_reason_codes"]
    payload = _load(path)
    payload["reason_codes"].append(payload["reason_codes"][0])
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_REASON_CODE_DUPLICATE"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(validator.LaneFailure) as excinfo:
        validator.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_CLAIM_GATE_VAL_TRUST_ZONE_FAILED"
