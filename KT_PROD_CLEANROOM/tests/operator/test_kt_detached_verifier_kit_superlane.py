from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import kt_detached_verifier_kit_superlane as kit


AUTHOR_HEAD = "cccccccccccccccccccccccccccccccccccccccc"
MAIN_HEAD = "d87c9fb80f03c872f03de696ed0654fe613ce042"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_file(source_root: Path, tmp_path: Path, raw: str) -> None:
    source = source_root / raw
    if not source.exists():
        return
    target = tmp_path / raw
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _copy_inputs(tmp_path: Path) -> None:
    source_root = Path.cwd()
    for raw in kit.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)
    contract = _load(tmp_path / kit.INPUTS["truth_lock_validation_contract"])
    for row in contract["artifact_bindings"]:
        _copy_file(source_root, tmp_path, row["path"])
    for raw in kit.OPTIONAL_INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = kit.AUTHORITY_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(kit, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(kit.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(kit.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(kit.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        kit,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    kit.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def kit_outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("detached_verifier_kit")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / kit.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(kit.REASON_CODES) == len(set(kit.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(kit.OUTPUTS.values()))
def test_required_outputs_exist(kit_outputs: Path, raw: str) -> None:
    path = kit_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "Detached Verifier Kit" in text


def test_receipt_selects_validation_next(kit_outputs: Path) -> None:
    receipt = _payload(kit_outputs, "receipt")
    assert receipt["selected_outcome"] == kit.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == kit.NEXT_LAWFUL_MOVE
    assert receipt["truth_lock_validated"] is True
    assert receipt["detached_verifier_clean_room_replay_run"] is False
    assert receipt["commercial_activation_claim_authorized"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["seven_b_amplification_claimed_proven"] is False


def test_manifest_and_evidence_bundle_define_full_kit(kit_outputs: Path) -> None:
    manifest = _payload(kit_outputs, "manifest")
    evidence = _payload(kit_outputs, "evidence_bundle")
    assert "governance/detached_verifier_replay_protocol_v1.json" in manifest["kit_components"]
    assert "trust-zone validation receipt" in evidence["evidence_classes"]
    assert evidence["clean_room_replay_required"] is True
    assert evidence["clean_room_replay_completed"] is False


def test_claim_limiter_blocks_overclaims(kit_outputs: Path) -> None:
    limiter = _payload(kit_outputs, "claim_limiter")
    assert "Truth Lock is validated." in limiter["allowed_claims"]
    assert "Commercial activation claims are authorized." in limiter["forbidden_claims"]
    assert "External audit is complete." in limiter["forbidden_claims"]
    assert "7B amplification is proven." in limiter["forbidden_claims"]
    assert limiter["cannot_authorize_commercial_activation_claims"] is True
    assert limiter["cannot_claim_external_audit_complete"] is True


def test_parallel_lanes_are_eligible_but_not_authority(kit_outputs: Path) -> None:
    eligibility = _payload(kit_outputs, "parallel_lane_eligibility")
    assert eligibility["highway_shadow_promotion_status"] == "ELIGIBLE_NON_CLAIM_EXPANSION_ONLY"
    assert eligibility["fp0_overlay_promotion_status"] == "ELIGIBLE_NON_CLAIM_EXPANSION_ONLY"
    assert eligibility["highway_shadow_promoted_to_authority"] is False
    assert eligibility["fp0_overlay_promoted_to_authority"] is False
    assert eligibility["canonical_authority_promotion_allowed"] is False


def test_input_bindings_recompute_current_files(kit_outputs: Path) -> None:
    receipt = _payload(kit_outputs, "receipt")
    roles = {row["role"] for row in receipt["input_bindings"]}
    assert set(kit.INPUTS) <= roles
    for row in receipt["input_bindings"]:
        assert len(row["sha256"]) == 64


def test_predecessor_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / kit.INPUTS["truth_lock_validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = "KT_EXTERNAL_LAUNCH_READINESS_TRUTH_LOCK_DEFERRED__NAMED_VALIDATION_DEFECT_REMAINS"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_PREDECESSOR_OUTCOME_DRIFT"


def test_predecessor_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / kit.INPUTS["truth_lock_validation_next_lawful_move_receipt"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_KT_SUPPLY_CHAIN_RELEASE_CORRIDOR_SUPERLANE_V1"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_PREDECESSOR_NEXT_MOVE_DRIFT"


def test_validation_binding_hash_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    tamper_path = tmp_path / "external/known_limitations.md"
    tamper_path.write_text(tamper_path.read_text(encoding="utf-8") + "\nTampered after validation.\n", encoding="utf-8")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_PREDECESSOR_HASH_MISMATCH"


def test_claim_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / kit.INPUTS["detached_verifier_kit_next_prep_only"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_BOUNDARY_DRIFT"


def test_forbidden_claim_text_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / kit.INPUTS["detached_verifier_kit_next_prep_only"]
    payload = _load(path)
    payload["unsafe_claim"] = "External audit is complete."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_CLAIM_TOKEN_DRIFT"


def test_branch_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(kit.LaneFailure) as excinfo:
        kit.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_DETACHED_VERIFIER_BRANCH_DRIFT"
