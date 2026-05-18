from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Iterator

import pytest

from tools.operator import kt_external_audit_and_ratification_packet_superlane_v1 as audit_packet
from tools.operator import validate_kt_adversarial_proof_corridor_superlane_v1 as predecessor
from tools.operator.titanium_common import repo_root


AUTHOR_HEAD = "a" * 40
MAIN_HEAD = "49cf6038b4dd5b28f9432e6715fc77b7c380ab2a"


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
    for raw in audit_packet.INPUTS.values():
        _copy_file(source_root, tmp_path, raw)


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = audit_packet.AUTHOR_BRANCH,
    head: str = AUTHOR_HEAD,
    dirty: str = "",
    trust_status: str = "PASS",
) -> None:
    refs = {"HEAD": head, "origin/main": MAIN_HEAD}
    monkeypatch.setattr(audit_packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(audit_packet.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(audit_packet.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(audit_packet.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        audit_packet,
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
    audit_packet.run(output_root=tmp_path)
    return tmp_path


@pytest.fixture(scope="module")
def authored_outputs(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    tmp_path = tmp_path_factory.mktemp("external_audit_ratification")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(root: Path, role: str) -> dict:
    return _load(root / audit_packet.OUTPUTS[role])


def test_reason_codes_are_unique() -> None:
    assert len(audit_packet.REASON_CODES) == len(set(audit_packet.REASON_CODES))


@pytest.mark.parametrize("raw", sorted(audit_packet.OUTPUTS.values()))
def test_outputs_exist(authored_outputs: Path, raw: str) -> None:
    path = authored_outputs / raw
    assert path.exists()
    if raw.endswith(".json"):
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]
    else:
        text = path.read_text(encoding="utf-8")
        assert "External audit completed: false" in text
        assert "Commercial activation claims authorized: false" in text


def test_authoring_selects_validation_next(authored_outputs: Path) -> None:
    receipt = _payload(authored_outputs, "packet_receipt")
    assert receipt["selected_outcome"] == audit_packet.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == audit_packet.NEXT_LAWFUL_MOVE
    assert receipt["external_audit_and_ratification_packet_authored"] is True
    assert receipt["external_audit_and_ratification_validated"] is False
    assert receipt["external_audit_completed"] is False
    assert receipt["external_reaudit_accepted"] is False


def test_bound_sources_include_adversarial_validation(authored_outputs: Path) -> None:
    manifest = _payload(authored_outputs, "source_manifest")
    roles = {row["role"] for row in manifest["sources"]}
    assert set(audit_packet.PREDECESSOR_INPUTS).issubset(roles)
    assert "h05_external_audit_ratification_gate_decision" in roles


def test_audit_scope_binds_required_evidence(authored_outputs: Path) -> None:
    scope = _payload(authored_outputs, "audit_scope_manifest")
    rows = {row["scope_id"]: row for row in scope["scope_rows"]}
    assert rows["detached_verifier_clean_room_replay"]["status"] == "PACKET_BOUND"
    assert rows["supply_chain_release_integrity"]["status"] == "PACKET_BOUND"
    assert rows["adversarial_proof_corridor"]["status"] == "PACKET_BOUND"
    assert rows["benchmark_or_7b_superiority"]["status"] == "NOT_CLAIMED"


def test_decision_matrix_declares_but_does_not_select_external_outcome(authored_outputs: Path) -> None:
    matrix = _payload(authored_outputs, "ratification_decision_matrix")
    outcomes = {row["outcome"] for row in matrix["decision_rows"]}
    assert outcomes == set(audit_packet.DECISION_OUTCOMES)
    assert matrix["decision_selected_now"] is False
    assert all(row["selected_now"] is False for row in matrix["decision_rows"])


def test_claim_boundaries_preserved(authored_outputs: Path) -> None:
    boundary = _payload(authored_outputs, "claim_boundary_receipt")
    assert boundary["no_claim_expansion"] is True
    assert boundary["external_audit_completed"] is False
    assert boundary["external_reaudit_accepted"] is False
    assert boundary["commercial_activation_claim_authorized"] is False
    assert boundary["seven_b_amplification_claimed_proven"] is False
    assert boundary["fp0_or_highway_promoted_to_authority"] is False


def test_validation_plan_names_expected_checks(authored_outputs: Path) -> None:
    plan = _payload(authored_outputs, "validation_plan")
    assert "reject_external_audit_completion_claim" in plan["validation_checks"]
    assert "reject_commercial_claim_authorization" in plan["validation_checks"]
    assert plan["expected_validation_outcome"] in plan["allowed_external_reaudit_outcomes"]
    assert plan["allowed_external_reaudit_outcomes"] == list(audit_packet.ALLOWED_VALIDATION_AND_REAUDIT_OUTCOMES)


def test_rejects_predecessor_outcome_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["selected_outcome"] = "WRONG"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_OUTCOME_DRIFT"


def test_rejects_predecessor_next_move_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_SOMETHING_ELSE"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_NEXT_MOVE_DRIFT"


def test_rejects_missing_adversarial_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["validation_receipt"]
    payload = _load(path)
    payload["adversarial_proof_corridor_validated"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREDECESSOR_MISSING"


def test_rejects_external_audit_authority_in_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / predecessor.OUTPUTS["external_audit_ratification_gate_decision"]
    payload = _load(path)
    payload["external_audit_ratification_packet_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY"


def test_rejects_unvalidated_detached_verifier_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["detached_verifier_clean_room_evidence_validation"]
    payload = _load(path)
    payload["clean_room_replay_evidence_review_packet_validated"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_failed_clean_room_replay_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["detached_verifier_clean_room_replay_result"]
    payload = _load(path)
    payload["clean_room_replay_passed"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_unvalidated_supply_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["supply_chain_validation_receipt"]
    payload = _load(path)
    payload["supply_chain_release_corridor_packet_validated"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_unbound_supply_chain_release_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["supply_chain_release_integrity_receipt"]
    payload = _load(path)
    payload["release_integrity_bound"] = False
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_commercial_evidence_pack_claim_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["commercial_proof_plane_evidence_pack_manifest"]
    payload = _load(path)
    payload["evidence_pack_authorizes_commercial_activation_claims"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY"


def test_rejects_incomplete_commercial_evidence_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["commercial_proof_plane_evidence_pack_manifest"]
    payload = _load(path)
    payload["evidence_pack_items"] = []
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_external_audit_manifest_not_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["external_audit_packet_manifest"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_public_verifier_manifest_not_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["public_verifier_manifest"]
    payload = _load(path)
    payload["status"] = "FAIL"
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_SOURCE_STATUS_FAILED"


def test_rejects_commercial_claim_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY"


def test_rejects_external_audit_completion_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["commercial_proof_plane_security_review_packet"]
    payload = _load(path)
    payload["external_audit_completed"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_PREMATURE_AUTHORITY"


def test_rejects_external_reaudit_accepted_claim_in_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["h05_claim_boundary_receipt"]
    payload = _load(path)
    payload["notes"] = "External reaudit is accepted."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_CLAIM_BOUNDARY_BREACH"


def test_rejects_beyond_sota_claim_in_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    path = tmp_path / audit_packet.SOURCE_INPUTS["h05_claim_boundary_receipt"]
    payload = _load(path)
    payload["notes"] = "Beyond-SOTA is proven."
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_CLAIM_BOUNDARY_BREACH"


def test_rejects_unexpected_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT"


def test_rejects_dirty_workspace_outside_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, dirty="?? unrelated.txt\n")
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_BRANCH_DRIFT"


def test_rejects_trust_zone_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, trust_status="FAIL")
    with pytest.raises(audit_packet.LaneFailure) as excinfo:
        audit_packet.run(output_root=tmp_path)
    assert excinfo.value.code == "RC_KT_EXTERNAL_AUDIT_RATIFICATION_TRUST_ZONE_FAILED"
