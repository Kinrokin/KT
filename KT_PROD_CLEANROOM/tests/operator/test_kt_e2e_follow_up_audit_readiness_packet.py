from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import kt_e2e_follow_up_audit_readiness_packet as packet


AUTHOR_HEAD = "abababababababababababababababababababab"
AUTHOR_MAIN_HEAD = "1efe6378a70684224d89f008faaec0d3cbda009d"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_inputs(tmp_path: Path) -> Path:
    source_root = Path.cwd()
    reports = tmp_path / "KT_PROD_CLEANROOM/reports"
    reports.mkdir(parents=True, exist_ok=True)
    for raw in packet.INPUTS.values():
        source = source_root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return reports


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = packet.AUTHORITY_BRANCH,
    head: str = AUTHOR_HEAD,
    origin_main: str = AUTHOR_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(packet, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(packet.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(packet.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(packet.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        packet,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path)
    packet.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("kt_e2e_follow_up_audit_readiness_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_packet(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / packet.OUTPUTS[role])


def _json_roles() -> list[str]:
    return sorted(role for role, filename in packet.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(packet.REASON_CODES) == len(set(packet.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(packet.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "follow-up audit readiness packet" in text
        assert "commercial activation claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_packet_binds_commercial_activation_evidence_review_validation(outputs: Path) -> None:
    contract = _payload(outputs, "packet_contract")
    assert contract["authoritative_lane"] == packet.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == packet.PREVIOUS_LANE
    assert contract["predecessor_outcome"] == packet.EXPECTED_PREVIOUS_OUTCOME
    assert contract["previous_next_lawful_move"] == packet.EXPECTED_PREVIOUS_NEXT_MOVE
    assert contract["binding_hashes"]["commercial_activation_evidence_review_validation_contract_hash"]
    assert contract["binding_hashes"]["commercial_activation_evidence_review_validation_receipt_hash"]


def test_packet_routes_to_audit_readiness_validation(outputs: Path) -> None:
    assert _payload(outputs, "packet_contract")["selected_outcome"] == packet.SELECTED_OUTCOME
    assert _payload(outputs, "packet_receipt")["selected_outcome"] == packet.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == packet.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_passed", True),
        ("commercial_activation_executed", True),
        ("commercial_activation_passed", True),
        ("commercial_activation_evidence_review_validated", True),
        ("follow_up_audit_readiness_packet_authored", True),
        ("follow_up_audit_readiness_validated", False),
        ("commercial_activation_claim_authorized", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_packet_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _payload(outputs, "packet_contract")[flag] == expected


def test_canonical_state_board_is_conservative(outputs: Path) -> None:
    board = _payload(outputs, "canonical_state_board")["state"]
    assert board["commercial_activation_evidence_review"] == "VALIDATED"
    assert board["follow_up_audit_readiness"] == "PACKET_AUTHORED_VALIDATION_NEXT"
    assert board["commercial_activation_claims"] == "UNAUTHORIZED"
    assert board["seven_b_amplification"] == "NOT_PROVEN"


def test_allowed_and_forbidden_claims_are_separated(outputs: Path) -> None:
    allowed = _payload(outputs, "allowed_claims_current_state")["allowed_claims"]
    forbidden = _payload(outputs, "forbidden_claims_current_state")["forbidden_claims"]
    assert "Commercial activation evidence review is validated." in allowed
    assert "Follow-up audit readiness is validated." in forbidden
    assert "7B amplification is proven." in forbidden


@pytest.mark.parametrize("role", packet.PREP_ONLY_ROLES)
def test_prep_only_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_follow_up_audit_readiness_validated"] is True


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_record_expected_heads(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["current_main_head"] == AUTHOR_MAIN_HEAD
    assert payload["current_git_head"] == AUTHOR_HEAD
    assert payload["current_branch_head"] == AUTHOR_HEAD


def test_commercial_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / packet.INPUTS["claim_ceiling_current_state"]
    payload = _load(path)
    payload["allowed_claims"].append("Commercial activation claims authorized.")
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(packet.LaneFailure) as excinfo:
        packet.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_PACKET_CLAIM_TOKEN_DRIFT"


def test_follow_up_audit_premature_validation_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    path = tmp_path / packet.INPUTS["commercial_activation_evidence_review_validation_contract"]
    payload = _load(path)
    payload["follow_up_audit_readiness_validated"] = True
    _write(path, payload)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(packet.LaneFailure) as excinfo:
        packet.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_PACKET_PREMATURE_VALIDATION"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _copy_inputs(tmp_path)
    _patch_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(packet.LaneFailure) as excinfo:
        packet.run(reports_root=reports)
    assert excinfo.value.code == "RC_KT_E2E_AUDIT_READY_PACKET_NEXT_MOVE_DRIFT"
