from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion_review_packet as package_review
from tools.operator import cohort0_b04_r6_package_promotion_review_packet_validation as validation


VALIDATION_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
VALIDATION_MAIN_HEAD = "d0c422ed99feeea938c580357b2742a8c7265ca7"


def _load_package_review_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion_review_packet.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_review_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package review helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


package_review_helpers = _load_package_review_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_validation_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = validation.AUTHORITY_BRANCH,
    head: str = VALIDATION_HEAD,
    origin_main: str = VALIDATION_MAIN_HEAD,
    origin_main_parent: str | None = None,
    dirty: str = "",
    git_blob_store: dict[tuple[str, str], bytes] | None = None,
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    if origin_main_parent is not None:
        refs[f"{origin_main}^1"] = origin_main_parent
    blob_store = dict(git_blob_store or {})
    if not blob_store:
        commits = {origin_main}
        if origin_main_parent is not None:
            commits.add(origin_main_parent)
        for commit in commits:
            for raw in list(validation.PACKAGE_REVIEW_JSON_INPUTS.values()) + list(
                validation.PACKAGE_REVIEW_TEXT_INPUTS.values()
            ):
                path = tmp_path / raw
                if path.exists():
                    blob_store[(commit, raw)] = path.read_bytes()

    def fake_git_blob_bytes(root: Path, commit: str, raw: str) -> bytes:
        if (commit, raw) not in blob_store:
            validation._fail(
                "RC_B04R6_PACKAGE_PROMOTION_REVIEW_VAL_INPUT_HASH_MISSING",
                f"missing git blob {commit}:{raw}",
            )
        return blob_store[(commit, raw)]

    def fake_git_blob_sha256(root: Path, commit: str, raw: str) -> str:
        import hashlib

        return hashlib.sha256(fake_git_blob_bytes(root, commit, raw)).hexdigest()

    monkeypatch.setattr(validation, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(validation.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(validation.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(validation.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(validation, "_git_blob_bytes", fake_git_blob_bytes)
    monkeypatch.setattr(validation, "_git_blob_sha256", fake_git_blob_sha256)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_package_review_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return package_review_helpers._run_package_review(tmp_path, monkeypatch)


def _run_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_review_validation")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_validation(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / validation.OUTPUTS[role])


def _review_payload(outputs: Path, role: str) -> dict:
    return _load(outputs / package_review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "validation_contract")


def _receipt(outputs: Path) -> dict:
    return _payload(outputs, "validation_receipt")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in validation.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(validation.REASON_CODES) == len(set(validation.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_required_validation_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "package-promotion review validation" in text
        assert "does not authorize package promotion" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_validation_contract_preserves_current_main_head(outputs: Path) -> None:
    assert _contract(outputs)["current_main_head"] == VALIDATION_MAIN_HEAD


def test_validation_binds_package_promotion_review_packet(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == package_review.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == package_review.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == package_review.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["packet_contract_hash"]
    assert contract["binding_hashes"]["packet_receipt_hash"]


def test_validation_outputs_do_not_overlap_package_review_inputs() -> None:
    reviewed_paths = {
        f"KT_PROD_CLEANROOM/reports/{filename}"
        for filename in package_review.OUTPUTS.values()
        if filename.endswith((".json", ".md"))
    }
    assert validation.OUTPUT_PATHS.isdisjoint(reviewed_paths)


def test_validation_records_no_overwritten_input_roles(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["overwritten_input_roles"] == []
    assert all(
        row.get("mutable_canonical_path_overwritten_by_this_lane") is not True
        for row in contract["input_bindings"]
    )


def test_main_replay_keeps_validation_outputs_separate_from_review_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    original_review_hashes = {
        role: validation.file_sha256(tmp_path / raw)
        for role, raw in validation.PACKAGE_REVIEW_JSON_INPUTS.items()
    }
    _patch_validation_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    replay_head = "cccccccccccccccccccccccccccccccccccccccc"
    _patch_validation_env(
        monkeypatch,
        tmp_path,
        branch=f"{validation.REPLAY_BRANCH_PREFIX}-main-replay",
        head=replay_head,
        origin_main=replay_head,
        origin_main_parent=VALIDATION_MAIN_HEAD,
    )
    validation.run(reports_root=reports)

    assert _contract(reports)["overwritten_input_roles"] == []
    assert {
        role: validation.file_sha256(tmp_path / raw)
        for role, raw in validation.PACKAGE_REVIEW_JSON_INPUTS.items()
    } == original_review_hashes


def test_validation_selects_package_authorization_packet_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["selected_outcome"] == validation.SELECTED_OUTCOME
    assert _receipt(outputs)["verdict"] == "PACKAGE_PROMOTION_REVIEW_VALIDATED_PACKAGE_PROMOTION_AUTHORIZATION_PACKET_NEXT"
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE


def test_validation_report_states_non_authorization_boundaries(outputs: Path) -> None:
    text = (outputs / validation.OUTPUTS["validation_report"]).read_text(encoding="utf-8").lower()
    assert "permits only package-promotion authorization packet authorship" in text
    assert "does not authorize package promotion" in text
    assert "commercial activation claims" in text
    assert "r6 remains open" in text


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("r6_opening_evidence_review_validated", True),
        ("package_promotion_review_packet_authored", True),
        ("package_promotion_review_validated", True),
        ("package_promotion_authorization_packet_next", True),
        ("package_promotion_authorized", False),
        ("package_promotion_executed", False),
        ("commercial_activation_claim_authorized", False),
        ("lobe_escalation_authorized", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
        ("r6_open_treated_as_package_promotion", False),
        ("package_promotion_treated_as_commercial_activation", False),
    ],
)
def test_validation_contract_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", validation.VALIDATION_RECEIPT_ROLES)
def test_validation_receipts_pass(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["validation_status"] == "PASS"


@pytest.mark.parametrize("role", validation.PREP_ONLY_OUTPUT_ROLES)
def test_validation_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_execute_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_preserve_boundaries(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["r6_open"] is True
    assert payload["package_promotion_authorized"] is False
    assert payload["package_promotion_executed"] is False
    assert payload["commercial_activation_claim_authorized"] is False
    assert payload["truth_engine_law_changed"] is False
    assert payload["trust_zone_law_changed"] is False


def test_pipeline_board_routes_to_authorization_packet(outputs: Path) -> None:
    board = _payload(outputs, "pipeline_board")["board"]
    assert board["package_promotion_review"] == "VALIDATED"
    assert board["package_promotion_authorization_packet"] == "NEXT_AUTHORING_LANE"
    assert board["package_promotion"] == "UNAUTHORIZED"


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        validation.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_packet_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["packet_contract"]
    payload = _load(path)
    payload["selected_outcome"] = package_review.OUTCOME_INVALID
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="PACKET_OUTCOME_DRIFT"):
        validation.run(reports_root=reports)


def test_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_PACKAGE_PROMOTION_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="NEXT_MOVE_DRIFT"):
        validation.run(reports_root=reports)


def test_scorecard_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["evidence_scorecard"]
    payload = _load(path)
    payload["scorecard"]["public_verifier_ready"] = False
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="SCORECARD_INCOMPLETE"):
        validation.run(reports_root=reports)


def test_decision_matrix_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["decision_matrix"]
    payload = _load(path)
    payload["decision_matrix"]["package_promotion_authorized"] = True
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="DECISION_UNJUSTIFIED"):
        validation.run(reports_root=reports)


def test_review_contract_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["public_verifier_readiness_review"]
    payload = _load(path)
    payload["review_status"] = "FAIL"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="REVIEW_CONTRACT_MISSING"):
        validation.run(reports_root=reports)


def test_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    path = reports / package_review.OUTPUTS["decision_matrix"]
    payload = _load(path)
    payload["package_promotion"] = "AUTHORIZED"
    _write(path, payload)
    _patch_validation_env(monkeypatch, tmp_path)
    with pytest.raises(validation.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        validation.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_package_review_only(tmp_path, monkeypatch)
    _patch_validation_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        validation,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(validation.LaneFailure, match="TRUST_ZONE_FAILED"):
        validation.run(reports_root=reports)
