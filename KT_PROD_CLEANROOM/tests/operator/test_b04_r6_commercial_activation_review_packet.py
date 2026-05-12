from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_commercial_activation_review_packet as review
from tools.operator import cohort0_b04_r6_package_promotion_evidence_review_packet_validation as prior_validation


REVIEW_HEAD = "efefefefefefefefefefefefefefefefefefefef"
REVIEW_MAIN_HEAD = "6093e82b6ef0b67fb04d7a2f3aad0f5bcf5745cc"


def _load_prior_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion_evidence_review_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_promotion_evidence_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package promotion evidence validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prior_helpers = _load_prior_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_review_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = review.AUTHORITY_BRANCH,
    head: str = REVIEW_HEAD,
    origin_main: str = REVIEW_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(review, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(review.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(review.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(review.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_prior_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return prior_helpers._run_validation(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("commercial_activation_review_packet")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _prior_payload(outputs: Path, role: str) -> dict:
    return _load(outputs / prior_validation.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "review_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in review.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(review.REASON_CODES) == len(set(review.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "commercial activation review packet" in text
        assert "commercial activation claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_review_binds_package_promotion_evidence_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == prior_validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == prior_validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == prior_validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_review_selects_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _payload(outputs, "review_receipt")["selected_outcome"] == review.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_review_preserves_branch_and_main_heads(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["current_git_head"] == REVIEW_HEAD
    assert contract["current_main_head"] == REVIEW_MAIN_HEAD


def test_decision_matrix_recommends_authorization_packet_only(outputs: Path) -> None:
    matrix = _payload(outputs, "post_package_decision_matrix")
    assert matrix["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert matrix["recommendation_is_authority"] is False
    assert matrix["commercial_activation_authorization_review_ready"] is True
    assert matrix["commercial_activation_claim_status"] == "UNAUTHORIZED_REVIEW_ONLY"


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_executed", True),
        ("package_promotion_passed", True),
        ("package_promotion_evidence_review_validated", True),
        ("commercial_activation_review_packet_authored", True),
        ("commercial_activation_review_packet_validated", False),
        ("commercial_activation_authorization_packet_next_recommended", True),
        ("commercial_activation_claim_authorized", False),
        ("commercial_activation_executed", False),
        ("benchmark_prep_authorizes_commercial_activation", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_review_preserves_authority_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", sorted(review.REVIEW_ROLES))
def test_review_contracts_are_bound(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["review_status"] == "BOUND"
    assert payload["grade"] == "PASS"
    assert payload["commercial_activation_claim_authorized"] is False


@pytest.mark.parametrize("role", sorted(review.PREP_ONLY_ROLES))
def test_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_execute_commercial_activation"] is True


@pytest.mark.parametrize("role", sorted(prior_validation.PREP_ONLY_OUTPUT_ROLES))
def test_prior_validation_prep_inputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _prior_payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["status"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True


@pytest.mark.parametrize("role", sorted(review.VALIDATION_JSON_INPUTS))
def test_review_binds_all_prior_validation_json_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


@pytest.mark.parametrize("role", sorted(review.VALIDATION_TEXT_INPUTS))
def test_review_binds_all_prior_validation_text_inputs(outputs: Path, role: str) -> None:
    value = _contract(outputs)["binding_hashes"][f"{role}_hash"]
    assert len(value) == 64
    assert all(ch in "0123456789abcdef" for ch in value)


def test_input_binding_rows_anchor_to_binding_hashes(outputs: Path) -> None:
    contract = _contract(outputs)
    for row in contract["input_bindings"]:
        assert contract["binding_hashes"][f"{row['role']}_hash"] == row["sha256"]


def test_claim_ceiling_preserves_forbidden_claims(outputs: Path) -> None:
    claim_ceiling = _payload(outputs, "claim_ceiling_current_state")
    assert "KT is commercially activated." in claim_ceiling["forbidden_claims"]
    assert "7B amplification is proven." in claim_ceiling["forbidden_claims"]


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_preserve_boundaries(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["commercial_activation_claim_authorized"] is False
    assert payload["commercial_activation_executed"] is False
    assert payload["truth_engine_law_changed"] is False
    assert payload["trust_zone_law_changed"] is False


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, dirty=" M drift")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        review.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="feature/wrong")
    with pytest.raises(review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_prior_validation_outcome_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["selected_outcome"] = prior_validation.OUTCOME_INVALID
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="OUTCOME_DRIFT"):
        review.run(reports_root=reports)


def test_prior_validation_next_move_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["next_lawful_move"] = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_AUTHORIZATION_PACKET"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="NEXT_MOVE_DRIFT"):
        review.run(reports_root=reports)


def test_commercial_claim_boolean_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_activation_claim_authorized"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="COMMERCIAL_CLAIM_DRIFT"):
        review.run(reports_root=reports)


def test_commercial_claim_token_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["commercial_claim"] = "AUTHORIZED"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        review.run(reports_root=reports)


def test_commercial_claim_token_inside_list_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["allowed_claims"] = ["Commercial activation authorized"]
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        review.run(reports_root=reports)


def test_prior_prep_only_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["commercial_activation_review_validation_plan_prep_only"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="PREP_ONLY_DRIFT"):
        review.run(reports_root=reports)


def test_benchmark_authority_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["benchmark_prep_authorizes_commercial_activation"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="BENCHMARK_AUTHORITY_DRIFT"):
        review.run(reports_root=reports)


def test_predecessor_package_benchmark_authority_drift_uses_specific_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["benchmark_prep_authorizes_package_promotion"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_COMMERCIAL_ACTIVATION_REVIEW_BENCHMARK_AUTHORITY_DRIFT"


def test_seven_b_amplification_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["seven_b_amplification_claimed_proven"] = True
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="7B_CLAIM_DRIFT"):
        review.run(reports_root=reports)


def test_text_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    path = reports / prior_validation.OUTPUTS["validation_report"]
    text = path.read_text(encoding="utf-8")
    path.write_text(text + "\nCommercial activation authorized.\n", encoding="utf-8")
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure, match="CLAIM_TOKEN_DRIFT"):
        review.run(reports_root=reports)


def test_trust_zone_failure_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_prior_validation(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        review,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "FAIL", "failures": ["boom"], "checks": []},
    )
    with pytest.raises(review.LaneFailure, match="TRUST_ZONE_FAILED"):
        review.run(reports_root=reports)
