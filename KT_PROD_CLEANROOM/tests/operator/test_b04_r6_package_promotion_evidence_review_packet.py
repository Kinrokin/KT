from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion as promotion
from tools.operator import cohort0_b04_r6_package_promotion_evidence_review_packet as review


REVIEW_HEAD = "abababababababababababababababababababab"
REVIEW_MAIN_HEAD = "5fc927536c7d883dc9d80d05687affc903188c71"


def _load_promotion_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_promotion_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package promotion helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


promotion_helpers = _load_promotion_helpers()


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


def _run_promotion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return promotion_helpers._run_promotion(tmp_path, monkeypatch)


def _run_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_promotion(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path)
    review.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_evidence_review")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_review(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / review.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "review_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in review.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(review.REASON_CODES) == len(set(review.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(review.OUTPUTS.values()))
def test_required_review_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "package promotion evidence review packet" in text
        assert "commercial activation claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_review_binds_package_promotion(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == review.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == promotion.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == promotion.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == promotion.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["promotion_contract_hash"]
    assert contract["binding_hashes"]["promotion_receipt_hash"]


def test_review_selects_validation_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == review.SELECTED_OUTCOME
    assert _payload(outputs, "review_receipt")["selected_outcome"] == review.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == review.NEXT_LAWFUL_MOVE


def test_decision_matrix_recommends_commercial_activation_review_only(outputs: Path) -> None:
    matrix = _payload(outputs, "post_promotion_decision_matrix")
    assert matrix["recommended_next_path"] == review.RECOMMENDED_NEXT_PATH
    assert matrix["commercial_activation_review_ready"] is True
    assert matrix["commercial_activation_claim_status"] == "UNAUTHORIZED_REVIEW_ONLY"


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_executed", True),
        ("package_promotion_passed", True),
        ("package_promotion_evidence_review_packet_authored", True),
        ("package_promotion_evidence_review_validated", False),
        ("commercial_activation_review_packet_next_recommended", True),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_package_promotion", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_review_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", review.REVIEW_CONTRACT_ROLES)
def test_review_contracts_are_bound(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["review_status"] == "BOUND"
    assert payload["grade"] == "PASS"


@pytest.mark.parametrize("role", review.PREP_ONLY_ROLES)
def test_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_commercial_activation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_promotion(tmp_path, monkeypatch)
    contract_path = reports / promotion.OUTPUTS["promotion_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_claim_authorized"] = True
    _write(contract_path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_COMMERCIAL_CLAIM_DRIFT"


def test_seven_b_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_promotion(tmp_path, monkeypatch)
    contract_path = reports / promotion.OUTPUTS["promotion_contract"]
    payload = _load(contract_path)
    payload["seven_b_claim"] = "7B amplification is proven"
    _write(contract_path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_CLAIM_TOKEN_DRIFT"


def test_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_promotion(tmp_path, monkeypatch)
    path = reports / promotion.OUTPUTS["commercial_activation_review_packet_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_PREP_ONLY_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_promotion(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT"


def test_lawful_self_replay_next_move_receipt_is_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review(tmp_path, monkeypatch)
    _patch_review_env(monkeypatch, tmp_path, branch=f"{review.REPLAY_BRANCH_PREFIX}-test")
    review.run(reports_root=reports)
    assert _load(reports / review.OUTPUTS["review_contract"])["selected_outcome"] == review.SELECTED_OUTCOME


def test_malformed_self_replay_next_move_receipt_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_review(tmp_path, monkeypatch)
    path = reports / review.OUTPUTS["next_lawful_move"]
    payload = _load(path)
    payload["previous_next_lawful_move"] = "AUTHOR_B04_R6_COMMERCIAL_ACTIVATION_REVIEW_PACKET"
    _write(path, payload)
    _patch_review_env(monkeypatch, tmp_path, branch=f"{review.REPLAY_BRANCH_PREFIX}-test")
    with pytest.raises(review.LaneFailure) as excinfo:
        review.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_EVID_REVIEW_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == REVIEW_MAIN_HEAD
