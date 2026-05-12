from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from tools.operator import cohort0_b04_r6_package_promotion as promotion
from tools.operator import cohort0_b04_r6_package_promotion_execution_packet_validation as validation


PROMOTION_HEAD = "9999999999999999999999999999999999999999"
PROMOTION_MAIN_HEAD = "aa7b984e0a9626eb845741663fbf369f46c1685f"


def _load_validation_helpers():
    helper_path = Path(__file__).with_name("test_b04_r6_package_promotion_execution_packet_validation.py")
    spec = importlib.util.spec_from_file_location("b04_r6_package_execution_validation_helpers", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load package promotion execution validation helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validation_helpers = _load_validation_helpers()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _patch_promotion_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = promotion.AUTHORITY_BRANCH,
    head: str = PROMOTION_HEAD,
    origin_main: str = PROMOTION_MAIN_HEAD,
    dirty: str = "",
) -> None:
    refs = {"HEAD": head, "origin/main": origin_main}
    monkeypatch.setattr(promotion, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(promotion.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(promotion.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(promotion.common, "git_rev_parse", lambda root, ref: refs.get(ref, head))
    monkeypatch.setattr(
        promotion,
        "validate_trust_zones",
        lambda *, root: {"schema_id": "trust", "status": "PASS", "failures": [], "checks": [{"status": "PASS"}]},
    )


def _run_execution_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return validation_helpers._run_validation(tmp_path, monkeypatch)


def _run_promotion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    _patch_promotion_env(monkeypatch, tmp_path)
    promotion.run(reports_root=reports)
    return reports


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    tmp_path = tmp_path_factory.mktemp("package_promotion_run")
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _run_promotion(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _payload(outputs: Path, role: str) -> dict:
    return _load(outputs / promotion.OUTPUTS[role])


def _contract(outputs: Path) -> dict:
    return _payload(outputs, "promotion_contract")


def _json_roles() -> list[str]:
    return sorted(role for role, filename in promotion.OUTPUTS.items() if filename.endswith(".json"))


def test_reason_codes_are_unique() -> None:
    assert len(promotion.REASON_CODES) == len(set(promotion.REASON_CODES))


@pytest.mark.parametrize("filename", sorted(promotion.OUTPUTS.values()))
def test_required_promotion_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        text = path.read_text(encoding="utf-8").lower()
        assert "package promotion passed" in text
        assert "commercial activation claims remain unauthorized" in text
    else:
        payload = _load(path)
        assert payload["schema_id"]
        assert payload["artifact_id"]


def test_promotion_binds_execution_validation(outputs: Path) -> None:
    contract = _contract(outputs)
    assert contract["authoritative_lane"] == promotion.AUTHORITATIVE_LANE
    assert contract["previous_authoritative_lane"] == validation.AUTHORITATIVE_LANE
    assert contract["predecessor_outcome"] == validation.SELECTED_OUTCOME
    assert contract["previous_next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert contract["binding_hashes"]["validation_contract_hash"]
    assert contract["binding_hashes"]["validation_receipt_hash"]


def test_promotion_selects_evidence_review_next(outputs: Path) -> None:
    assert _contract(outputs)["selected_outcome"] == promotion.SELECTED_OUTCOME
    assert _payload(outputs, "promotion_receipt")["selected_outcome"] == promotion.SELECTED_OUTCOME
    assert _payload(outputs, "next_lawful_move")["next_lawful_move"] == promotion.NEXT_LAWFUL_MOVE


@pytest.mark.parametrize(
    "flag,expected",
    [
        ("r6_open", True),
        ("package_promotion_execution_packet_validated", True),
        ("package_promotion_authorized", True),
        ("package_promotion_executed", True),
        ("package_promotion_passed", True),
        ("package_promotion_evidence_review_packet_next", True),
        ("commercial_activation_claim_authorized", False),
        ("benchmark_prep_authorizes_package_promotion", False),
        ("seven_b_amplification_claimed_proven", False),
        ("truth_engine_law_changed", False),
        ("truth_engine_law_unchanged", True),
        ("trust_zone_law_changed", False),
        ("trust_zone_law_unchanged", True),
    ],
)
def test_promotion_boundaries(outputs: Path, flag: str, expected: object) -> None:
    assert _contract(outputs)[flag] == expected


@pytest.mark.parametrize("role", promotion.PROMOTION_RECEIPT_ROLES)
def test_promotion_receipts_pass(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["receipt_status"] == "PASS"
    assert payload["checks"]


@pytest.mark.parametrize("role", promotion.PREP_ONLY_ROLES)
def test_downstream_prep_outputs_remain_prep_only(outputs: Path, role: str) -> None:
    payload = _payload(outputs, role)
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_claim_7b_amplification_proven"] is True


def test_commercial_activation_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    contract_path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(contract_path)
    payload["commercial_activation_claim_authorized"] = True
    _write(contract_path, payload)
    _patch_promotion_env(monkeypatch, tmp_path)
    with pytest.raises(promotion.LaneFailure) as excinfo:
        promotion.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_COMMERCIAL_CLAIM_DRIFT"


def test_seven_b_amplification_claim_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["validation_contract"]
    payload = _load(path)
    payload["seven_b_claim"] = "7B amplification is proven"
    _write(path, payload)
    _patch_promotion_env(monkeypatch, tmp_path)
    with pytest.raises(promotion.LaneFailure) as excinfo:
        promotion.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_CLAIM_TOKEN_DRIFT"


def test_validation_prep_only_drift_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    path = reports / validation.OUTPUTS["package_promotion_run_prep_only_draft"]
    payload = _load(path)
    payload["authority"] = "AUTHORITATIVE"
    _write(path, payload)
    _patch_promotion_env(monkeypatch, tmp_path)
    with pytest.raises(promotion.LaneFailure) as excinfo:
        promotion.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_PREP_ONLY_DRIFT"


def test_main_replay_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_execution_validation(tmp_path, monkeypatch)
    _patch_promotion_env(monkeypatch, tmp_path, branch="main", head="1" * 40, origin_main="2" * 40)
    with pytest.raises(promotion.LaneFailure) as excinfo:
        promotion.run(reports_root=reports)
    assert excinfo.value.code == "RC_B04R6_PACKAGE_PROMOTION_NEXT_MOVE_DRIFT"


@pytest.mark.parametrize("role", _json_roles())
def test_all_json_outputs_have_current_main_head(outputs: Path, role: str) -> None:
    assert _payload(outputs, role)["current_main_head"] == PROMOTION_MAIN_HEAD
