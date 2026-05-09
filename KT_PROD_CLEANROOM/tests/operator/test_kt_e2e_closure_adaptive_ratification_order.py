from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import kt_e2e_closure_adaptive_ratification_order as order


HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN = "63b1424b0348a7c85526b35d06f45a10874683f9"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_prior_receipts(reports: Path, *, outcome: str = order.PREVIOUS_OUTCOME) -> None:
    _write(
        reports / order.VALIDATION_RECEIPT,
        {
            "schema_id": "test.prior.validation",
            "artifact_id": "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            "selected_outcome": outcome,
            "next_lawful_move": order.PREVIOUS_NEXT_LAWFUL_MOVE,
            "runtime_cutover_authorized": False,
            "r6_open": False,
        },
    )
    _write(
        reports / order.CANARY_DECISION_RECEIPT,
        {
            "schema_id": "test.prior.decision",
            "artifact_id": "B04_R6_CANARY_POST_RUN_DECISION_MATRIX_VALIDATION_RECEIPT",
            "recommended_next_path_validated": "EXPANDED_CANARY_AUTHORIZATION_PACKET_NEXT",
        },
    )


def _patch_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    branch: str = order.AUTHORITY_BRANCH,
    dirty: str = "",
) -> None:
    monkeypatch.setattr(order, "repo_root", lambda: tmp_path)
    monkeypatch.setattr(order.common, "git_current_branch_name", lambda root: branch)
    monkeypatch.setattr(order.common, "git_status_porcelain", lambda root: dirty)
    monkeypatch.setattr(order.common, "git_rev_parse", lambda root, ref: MAIN if ref == "origin/main" else HEAD)


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_prior_receipts(reports)
    _patch_env(monkeypatch, tmp_path)
    order.run(reports_root=reports)
    return reports


@pytest.mark.parametrize("filename", sorted(order.OUTPUTS.values()))
def test_required_outputs_exist_and_parse(outputs: Path, filename: str) -> None:
    payload = _load(outputs / filename)
    assert payload["schema_id"] == "kt.e2e_closure.adaptive_ratification_order.v1"
    assert payload["artifact_id"]


@pytest.mark.parametrize("role", sorted(order.OUTPUTS))
def test_every_campaign_artifact_is_prep_only(outputs: Path, role: str) -> None:
    payload = _load(outputs / order.OUTPUTS[role])
    assert payload["authority"] == "PREP_ONLY"
    assert payload["cannot_authorize_runtime_cutover"] is True
    assert payload["cannot_open_r6"] is True
    assert payload["cannot_authorize_lobe_escalation"] is True
    assert payload["cannot_authorize_package_promotion"] is True
    assert payload["cannot_authorize_commercial_activation_claims"] is True
    assert payload["cannot_mutate_truth_engine_law"] is True
    assert payload["cannot_mutate_trust_zone_law"] is True
    assert payload["runtime_cutover_authorized"] is False
    assert payload["r6_open"] is False
    assert payload["package_promotion_authorized"] is False
    assert payload["commercial_activation_claim_authorized"] is False


def test_campaign_order_selects_validation_next(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["campaign_order"])
    assert payload["selected_outcome"] == order.SELECTED_OUTCOME
    assert payload["next_lawful_move"] == order.NEXT_LAWFUL_MOVE
    assert payload["current_main_head"] == MAIN
    assert payload["previous_next_lawful_move"] == order.PREVIOUS_NEXT_LAWFUL_MOVE


def test_campaign_order_carries_required_statement(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["campaign_order"])
    assert "does not claim small models are secretly giant models" in payload["required_statement"]
    assert "proves where it does not" in payload["required_statement"]


def test_claim_ceiling_blocks_overclaiming(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["claim_ceiling"])
    assert "The canary evidence review is validated on canonical main." in payload["allowed_claims"]
    assert "7B amplification is proven." in payload["forbidden_claims"]
    assert "KT beats larger models generally." in payload["forbidden_claims"]


def test_ablation_ladder_is_ordered_and_complete(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["amplification_ablation_plan"])
    assert payload["ablation_ladder"] == list(order.ABLATION_LADDER)
    assert payload["ablation_ladder"][0] == "A0_RAW_7B_BASELINE"
    assert payload["ablation_ladder"][-1] == "A8_7B_PLUS_FULL_KT_GOVERNANCE_RECEIPTS_REPLAY"
    assert payload["theorem_status"] == "NOT_PROVEN"


def test_lobe_factory_requires_ratification_before_activation(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["lobe_ratification_factory"])
    assert payload["lobe_ratification_order"] == list(order.LOBE_RATIFICATION_ORDER)
    assert "proof_validator" in payload["candidate_lobe_families"]
    assert payload["lobe_activation"] == "BLOCKED_UNTIL_FUTURE_AUTHORITY"
    assert payload["lobe_activation_authorized"] is False


def test_campaign_board_tracks_required_corridors(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["campaign_board"])
    corridors = {row["corridor"]: row for row in payload["corridors"]}
    for corridor in order.REQUIRED_CORRIDORS:
        assert corridor in corridors
    assert corridors["R6_CORRIDOR"]["authoritative_next"] == order.PREVIOUS_NEXT_LAWFUL_MOVE
    assert "RUNTIME_CUTOVER" in corridors["R6_CORRIDOR"]["blocked_authorities"]


def test_gpu_training_gate_blocks_training_authority(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["gpu_training_gate"])
    assert payload["gpu_training_readiness"] == "BLOCKED_PENDING_TRAINING_LAW"
    assert payload["gpu_training_authorized"] is False
    assert "source_packet" in payload["required_before_gpu_training"]


def test_next_lawful_move_receipt_preserves_validation_next(outputs: Path) -> None:
    payload = _load(outputs / order.OUTPUTS["next_lawful_move"])
    assert payload["receipt_type"] == "NEXT_LAWFUL_MOVE"
    assert payload["next_lawful_move"] == order.NEXT_LAWFUL_MOVE
    assert "proof_factory_v1" in payload["after_validation_parallel_tracks"]


def test_prior_validation_wrong_outcome_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_prior_receipts(reports, outcome="WRONG_OUTCOME")
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="requires canonical canary evidence validation outcome"):
        order.run(reports_root=reports)


def test_dirty_worktree_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_prior_receipts(reports)
    _patch_env(monkeypatch, tmp_path, dirty=" M file\n")
    with pytest.raises(RuntimeError, match="dirty worktree"):
        order.run(reports_root=reports)


def test_wrong_branch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_prior_receipts(reports)
    _patch_env(monkeypatch, tmp_path, branch="feature/random")
    with pytest.raises(RuntimeError, match="must run on one of"):
        order.run(reports_root=reports)
