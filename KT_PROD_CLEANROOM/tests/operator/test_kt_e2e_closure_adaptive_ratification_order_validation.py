from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.operator import kt_e2e_closure_adaptive_ratification_order as order
from tools.operator import kt_e2e_closure_adaptive_ratification_order_validation as validation


HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
MAIN = "8a442c5e56e9fb297ead47e823e0dde3bbcc73fd"
ORDER_MAIN = "db1764ddfe75da995163a2cb46affc809367c8d0"


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _seed_prior_receipts(reports: Path) -> None:
    _write(
        reports / order.VALIDATION_RECEIPT,
        {
            "schema_id": "test.prior.validation",
            "artifact_id": "B04_R6_CANARY_EVIDENCE_REVIEW_VALIDATION_RECEIPT",
            "selected_outcome": order.PREVIOUS_OUTCOME,
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
    branch: str = validation.AUTHORITY_BRANCH,
    dirty: str = "",
    head: str = HEAD,
    origin_main: str = MAIN,
) -> None:
    for module in (order, validation):
        monkeypatch.setattr(module, "repo_root", lambda: tmp_path)
        monkeypatch.setattr(module.common, "git_current_branch_name", lambda root: branch)
        monkeypatch.setattr(module.common, "git_status_porcelain", lambda root: dirty)
        monkeypatch.setattr(module.common, "git_rev_parse", lambda root, ref: origin_main if ref == "origin/main" else head)


def _run_order_then_validation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    reports = tmp_path / "KT_PROD_CLEANROOM" / "reports"
    _seed_prior_receipts(reports)
    _patch_env(monkeypatch, tmp_path, branch=order.AUTHORITY_BRANCH, head=ORDER_MAIN, origin_main=ORDER_MAIN)
    order.run(reports_root=reports)
    _patch_env(monkeypatch, tmp_path)
    validation.run(reports_root=reports)
    return reports


@pytest.fixture()
def outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return _run_order_then_validation(tmp_path, monkeypatch)


@pytest.mark.parametrize("filename", sorted(validation.OUTPUTS.values()))
def test_validation_outputs_exist(outputs: Path, filename: str) -> None:
    path = outputs / filename
    assert path.exists()
    if filename.endswith(".md"):
        assert validation.SELECTED_OUTCOME in path.read_text(encoding="utf-8")
    else:
        payload = _load(path)
        assert payload["schema_id"] == "kt.e2e_closure.adaptive_ratification_order.validation.v1"


def test_validation_selects_expanded_canary_authorization_next(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["validation_receipt"])
    assert receipt["selected_outcome"] == validation.SELECTED_OUTCOME
    assert receipt["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert receipt["campaign_order_validated"] is True
    assert receipt["runtime_cutover_authorized"] is False
    assert receipt["r6_open"] is False


def test_validation_next_lawful_move_receipt(outputs: Path) -> None:
    next_move = _load(outputs / validation.OUTPUTS["next_lawful_move"])
    assert next_move["next_lawful_move"] == validation.NEXT_LAWFUL_MOVE
    assert next_move["expanded_canary_execution_authorized"] is False
    assert next_move["package_promotion_authorized"] is False


def test_validation_binds_all_campaign_order_outputs(outputs: Path) -> None:
    contract = _load(outputs / validation.OUTPUTS["validation_contract"])
    for role, filename in order.OUTPUTS.items():
        assert contract["binding_hashes"][f"{role}_path"] == f"KT_PROD_CLEANROOM/reports/{filename}"
        assert contract["binding_hashes"][f"{role}_hash"]


def test_validation_preserves_campaign_prep_only_boundaries(outputs: Path) -> None:
    receipt = _load(outputs / validation.OUTPUTS["validation_receipt"])
    assert receipt["lobe_activation_authorized"] is False
    assert receipt["adapter_promotion_authorized"] is False
    assert receipt["gpu_training_authorized"] is False
    assert receipt["seven_b_amplification_proven"] is False
    assert "proof_factory_v1" in receipt["post_validation_parallel_prep_tracks"]


def test_validation_rejects_authority_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_order_then_validation(tmp_path, monkeypatch)
    campaign = _load(reports / order.OUTPUTS["campaign_order"])
    campaign["runtime_cutover_authorized"] = True
    _write(reports / order.OUTPUTS["campaign_order"], campaign)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="BOUNDARY_AUTHORITY_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_absolute_prior_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_order_then_validation(tmp_path, monkeypatch)
    campaign = _load(reports / order.OUTPUTS["campaign_order"])
    campaign["prior_bindings"]["canary_evidence_validation_receipt"] = "D:/tmp/receipt.json"
    _write(reports / order.OUTPUTS["campaign_order"], campaign)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="PATH_BINDING_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_ablation_ladder_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_order_then_validation(tmp_path, monkeypatch)
    ablation = _load(reports / order.OUTPUTS["amplification_ablation_plan"])
    ablation["ablation_ladder"] = list(reversed(ablation["ablation_ladder"]))
    _write(reports / order.OUTPUTS["amplification_ablation_plan"], ablation)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="ABLATION_LADDER_DRIFT"):
        validation.run(reports_root=reports)


def test_validation_rejects_missing_campaign_corridor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_order_then_validation(tmp_path, monkeypatch)
    board = _load(reports / order.OUTPUTS["campaign_board"])
    board["corridors"] = [row for row in board["corridors"] if row["corridor"] != "GPU_TRAINING_READINESS"]
    _write(reports / order.OUTPUTS["campaign_board"], board)
    _patch_env(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="BOARD_DRIFT"):
        validation.run(reports_root=reports)


def test_main_validation_requires_head_equal_origin_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reports = _run_order_then_validation(tmp_path, monkeypatch)
    _patch_env(
        monkeypatch,
        tmp_path,
        branch="main",
        head="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        origin_main=MAIN,
    )
    with pytest.raises(RuntimeError, match="HEAD to equal origin/main"):
        validation.run(reports_root=reports)
