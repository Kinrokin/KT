from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as author
from tools.operator import verify_13_lobe_tranche_readiness as readiness


def _copy_inputs(tmp_path: Path) -> None:
    root = author.repo_root()
    required = [
        "registry/artifact_authority_registry.json",
        "governance/current_claim_ceiling.json",
        "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_repair_next_lawful_move.json",
        "KT_PROD_CLEANROOM/tools/operator/taxonomy_drift_scan.py",
    ]
    for raw in required:
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _stage(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)
    readiness.run(output_root=tmp_path)


def test_13_lobe_tranche_readiness_emits_config_receipt_and_runbook(tmp_path: Path) -> None:
    _stage(tmp_path)

    config = _load(tmp_path / readiness.CONFIG_PATH)
    receipt = _load(tmp_path / readiness.RECEIPT_PATH)
    runbook = (tmp_path / readiness.RUNBOOK_PATH).read_text(encoding="utf-8")

    assert config["run_mode"] == "RUN_13_LOBE_7B_TRANCHE"
    assert config["target_lobe_ids"] == readiness.CANONICAL_LOBES
    assert config["historical_lobe_labels_allowed_as_targets"] is False
    assert config["advisor_labels_allowed_as_targets"] is False
    assert "head_binding_receipt.json" in config["required_kaggle_outputs"]
    assert "qlora_effectiveness_receipt.json" in config["required_kaggle_outputs"]
    assert receipt["outcome"] == readiness.PASS_OUTCOME
    assert receipt["next_lawful_move"] == "RUN_13_LOBE_7B_TRANCHE"
    assert receipt["blockers"] == []
    assert "The Kaggle runner must train only these 13 cognitive lobes" in runbook


def test_13_lobe_tranche_readiness_blocks_forbidden_training_target(tmp_path: Path) -> None:
    _stage(tmp_path)

    config_path = tmp_path / readiness.CONFIG_PATH
    config = _load(config_path)
    config["target_lobe_ids"][0] = "claim_boundary"
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    receipt = readiness.inspect(tmp_path)

    assert receipt["outcome"] == readiness.BLOCKED_OUTCOME
    assert any(item["failure_id"] == "tranche_config_targets_not_13_canonical" for item in receipt["blockers"])
    assert any(item["failure_id"] == "tranche_config_contains_forbidden_targets" for item in receipt["blockers"])


def test_13_lobe_tranche_readiness_preserves_advisor_authority_boundary(tmp_path: Path) -> None:
    _stage(tmp_path)

    receipt = _load(tmp_path / readiness.RECEIPT_PATH)
    delta = _load(tmp_path / readiness.DELTA_PATH)
    registry = _load(tmp_path / readiness.REGISTRY_PATH)
    artifact_ids = {artifact["artifact_id"] for artifact in registry["artifacts"]}

    assert receipt["advisor_outputs_own_pass_fail_authority"] is False
    assert receipt["code_owned_gates_retain_pass_fail_authority"] is True
    assert receipt["future_kaggle_training_restricted_to_13_lobe_ids"] is True
    assert receipt["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    assert "KT_13_LOBE_7B_TRANCHE_CONFIG" in artifact_ids
    assert "KT_13_LOBE_TRANCHE_READINESS_INSPECTION_RECEIPT" in artifact_ids
