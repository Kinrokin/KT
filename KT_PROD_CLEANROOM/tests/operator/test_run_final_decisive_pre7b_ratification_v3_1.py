from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import run_final_decisive_pre7b_ratification_v3_1 as lane


def _copy_inputs(tmp_path: Path) -> None:
    root = lane.repo_root()
    for raw in sorted(lane.LIVE_INPUTS.values()):
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_final_decisive_lane_emits_target_and_next_move(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    summary = lane.run(output_root=tmp_path)

    assert summary["outcome"] == lane.TARGET_OUTCOME
    assert summary["next_lawful_move"] == "RUN_7B_Q_LORA_SMOKE"
    assert summary["claim_ceiling"] == "unchanged"
    assert summary["blockers"] == []

    scorecard = _load(tmp_path / lane.OUTPUTS["final_scorecard"])
    assert scorecard["all_gates_pass"] is True
    assert scorecard["selected_outcome"] == lane.TARGET_OUTCOME
    assert scorecard["next_lawful_move"] == "RUN_7B_Q_LORA_SMOKE"
    assert scorecard["seven_b_amplification_proven"] is False
    assert scorecard["commercial_claim_authorized"] is False


def test_artifact_authority_registry_controls_only_registered_live_artifacts(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    registry = _load(tmp_path / lane.OUTPUTS["registry"])
    delta = _load(tmp_path / lane.OUTPUTS["registry_delta"])

    assert registry["schema_id"] == "kt.artifact_authority_registry.v3"
    artifact_ids = {artifact["artifact_id"] for artifact in registry["artifacts"]}
    assert "V3_2_CLASS_BALANCED_ARTIFACT" in artifact_ids
    assert "PRIMITIVE_REGISTRY" in artifact_ids
    assert "PROSPECTIVE_METACOGNITION_GATE" in artifact_ids
    assert "FINAL_SCORECARD" in artifact_ids
    assert delta["duplicate_controlling_artifacts"] == []
    assert "governance/artifact_authority_classification.json" in delta["retired_or_superseded_artifacts"]


def test_v3_2_evidence_is_generated_only_when_absent_and_passes_gate_b(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    evidence = _load(tmp_path / lane.OUTPUTS["v3_2_evidence"])

    assert evidence["generated_because_absent"] is True
    assert evidence["import_ready"] is True
    assert evidence["negative_result_count"] == 0
    assert evidence["training_errors_count"] == 0
    assert evidence["class_balance_pass"] is True
    assert evidence["router_no_regression_pass"] is True
    assert evidence["bio_med_firewall_trained"] is True
    assert evidence["seven_b_amplification_proven"] is False


def test_existing_valid_v3_2_evidence_is_validated_not_regenerated(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    existing_path = tmp_path / lane.OUTPUTS["v3_2_evidence"]
    existing_path.parent.mkdir(parents=True, exist_ok=True)
    existing_path.write_text(
        json.dumps(
            {
                "schema_id": "kt.final_pre7b.v3_2_class_balanced_evidence.v1",
                "artifact_id": "KT_V3_2_CLASS_BALANCED_EVIDENCE",
                "import_ready": True,
                "negative_result_count": 0,
                "training_errors_count": 0,
                "class_balance_pass": True,
                "router_no_regression_pass": True,
                "bio_med_firewall_trained": True,
                "seven_b_amplification_proven": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    lane.run(output_root=tmp_path)
    evidence = _load(existing_path)

    assert evidence["validated_by_v3_1_superlane"] is True
    assert "generated_because_absent" not in evidence


def test_invalid_existing_v3_2_evidence_blocks(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    existing_path = tmp_path / lane.OUTPUTS["v3_2_evidence"]
    existing_path.parent.mkdir(parents=True, exist_ok=True)
    existing_path.write_text(
        json.dumps(
            {
                "schema_id": "kt.final_pre7b.v3_2_class_balanced_evidence.v1",
                "artifact_id": "KT_V3_2_CLASS_BALANCED_EVIDENCE",
                "import_ready": True,
                "negative_result_count": 1,
                "training_errors_count": 0,
                "class_balance_pass": True,
                "router_no_regression_pass": True,
                "bio_med_firewall_trained": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="V3.2 class-balanced evidence invalid"):
        lane.run(output_root=tmp_path)


def test_final_gates_emit_required_primitive_metacognitive_and_integrity_artifacts(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)

    lane.run(output_root=tmp_path)
    required = [
        "primitive_registry",
        "primitive_invariance",
        "categorical_boundary",
        "compositional_generalization",
        "metacognition_contract",
        "route_receipt_schema",
        "pd_ed_scorecard",
        "metacognitive_admission",
        "reality_grounding",
        "runtime_execution_chain",
        "evaluator_integrity",
        "delta_to_primitive",
        "adapter_recombination",
        "elevated_smoke",
        "next_move",
    ]
    for key in required:
        assert (tmp_path / lane.OUTPUTS[key]).is_file(), key


def test_claim_ceiling_drift_blocks_final_decisive_lane(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    claim_path = tmp_path / lane.LIVE_INPUTS["claim_ceiling"]
    claim = _load(claim_path)
    claim["commercial_claim_authorized"] = True
    claim_path.write_text(json.dumps(claim, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Claim ceiling drift"):
        lane.run(output_root=tmp_path)
