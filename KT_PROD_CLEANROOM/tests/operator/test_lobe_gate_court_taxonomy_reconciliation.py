from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as author
from tools.operator import taxonomy_drift_scan


def _copy_inputs(tmp_path: Path) -> None:
    root = author.repo_root()
    required = [
        "registry/artifact_authority_registry.json",
        "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_repair_next_lawful_move.json",
    ]
    for raw in required:
        source = root / raw
        target = tmp_path / raw
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def test_cognitive_lobe_registry_has_13_lobes(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    registry = _load(tmp_path / author.OUTPUTS["cognitive_lobe_registry"])
    lobe_ids = [item["lobe_id"] for item in registry["lobes"]]

    assert len(lobe_ids) == 13
    assert set(lobe_ids) == {lobe_id for lobe_id, _, _ in author.CANONICAL_LOBES}
    assert all(item["training_target"] is True for item in registry["lobes"])
    assert all(item["canonical_lobe"] is True for item in registry["lobes"])
    assert all(item["gate_or_court"] is False for item in registry["lobes"])


def test_no_gate_court_validator_named_as_lobe(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    registry = _load(tmp_path / author.OUTPUTS["cognitive_lobe_registry"])
    lobe_ids = [item["lobe_id"] for item in registry["lobes"]]

    assert not set(lobe_ids).intersection(author.FORBIDDEN_CANONICAL_LOBE_LABELS)
    assert all("gate" not in lobe_id and "validator" not in lobe_id for lobe_id in lobe_ids)


def test_gate_court_validator_registry_separate(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    gate_registry = _load(tmp_path / author.OUTPUTS["gate_registry"])

    component_ids = {component["component_id"] for component in gate_registry["components"]}
    assert "truth_engine" in component_ids
    assert "claim_compiler" in component_ids
    assert "benchmark_court" in component_ids
    assert "bio_med_firewall_gate" in component_ids
    assert all(component["code_authority"] is True for component in gate_registry["components"])
    assert all(component["fail_closed"] is True for component in gate_registry["components"])
    assert all(component["production_claim_allowed"] is False for component in gate_registry["components"])


def test_old_training_labels_map_to_new_taxonomy(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    mapping = _load(tmp_path / author.OUTPUTS["mapping"])
    by_label = {item["source_label"]: item for item in mapping["mappings"]}

    assert by_label["claim_boundary"]["corrected_target"] == "claim_compiler_advisor"
    assert by_label["primitive_invariance"]["corrected_target"] == "primitive_invariance_gate_advisor"
    assert by_label["metacognitive_admission"]["corrected_target"] == "route_admission_advisor"
    assert by_label["router_controller"]["taxonomy_class"] == "ROUTER_LAYER"
    assert by_label["adapter_forge"]["taxonomy_class"] == "TRAINING_FACTORY"
    assert by_label["context_efficiency_lobe"]["corrected_target"] == "context_memory_compression_lobe"
    assert by_label["lobe.auditor.v1"]["taxonomy_class"] == "HISTORICAL_COMPAT_ALIAS"
    assert by_label["lobe.strategist.v1"]["canonical_lobe"] is False


def test_prior_gate_scaffold_adapters_are_advisors_not_lobes(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    mapping = _load(tmp_path / author.OUTPUTS["mapping"])
    advisor_labels = {
        "claim_boundary",
        "truth_grounding",
        "primitive_invariance",
        "metacognitive_admission",
        "runtime_execution_chain",
        "evaluator_integrity",
        "delta_to_primitive",
        "bio_med_firewall",
        "proof_validator",
        "benchmark_evaluator",
        "external_attestation",
        "commercial_boundary",
    }
    by_label = {item["source_label"]: item for item in mapping["mappings"]}
    for label in advisor_labels:
        assert by_label[label]["taxonomy_class"] == "TRAINED_GATE_COURT_EVALUATOR_ADVISOR"
        assert by_label[label]["advisor_only"] is True
        assert by_label[label]["canonical_lobe"] is False


def test_future_kaggle_training_uses_corrected_13_lobe_ids(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    canonical = {lobe_id for lobe_id, _, _ in author.CANONICAL_LOBES}
    lobe_matrix = _load(tmp_path / author.OUTPUTS["lobe_target_matrix"])
    adapter_matrix = _load(tmp_path / author.OUTPUTS["adapter_target_matrix"])

    assert {item["lobe_id"] for item in lobe_matrix["lobes"]} == canonical
    assert len(lobe_matrix["lobes"]) == 13
    assert all(item["parent_lobe"] in canonical for item in adapter_matrix["adapters"])
    assert len(adapter_matrix["adapters"]) == 13


def test_claim_ceiling_preserved(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    receipt = _load(tmp_path / author.OUTPUTS["reconciliation_receipt"])
    for key, expected in author.BLOCKED_CLAIMS.items():
        assert receipt[key] is expected


def test_router_superiority_order_preserved(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    receipt = _load(tmp_path / author.OUTPUTS["reconciliation_receipt"])
    assert receipt["router_superiority_order_preserved"] == [
        "static_baseline",
        "shadow_evaluation",
        "best_static_comparison",
        "learned_router_candidate",
        "statistical_evidence",
        "multi_lobe_orchestration",
    ]
    assert receipt["router_superiority_claim_authorized"] is False


def test_taxonomy_drift_scan_blocks_bad_labels(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    registry_path = tmp_path / author.OUTPUTS["cognitive_lobe_registry"]
    registry = _load(registry_path)
    registry["lobes"][0]["lobe_id"] = "claim_boundary"
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    receipt = taxonomy_drift_scan.scan(root=tmp_path)

    assert receipt["status"] == "FAIL"
    assert any(item["failure_id"] == "canonical_lobe_set_mismatch" for item in receipt["failures"])
    assert any(item["failure_id"] == "gate_court_validator_named_as_lobe" for item in receipt["failures"])


def test_gate_advisor_interface_blocks_pass_fail_authority(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    schema = _load(tmp_path / author.OUTPUTS["advisor_schema"])
    props = schema["properties"]

    assert props["may_authorize_claims"]["const"] is False
    assert props["may_promote_adapters_or_lobes"]["const"] is False
    assert props["may_certify_benchmark_results"]["const"] is False
    assert props["may_override_code_owned_gates"]["const"] is False
    assert props["pass_fail_authority"]["const"] == "CODE_OWNED_SCHEMA_BOUND_RECEIPT_BOUND_FAIL_CLOSED_ONLY"


def test_reconciliation_updates_registry_without_claim_expansion(tmp_path: Path) -> None:
    _copy_inputs(tmp_path)
    author.run(output_root=tmp_path)

    registry = _load(tmp_path / author.OUTPUTS["registry"])
    delta = _load(tmp_path / author.OUTPUTS["registry_delta"])
    artifact_ids = {artifact["artifact_id"] for artifact in registry["artifacts"]}

    assert "KT_COGNITIVE_LOBE_REGISTRY" in artifact_ids
    assert "KT_GATE_COURT_VALIDATOR_REGISTRY" in artifact_ids
    assert "KT_LOBE_GATE_MAPPING" in artifact_ids
    assert "KT_13_LOBE_SUPERLANE_NEXT_LAWFUL_MOVE" in artifact_ids
    assert delta["claim_ceiling_unchanged"] is True
    assert delta["production_commercial_external_superiority_authority_added"] is False
    assert "claim_boundary" in delta["old_labels_reclassified"]
