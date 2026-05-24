
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_LOBES = set(['strategic_synthesis_lobe', 'audit_reasoning_lobe', 'formal_proof_reasoning_lobe', 'contradiction_paradox_lobe', 'temporal_chronology_lobe', 'cross_domain_patterncraft_lobe', 'grounded_evidence_lobe', 'regulated_domain_lobe', 'commercial_operator_lobe', 'execution_tool_lobe', 'context_memory_compression_lobe', 'learning_delta_lobe', 'adversarial_red_assault_lobe'])
FORBIDDEN_AS_LOBES = {"claim_boundary","proof_validator","truth_engine","bio_med_firewall","evaluator_integrity","primitive_invariance","router_control","adapter_forge","lobe_trainer","benchmark_evaluator","external_attestation","commercial_boundary"}

def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8-sig"))

def test_crucible_intensity_matrix():
    m=load("adaptive/crucible_intensity_matrix.json")
    assert m["claim_ceiling_preserved"] is True
    assert m["pressure_items"]
    required=load("adaptive/crucible_intensity_matrix.schema.json")["required_pressure_item_fields"]
    for item in m["pressure_items"]:
        for field in required:
            assert field in item
        assert set(item["target_lobes"]).issubset(ALLOWED_LOBES)

def test_epoch_pressure_schedule():
    s=load("adaptive/epoch_pressure_schedule.json")
    assert s["claim_ceiling_preserved"] is True
    assert s["not_claim_authorizing"] is True
    assert len(s["epochs"]) >= 4

def test_academy_curriculum_registry():
    a=load("adaptive/academy_curriculum_registry.json")
    assert a["claim_ceiling_preserved"] is True
    assert "pressure-to-repair compiler" in a["doctrine"]
    assert a["curriculum_units"]

def test_pressure_item_contracts():
    for item in load("adaptive/crucible_intensity_matrix.json")["pressure_items"]:
        assert item["scoring_contract"]
        assert item["receipt_contract"]
        assert item["expected_output_contract"]

def test_crucible_to_lobe_gate_mapping():
    lm=load("adaptive/crucible_to_lobe_mapping.json")
    gm=load("adaptive/crucible_to_gate_mapping.json")
    assert len(lm["mappings"]) == len(gm["mappings"])
    for row in lm["mappings"]:
        assert set(row["target_lobes"]).issubset(ALLOWED_LOBES)

def test_benchmark_failure_to_crucible_mapping():
    bm=load("adaptive/crucible_to_benchmark_failure_mapping.json")
    assert bm["mappings"]
    assert any("GSM8K" in row["target_benchmarks"] for row in bm["mappings"])

def test_crucible_pressure_preserves_claim_ceiling():
    for rel in ["adaptive/crucible_intensity_matrix.json","adaptive/epoch_pressure_schedule.json","adaptive/academy_curriculum_registry.json"]:
        obj=load(rel)
        assert obj["claim_ceiling_preserved"] is True
        assert obj["commercial_claim_authorized"] is False
        assert obj["external_audit_complete"] is False

def test_crucible_epoch_academy_no_gate_as_lobe():
    for item in load("adaptive/crucible_intensity_matrix.json")["pressure_items"]:
        assert not (FORBIDDEN_AS_LOBES & set(item["target_lobes"]))

def test_pressure_curriculum_generates_receipts():
    assert (ROOT / "tools/operator/build_crucible_pressure_curriculum.py").exists()
    assert (ROOT / "tools/operator/run_crucible_epoch_academy_pressure.py").exists()
    assert (ROOT / "packets/kt13_crucible_epoch_academy_v1/KT13_CRUCIBLE_EPOCH_ACADEMY_V1_RUNNER.py").exists()

def test_red_assault_suite_pressure_pack():
    p=load("adaptive/red_assault_suite_pressure_pack.json")
    assert "cea.red_assault.suite_boundary.v1" in p["pressure_item_ids"]
    assert p["claim_ceiling_preserved"] is True


def test_v2_required_pressure_fields_present():
    m=load("adaptive/crucible_intensity_matrix.json")
    required=set(load("adaptive/crucible_intensity_matrix.schema.json")["required_pressure_item_fields"])
    for item in m["pressure_items"]:
        assert required.issubset(set(item)), sorted(required-set(item))
        assert item["claim_ceiling_risk"] >= 0
        assert isinstance(item["route_regret_relevance"], list)
        assert isinstance(item["scar_delta_relevance"], list)
        assert isinstance(item["benchmark_repair_relevance"], list)

def test_overlay_validator_exists():
    assert (ROOT / "tools/operator/validate_crucible_epoch_academy_overlay.py").exists()

def test_current_status_docs_exist():
    assert (ROOT / "CURRENT_REPO_STATUS_AND_BOUNDARY.md").exists()
    assert (ROOT / "KT_PROD_CLEANROOM/reports/inspection_receipt.json").exists()
