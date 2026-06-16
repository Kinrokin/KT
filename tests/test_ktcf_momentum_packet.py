from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def test_ktcf_momentum_imports_assessment_and_reconciles_scorecard() -> None:
    import_receipt = load_json("reports/ktcf_assessment_import_receipt.json")
    reconciliation = load_json("reports/ktcf_scorecard_reconciliation.json")

    assert import_receipt["status"] == "PASS"
    assert import_receipt["assessment_sha256"] == "ef5f7719bb35094eb66a53c6a780a36c5ec2d167577d4896e332ea59c13b247f"
    assert reconciliation["status"] == "PASS"
    assert reconciliation["row_count"] == 40
    assert reconciliation["generation_trial_count"] == 320
    assert reconciliation["oracle_any_correct_rows"] == 35
    assert reconciliation["finalizer_recovered_count"] == 4
    assert reconciliation["finalizer_recovered_scope"] == "NO_CORRECT_ARM_TARGET_ROWS_ONLY"


def test_ktcf_momentum_selects_finalizer_first_preference() -> None:
    owner = load_json("reports/ktcf_owner_action_decision.json")
    finalizer_gate = load_json("reports/ktcf_finalizer_repair_gate.json")
    structured_gate = load_json("reports/ktcf_structured_prompt_gate.json")

    assert owner["status"] == "PASS_SELECTED_FINALIZER_REPAIR"
    assert owner["selected_action"] == "AUTHOR_KTCF_FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_REPAIR_PACKET_V1"
    assert owner["repair_owner"] == "FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_OWNED"
    assert finalizer_gate["status"] == "PASS"
    assert finalizer_gate["selected"] is True
    assert structured_gate["status"] == "PASS_NOT_SELECTED_FIRST_PREFERENCE_FINALIZER"
    assert structured_gate["selected"] is False


def test_ktcf_momentum_packet_shape_and_authority_flags() -> None:
    decision = load_json("reports/ktcf_next_runtime_packet_decision.json")
    summary = load_json("reports/ktcf_momentum_builder_summary.json")
    claim = load_json("reports/ktcf_momentum_claim_boundary_receipt.json")

    assert decision["packet_path"] == "packets/ktcffix_v1.zip"
    assert decision["kaggle_dataset_name"] == "ktcffix-v1"
    assert decision["next_lawful_move"] == "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1"
    assert summary["outcome"] == "KT_KTCF_IMPORTED__FINALIZER_REPAIR_PACKET_READY__CLAIM_CEILING_PRESERVED"
    assert claim["claim_ceiling_status"] == "PRESERVED"

    for field in [
        "runtime_authority",
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
    ]:
        assert decision[field] is False
        assert summary[field] is False
        assert claim[field] is False

    packet = ROOT / decision["packet_path"]
    assert packet.exists()
    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        assert "runtime/KT_CANONICAL_RUNNER.py" in names
        assert "runtime/ktcffix_config.json" in names
        assert "data/counterfactual_row_trial_matrix.jsonl" in names
        assert "KAGGLE_BOOTSTRAP_CELL.py" in names
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8"))
        config = json.loads(zf.read("runtime/ktcffix_config.json").decode("utf-8"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")

    assert manifest["run_mode"] == "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1"
    assert manifest["model_generation_invoked"] is False
    assert config["expected_answers_are_scorer_side_only"] is True
    assert len(config["rows"]) == 40
    assert "AutoModelForCausalLM" not in runner
    assert "PeftModel" not in runner
    assert "KTCFFIX_V1_ASSESSMENT_ONLY.zip" in runner
