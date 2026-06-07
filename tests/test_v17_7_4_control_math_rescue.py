import json
from pathlib import Path

from scripts.verify_v17_7_4_gsm8k_math_sidecar import verify_gsm8k_math_sidecar


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_control_math_rescue_binds_predecessor_and_preserves_first_pass():
    summary = read_json("reports/v17_7_4_control_math_rescue_builder_summary.json")
    predecessor = read_json("reports/v17_7_4_control_math_rescue_predecessor_binding.json")
    invariance = read_json("reports/v17_7_4_first_pass_invariance_receipt.json")
    contract = read_json("reports/v17_7_4_control_preserving_math_rescue_contract.json")

    assert summary["status"] == "PASS"
    assert predecessor["status"] == "PASS"
    assert invariance["status"] == "PASS"
    assert invariance["first_pass_correct"] == 13
    assert invariance["first_pass_total"] == 25
    assert invariance["prompt_or_adapter_mutation_allowed"] is False
    assert contract["first_pass_arm"] == "A_true_known_good_math_act_byte_repro"
    assert contract["first_pass_mutation_allowed"] is False
    assert contract["runtime_authority"] is False


def test_math_verifier_sidecar_is_deterministic_and_gold_blind():
    clean_row = {
        "sample_id": "x",
        "arm_id": "A_true_known_good_math_act_byte_repro",
        "dataset": "gsm8k",
        "task_family": "formal_math",
        "output_text": "Work: 2 + 2 = 4. Final answer: 4",
        "parsed_answer": "4",
        "visible_answer": "4",
        "parser_format_failure": False,
        "final_answer_marker_present": True,
    }
    echo_row = {
        **clean_row,
        "output_text": "Compact mode: X. Mode rule: Y. Question: What is 2+2? Final: 4",
        "final_answer_marker_present": False,
    }

    clean = verify_gsm8k_math_sidecar(clean_row)
    echo = verify_gsm8k_math_sidecar(echo_row)

    assert clean["verdict"] == "VERIFIER_PASS_FIRST_PASS_INTACT"
    assert clean["expected_answer_used"] is False
    assert clean["model_generation_invoked"] is False
    assert clean["first_pass_mutated"] is False
    assert echo["verdict"] == "ABSTAIN_PROMPT_ECHO_RISK"
    assert echo["rescue_eligible"] is True


def test_control_math_rescue_simulation_does_not_grant_runtime_authority():
    simulation = read_json("reports/v17_7_4_control_math_rescue_offline_simulation.json")
    damage = read_json("reports/v17_7_4_control_math_rescue_damage_rescue_matrix.json")
    epc = read_json("reports/v17_7_4_epc_decision_after_control_math_rescue_design.json")
    next_lane = read_json("reports/v17_7_4_control_math_rescue_next_evidence_lane.json")

    assert simulation["status"] == "PASS_DESIGN_ONLY_NO_RUNTIME_AUTHORITY"
    assert simulation["first_pass_correct_before"] == 13
    assert simulation["simulated_correct_after"] == 13
    assert simulation["first_pass_damage_rows"] == 0
    assert simulation["rescue_executed_rows"] == 0
    assert simulation["model_generation_invoked"] is False
    assert simulation["runtime_authority"] is False
    assert damage["status"] == "PASS_NO_OFFLINE_DAMAGE_NO_EXECUTED_RESCUE"
    assert damage["runtime_rescue_authority"] is False
    assert epc["runtime_packet_authorized"] is False
    assert next_lane["packet_path_if_any"] is None


def test_control_math_rescue_outputs_row_tables_and_policy_boundaries():
    rows = read_jsonl("reports/v17_7_4_control_math_rescue_row_table.jsonl")
    scorer = read_jsonl("reports/v17_7_4_control_math_rescue_scorer_disagreement_table.jsonl")
    policy = read_json("reports/v17_7_4_math_rescue_policy_design.json")
    audit = read_json("reports/v17_7_4_control_math_rescue_answer_surface_audit.json")
    sidecar = read_json("reports/v17_7_4_math_verifier_sidecar_design.json")

    assert len(rows) == 25
    assert len(scorer) == 25
    assert all(row["first_pass_mutated"] is False for row in rows)
    assert all(row["expected_answer_used_by_sidecar"] is False for row in rows)
    assert policy["first_pass_preserved"] is True
    assert policy["rescue_for_control_correct_rows"] is False
    assert policy["training_authorized"] is False
    assert audit["visible_tpc_not_full_tpc"] is True
    assert sidecar["expected_answer_used"] is False
