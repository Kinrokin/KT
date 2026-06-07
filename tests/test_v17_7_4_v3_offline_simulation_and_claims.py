import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
V3_SOURCE_FILES = [
    ROOT / "kt_system" / "eval" / "math_verifier_v3_honest.py",
    ROOT / "kt_system" / "eval" / "math_rescue_v3_honest.py",
    ROOT / "scripts" / "simulate_v17_7_4_control_math_rescue_v3_honest.py",
]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_v3_offline_simulation_is_zero_damage_no_gain_and_no_packet():
    summary = read_json("reports/v17_7_4_control_math_rescue_v3_builder_summary.json")
    sim = read_json("reports/v17_7_4_control_math_rescue_v3_offline_simulation.json")
    damage = read_json("reports/v17_7_4_control_math_rescue_v3_damage_gate_receipt.json")
    epc = read_json("reports/v17_7_4_epc_decision_after_control_math_rescue_v3_honest.json")
    next_lane = read_json("reports/v17_7_4_control_math_rescue_v3_next_lane.json")

    assert summary["outcome"] == "KT_CONTROL_PRESERVING_MATH_RESCUE_V3_HONEST_COMPLETE_SIMULATED__NEXT_LANE_DECIDED__CLAIM_CEILING_PRESERVED"
    assert sim["status"] == "PASS_ZERO_DAMAGE_NO_GAIN"
    assert sim["control_correct_preservation_rate"] == 1.0
    assert sim["false_fail_count"] == 0
    assert sim["damage_to_control_correct"] == 0
    assert sim["net_accuracy_delta"] == 0
    assert sim["runtime_packet_warranted"] is False
    assert damage["runtime_packet_allowed"] is False
    assert epc["epc_option"] == "V3_HONEST_ZERO_DAMAGE_NO_GAIN"
    assert epc["runtime_packet_authorized"] is False
    assert next_lane["packet_path_if_any"] is None


def test_v3_preserves_scratchpad_quarantine_and_evidence_memory():
    predecessor = read_json("reports/v17_7_4_scratchpad_failure_predecessor_receipt.json")
    quarantine = read_json("reports/v17_7_4_scratchpad_runtime_quarantine_receipt.json")
    manifest = read_json("reports/v17_7_4_quarantined_evidence_manifest.json")
    no_mutation = read_json("reports/v17_7_4_no_upstream_mutation_receipt.json")

    assert predecessor["status"] == "PASS"
    assert quarantine["status"] == "PASS"
    assert "A2_math_act_full_reasoning" in quarantine["quarantined_from_runtime"]
    assert manifest["action"] == "QUARANTINE_FROM_RUNTIME_NOT_DELETED"
    assert manifest["preserved_receipts"]
    assert no_mutation["prompt_changes"] is False
    assert no_mutation["adapter_changes"] is False
    assert no_mutation["verifier_runs_after_raw_output"] is True


def test_v3_first_pass_invariance_and_wrapper_hygiene_block_runtime():
    contract = read_json("reports/v17_7_4_first_pass_invariance_contract.json")
    prompt_rows = read_jsonl("reports/v17_7_4_v3_control_prompt_hash_matrix.jsonl")
    wrapper = read_json("reports/v17_7_4_control_math_rescue_v3_wrapper_hygiene_receipt.json")

    assert contract["first_pass_arm"] == "A_true_known_good_math_act_byte_repro"
    assert contract["prompt_mutation_allowed"] is False
    assert contract["rescue_on_abstain_allowed"] is False
    assert len(prompt_rows) == 25
    assert all(row["prompt_mutated"] is False for row in prompt_rows)
    assert wrapper["status"] == "FIX_REQUIRED_RUNTIME_PACKET_BLOCKED"
    assert wrapper["runtime_packet_blocked"] is True


def test_v3_row_table_has_hash_only_expected_answer_boundary():
    rows = read_jsonl("reports/v17_7_4_control_math_rescue_v3_row_table.jsonl")

    assert len(rows) == 25
    assert all(row["expected_answer_model_visible"] is False for row in rows)
    assert all(row["expected_answer_used_by_verifier"] is False for row in rows)
    assert all(row["expected_answer_used_by_rescue"] is False for row in rows)
    assert all("expected_answer" not in row for row in rows)
    assert all(row["raw_output_hash"] for row in rows)


def test_v3_sources_do_not_use_python_process_hash():
    for path in V3_SOURCE_FILES:
        source = path.read_text(encoding="utf-8")
        assert re.search(r"\bhash\s*\(", source) is None
        assert "hashlib.sha256" in source or path.name in {
            "math_verifier_v3_honest.py",
            "math_rescue_v3_honest.py",
        }


def test_v3_claim_ceiling_preserved_everywhere():
    summary = read_json("reports/v17_7_4_control_math_rescue_v3_builder_summary.json")
    claim = read_json("reports/v17_7_4_control_math_rescue_v3_claim_boundary_receipt.json")

    assert summary["claim_ceiling_status"] == "PRESERVED"
    assert summary["adapter_training_authorized"] is False
    assert summary["promotion_authority"] is False
    assert summary["runtime_authority"] is False
    assert claim["status"] == "PASS"
    assert "verifier/rescue performance improvement" in claim["forbidden_claims"]
