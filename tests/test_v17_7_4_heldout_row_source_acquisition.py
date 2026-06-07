import json
import zipfile

from runtime.v17_7_4 import KT_V1774_TRUEGEN_ARM_CORE as core
from scripts import build_v17_7_4_heldout_row_source_acquisition as builder


def load_manifest():
    if not builder.HELDOUT_MANIFEST.exists():
        assert builder.main() == 0
    return builder.read_json(builder.HELDOUT_MANIFEST)


def test_heldout_rows_bind_nonoverlapping_public_benchmark_source():
    manifest = load_manifest()
    rows = manifest["rows"]
    control_rows = builder.control_rows()

    assert manifest["status"] == "BOUND"
    assert manifest["row_count"] == 50
    assert manifest["dataset_mix"] == {"arc_challenge": 15, "gsm8k": 20, "hellaswag": 15}
    assert builder.row_id_set(rows).isdisjoint(builder.row_id_set(control_rows))
    assert builder.question_hash_set(rows).isdisjoint(builder.question_hash_set(control_rows))
    assert builder.duplicate_surface_count(rows) == 0
    assert all(row["label_source"] == "PUBLIC_BENCHMARK_GROUND_TRUTH" for row in rows)
    assert all(row["holdout_status"] == "HELDOUT_NOT_FOR_PROMOTION" for row in rows)
    assert all(row["expected_answer_hash"] for row in rows)


def test_expected_answers_are_scorer_only_not_model_visible():
    manifest = load_manifest()
    config = builder.generalization_config()
    arm = core.reprolock_arm(config)

    for row in manifest["rows"]:
        prompt = core.materialize_prompt(row, arm)
        expected = core.expected_answer_for_row(row)
        assert expected
        assert f"expected answer: {expected}".lower() not in prompt.lower()
        assert f"correct answer: {expected}".lower() not in prompt.lower()
        assert f"#### {expected}" not in prompt
        assert row["expected_answer_visible_to_model"] is False


def test_generalization_config_preserves_single_byte_locked_reprolock_arm():
    config = builder.generalization_config()
    arms = config["arms"]

    assert config["measurement_mode"] == core.REPROLOCK_MODE
    assert config["shuffle_control_required"] is False
    assert config["heldout_source_required"] is True
    assert config["prompt_template_mutation_allowed"] is False
    assert [arm["arm_id"] for arm in arms] == [core.REPROLOCK_ARM_ID]
    assert arms[0]["reproduction_mode"] == core.TRUE_KNOWN_GOOD_BYTE_REPRO
    assert arms[0]["finalizer_intervention_disabled"] is True
    assert arms[0]["kt_hat_scaffold_disabled"] is True
    assert arms[0]["route_admission_disabled"] is True


def test_binding_receipts_authorize_generalization_packet_only_after_source_bound():
    manifest = load_manifest()
    receipts = builder.binding_receipts(manifest["rows"], manifest)
    court = receipts["v17_7_4_heldout_row_binding_court.json"]
    answer = receipts["v17_7_4_heldout_row_answer_key_authority_receipt.json"]

    assert court["status"] == "BOUND"
    assert court["row_ids_overlap_known_good"] is False
    assert court["question_hashes_overlap_known_good"] is False
    assert court["expected_answer_model_visible"] is False
    assert court["raw_outputs_saved_in_runtime_packet"] is True
    assert answer["status"] == "PASS"
    assert answer["answer_key_authority"] == "PUBLIC_BENCHMARK_GROUND_TRUTH_SCORER_ONLY"


def test_builder_creates_generalization_packet_with_reprolock_contract():
    assert builder.main() == 0

    summary = builder.read_json(builder.ROOT / "reports" / "v17_7_4_heldout_row_source_acquisition_builder_summary.json")
    assert summary["outcome"] == builder.OUTCOME
    assert summary["heldout_row_source_binding_status"] == "BOUND"
    assert summary["generalization_packet_status"] == "PASS"
    assert summary["extension_packet_status"] == "NOT_GENERATED_HELDOUT_50_SOURCE_BOUND"
    assert summary["next_lawful_move"] == "RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_PACKET"
    assert summary["claim_ceiling_status"] == "PRESERVED"

    with zipfile.ZipFile(builder.PACKET_PATH) as archive:
        names = set(archive.namelist())
        run_manifest = json.loads(archive.read("run_manifest.json"))
        row_manifest = json.loads(archive.read("runtime_inputs/truegen_row_manifest.json"))
        config = json.loads(archive.read("runtime_inputs/arm_model_config.json"))

    assert "KTV1774_REPROLOCK_GENERALIZATION_PROBE_RUNNER.py" in names
    assert "KT_V1774_TRUEGEN_ARM_CORE.py" in names
    assert "runtime_inputs/prior_realbench_math_act_prompt_manifest.jsonl" in names
    assert "runtime_inputs/answer_leakage_scan_plan.json" in names
    assert "runtime_inputs/negative_control_plan.json" in names
    assert run_manifest["run_mode"] == builder.RUN_MODE
    assert row_manifest["row_count"] == 50
    assert row_manifest["heldout_from_control_slice"] is True
    assert row_manifest["heldout_generalization_claim"] is False
    assert config["arms"][0]["arm_id"] == core.REPROLOCK_ARM_ID
