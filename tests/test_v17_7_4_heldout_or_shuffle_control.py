import json
import zipfile

from scripts import build_v17_7_4_heldout_or_shuffle_control_packet as builder


def test_unbound_heldout_source_selects_shuffle_control_not_generalization():
    search, binding, candidate, missing = builder.search_heldout_sources()
    decision = builder.branch_decision(search)

    if builder.BOUND_HELDOUT_MANIFEST.exists():
        assert search["status"] == "BOUND"
        assert binding["status"] == "BOUND"
        assert decision["selected_branch"] == "HELDOUT_GENERALIZATION_PACKET"
        assert decision["heldout_packet_authorized"] is True
        assert decision["shuffle_control_packet_authorized"] is False
    else:
        assert search["status"] == "NOT_BOUND_WITH_SEARCH_RECEIPT"
        assert binding["status"] == "NOT_BOUND_WITH_SEARCH_RECEIPT"
        assert candidate["heldout_generalization_claim"] is False
        assert missing["action"] == "GENERATE_SHUFFLE_CONTROL_INSTEAD"
        assert decision["selected_branch"] == "SHUFFLE_CONTROL_PACKET"
        assert decision["heldout_packet_authorized"] is False
        assert decision["shuffle_control_packet_authorized"] is True


def test_shuffle_manifest_preserves_rows_but_changes_order_and_blocks_heldout_claim():
    manifest, order_manifest = builder.build_shuffle_row_manifest()
    source_rows = builder.read_json(builder.REALBENCH_MANIFEST)["rows"]

    source_ids = [str(row["sample_id"]) for row in source_rows]
    shuffled_ids = [str(row["sample_id"]) for row in manifest["rows"]]

    assert manifest["row_count"] == 50
    assert sorted(shuffled_ids) == sorted(source_ids)
    assert shuffled_ids != source_ids
    assert manifest["heldout_generalization_claim"] is False
    assert manifest["control_test_type"] == "ROW_ORDER_SHUFFLE_CONTROL_NOT_HELDOUT_GENERALIZATION"
    assert order_manifest["not_heldout_generalization"] is True
    assert order_manifest["row_order_changed"] is True


def test_shuffle_config_preserves_known_good_control_only():
    config = builder.reprolock_config()
    arms = config["arms"]

    assert [arm["arm_id"] for arm in arms] == ["A_true_known_good_math_act_byte_repro"]
    assert arms[0]["adapter_id"] == "math_act_adapter_global"
    assert arms[0]["finalizer_intervention_disabled"] is True
    assert arms[0]["kt_hat_scaffold_disabled"] is True
    assert arms[0]["route_admission_disabled"] is True
    assert config["known_good_control_preserved"] is True


def test_leakage_and_negative_control_plans_are_fail_closed():
    leakage = builder.answer_leakage_scan_plan("shuffle")
    negative = builder.negative_control_plan("shuffle")

    assert leakage["status"] == "PASS_PLAN_RUNTIME_REQUIRED"
    assert "gold_answer" in leakage["forbidden_model_visible_fields"]
    assert "expected_answer" in leakage["forbidden_model_visible_fields"]
    assert leakage["model_input_excludes_expected_answer"] is True
    assert negative["status"] == "PASS_PLAN_RUNTIME_REQUIRED"
    assert negative["any_negative_control_scored_as_success_blocks"] is True
    assert negative["negative_controls"][0]["expected_outcome"] == "FAIL_CLOSED"


def test_builder_creates_shuffle_packet_with_runtime_contract(tmp_path, monkeypatch):
    monkeypatch.chdir(builder.ROOT)
    assert builder.main() == 0

    if builder.BOUND_HELDOUT_MANIFEST.exists():
        from scripts import build_v17_7_4_heldout_row_source_acquisition as acquisition

        assert acquisition.PACKET_PATH.exists()
        summary = acquisition.read_json(acquisition.ROOT / "reports" / "v17_7_4_heldout_row_source_acquisition_builder_summary.json")
        assert summary["generalization_packet_status"] == "PASS"
        assert summary["next_lawful_move"] == "RUN_KTV1774_REPROLOCK_GENERALIZATION_PROBE_PACKET"
        return

    assert builder.SHUFFLE_PACKET_PATH.exists()
    with zipfile.ZipFile(builder.SHUFFLE_PACKET_PATH) as archive:
        names = set(archive.namelist())
        run_manifest = json.loads(archive.read("run_manifest.json"))
        row_manifest = json.loads(archive.read("runtime_inputs/truegen_row_manifest.json"))

    assert "KTV1774_REPROLOCK_SHUFFLE_CONTROL_RUNNER.py" in names
    assert "runtime_inputs/answer_leakage_scan_plan.json" in names
    assert "runtime_inputs/negative_control_plan.json" in names
    assert "runtime_inputs/adversarial_telemetry_contract.json" in names
    assert run_manifest["run_mode"] == builder.SHUFFLE_RUN_MODE
    assert run_manifest["not_heldout_generalization"] is True
    assert row_manifest["control_test_type"] == "ROW_ORDER_SHUFFLE_CONTROL_NOT_HELDOUT_GENERALIZATION"
    assert row_manifest["heldout_generalization_claim"] is False
