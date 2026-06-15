from __future__ import annotations

import json
import zipfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8-sig"))


def read_jsonl(path: str):
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def test_ktcf_binds_g32s_predecessor_and_next_lane() -> None:
    summary = load_json("reports/ktcf_builder_summary.json")
    predecessor = load_json("reports/ktcf_predecessor_binding_receipt.json")

    assert summary["outcome"] == "KT_COUNTERFACTUAL_MICROFURNACE_PACKET_READY__STRATIFIED_FAILURE_COURTS_BOUND__CLAIM_CEILING_PRESERVED"
    assert summary["next_lawful_move"] == "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1"
    assert predecessor["status"] == "PASS"
    assert predecessor["g32s_outcome"] == "KT_G32_STRATIFIED_FIXED512_FAILURES_OWNED__COUNTERFACTUAL_COURTS_BOUND__DIFFICULTY_AWARE_SELECTOR_SEED_READY__CLAIM_CEILING_PRESERVED"


def test_ktcf_row_selection_and_controls_are_exact() -> None:
    selection = load_json("reports/ktcf_row_selection_receipt.json")
    targets = read_jsonl("reports/ktcf_target_row_manifest.jsonl")
    controls = read_jsonl("reports/ktcf_control_row_manifest.jsonl")
    matching = load_json("reports/ktcf_control_matching_report.json")

    assert selection["status"] == "PASS"
    assert selection["target_rows_unique"] == 26
    assert selection["control_rows"] == 14
    assert len(targets) == 26
    assert len(controls) == 14
    assert {row["row_id"] for row in targets}.isdisjoint({row["row_id"] for row in controls})
    assert matching["status"] == "PASS"
    assert matching["control_count"] == 14

    counts = Counter(source for row in targets for source in row["source_classes"])
    assert counts["NO_CORRECT_ARM"] == 14
    assert counts["FALSE384"] == 7
    assert counts["COT640_RECOVERY"] == 4
    assert counts["COT640_DAMAGE"] == 2


def test_ktcf_gold_firewall_and_feature_legality_are_strict() -> None:
    firewall = load_json("reports/ktcf_gold_prompt_leakage_firewall_receipt.json")
    feature = load_json("reports/ktcf_feature_legality_receipt.json")
    prompt = load_json("configs/ktcf_prompt_templates.json")

    assert firewall["status"] == "PASS"
    assert firewall["prompt_rendering_source_fields"] == ["question"]
    assert firewall["expected_answer_text_never_injected_by_prompt_renderer"] is True
    assert firewall["oracle_diagnostic_report_only"] is True
    assert feature["status"] == "PASS"
    assert feature["selector_deployment_authority"] is False
    assert "expected_answer" in feature["forbidden_features"]
    assert "measured_arm_correctness" in feature["forbidden_features"]
    assert all(row["contains_final_answer_marker"] for row in prompt["templates"])


def test_ktcf_packet_shape_and_authorities() -> None:
    decision = load_json("reports/ktcf_packet_decision.json")
    packet = ROOT / decision["packet_path"]
    assert packet.exists()

    with zipfile.ZipFile(packet) as zf:
        names = set(zf.namelist())
        assert "runtime/KT_CANONICAL_RUNNER.py" in names
        assert "runtime/ktcf_config.json" in names
        assert "KAGGLE_BOOTSTRAP_CELL.py" in names
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8"))
        config = json.loads(zf.read("runtime/ktcf_config.json").decode("utf-8"))

    assert manifest["run_mode"] == "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1"
    assert manifest["training_authority"] is False
    assert manifest["promotion_authority"] is False
    assert manifest["selector_deployment_authority"] is False
    assert manifest["deploy_384"] is False
    assert manifest["deploy_640"] is False
    assert manifest["deploy_768"] is False
    assert manifest["deploy_1024"] is False
    assert config["expected_answers_are_scorer_side_only"] is True
    assert len([row for row in config["rows"] if row["role"] == "TARGET"]) == 26
    assert len([row for row in config["rows"] if row["role"] != "TARGET"]) == 14
    assert "A9_ORACLE_DIAGNOSTIC" in {arm["arm_id"] for arm in config["arms"]}
