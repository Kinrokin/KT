from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "packets" / "ktcf_v1.zip"
DECISION_PATH = ROOT / "reports" / "ktcf_packet_decision.json"
SUMMARY_PATH = ROOT / "reports" / "ktcf_builder_summary.json"
VALIDATION_RECEIPT_PATH = ROOT / "reports" / "ktcf_packet_validation_receipt.json"

EXPECTED_MEMBERS = {
    "README.md",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "requirements.txt",
    "KAGGLE_BOOTSTRAP_CELL.py",
    "COPY_PASTE_NOW_ktcf_v1.txt",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/ktcf_config.json",
    "tests/smoke_test.py",
}

EXPECTED_ARMS = {
    "A0_FIXED512_BASELINE",
    "A1_FIXED640_SENTINEL",
    "A2_FIXED768_CONTINUATION",
    "A3_FIXED1024_CEILING",
    "A4_EXPLICIT_VARIABLE_COT_512",
    "A5_MINIMAL_PLAIN_COT_512",
    "A6_STRUCTURED_FACT_EQUATION_COT_512",
    "A7_ANSWER_ONLY_NO_COT",
    "A8_FINALIZER_REPLAY_ONLY",
    "A9_ORACLE_DIAGNOSTIC",
}

AUTHORITY_FIELDS = [
    "runtime_authority",
    "dataset_generation_authority",
    "training_authority",
    "promotion_authority",
    "selector_deployment_authority",
    "adapter_mutation_authority",
    "production_prompt_mutation_authority",
]


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate() -> dict[str, Any]:
    assert_true(PACKET_PATH.exists(), "packets/ktcf_v1.zip is missing")
    assert_true(DECISION_PATH.exists(), "reports/ktcf_packet_decision.json is missing")
    assert_true(SUMMARY_PATH.exists(), "reports/ktcf_builder_summary.json is missing")

    decision = read_json(DECISION_PATH)
    summary = read_json(SUMMARY_PATH)
    row_selection = read_json(ROOT / "reports" / "ktcf_row_selection_receipt.json")
    control_matching = read_json(ROOT / "reports" / "ktcf_control_matching_report.json")
    firewall = read_json(ROOT / "reports" / "ktcf_gold_prompt_leakage_firewall_receipt.json")
    feature_legality = read_json(ROOT / "reports" / "ktcf_feature_legality_receipt.json")
    claim_boundary = read_json(ROOT / "reports" / "ktcf_claim_boundary_receipt.json")
    target_rows = read_jsonl(ROOT / "reports" / "ktcf_target_row_manifest.jsonl")
    control_rows = read_jsonl(ROOT / "reports" / "ktcf_control_row_manifest.jsonl")

    packet_sha = sha256_file(PACKET_PATH)
    assert_true(decision["packet_sha256"] == packet_sha, "decision packet SHA mismatch")
    assert_true(summary["packet_sha256_if_any"] == packet_sha, "summary packet SHA mismatch")
    assert_true(claim_boundary["packet_sha256_if_known"] == packet_sha, "claim boundary packet SHA mismatch")
    assert_true(decision["packet_path"] == "packets/ktcf_v1.zip", "unexpected packet path")
    assert_true(decision["kaggle_dataset_name"] == "ktcf-v1", "unexpected Kaggle dataset name")
    assert_true(decision["run_mode"] == "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1", "unexpected run mode")
    assert_true(decision["next_lawful_move"] == "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1", "unexpected next lawful move")

    for field in AUTHORITY_FIELDS:
        assert_true(decision[field] is False, f"{field} must be false in decision")
        assert_true(summary[field] is False, f"{field} must be false in summary")
        assert_true(claim_boundary[field] is False, f"{field} must be false in claim boundary")

    assert_true(row_selection["status"] == "PASS", "row selection must pass")
    assert_true(row_selection["target_rows_unique"] == 26, "unique target rows must be 26")
    assert_true(row_selection["control_rows"] == 14, "control rows must be 14")
    assert_true(row_selection["target_source_class_counts"] == {"COT640_DAMAGE": 2, "COT640_RECOVERY": 4, "FALSE384": 7, "NO_CORRECT_ARM": 14}, "target class counts mismatch")
    assert_true(len(target_rows) == 26, "target manifest row count mismatch")
    assert_true(len(control_rows) == 14, "control manifest row count mismatch")
    assert_true(len({row["row_id"] for row in target_rows}) == 26, "target rows must deduplicate")
    assert_true(not ({row["row_id"] for row in target_rows} & {row["row_id"] for row in control_rows}), "target/control overlap is forbidden")

    source_counts = Counter(source for row in target_rows for source in row["source_classes"])
    assert_true(dict(source_counts) == {"NO_CORRECT_ARM": 14, "FALSE384": 7, "COT640_RECOVERY": 4, "COT640_DAMAGE": 2}, "target manifest class counts mismatch")

    assert_true(control_matching["status"] == "PASS", "control matching must pass")
    assert_true(control_matching["control_count"] == 14, "control matching count must be 14")
    assert_true(firewall["status"] == "PASS", "gold prompt leakage firewall must pass")
    assert_true(firewall["expected_answer_text_never_injected_by_prompt_renderer"] is True, "expected answers must not be injected")
    assert_true(feature_legality["status"] == "PASS", "feature legality must pass")
    assert_true(feature_legality["selector_deployment_authority"] is False, "selector deployment must remain false")
    assert_true("expected_answer" in feature_legality["forbidden_features"], "expected answer must be a forbidden feature")
    assert_true("row_id" in feature_legality["forbidden_features"], "row_id must be a forbidden selector feature")

    with zipfile.ZipFile(PACKET_PATH) as zf:
        names = set(zf.namelist())
        assert_true(EXPECTED_MEMBERS <= names, f"packet missing members: {sorted(EXPECTED_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8"))
        sha_manifest = json.loads(zf.read("SHA256_MANIFEST.json").decode("utf-8"))
        config = json.loads(zf.read("runtime/ktcf_config.json").decode("utf-8"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8")

        assert_true(manifest["run_mode"] == "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1", "packet manifest run mode mismatch")
        assert_true(manifest["target_rows"] == 26, "packet target row count mismatch")
        assert_true(manifest["control_rows"] == 14, "packet control row count mismatch")
        for field in AUTHORITY_FIELDS:
            assert_true(manifest[field] is False, f"{field} must be false in packet manifest")
        for deploy_field in ["deploy_384", "deploy_640", "deploy_768", "deploy_1024", "production_math_mode_claim"]:
            assert_true(manifest[deploy_field] is False, f"{deploy_field} must be false")

        for member, expected_sha in sha_manifest["members"].items():
            assert_true(member in names, f"sha manifest references missing member {member}")
            assert_true(sha256_bytes(zf.read(member)) == expected_sha, f"member SHA mismatch: {member}")

        assert_true(config["expected_answers_are_scorer_side_only"] is True, "expected answers must be scorer-side only")
        assert_true(len([row for row in config["rows"] if row["role"] == "TARGET"]) == 26, "config target row mismatch")
        assert_true(len([row for row in config["rows"] if row["role"] != "TARGET"]) == 14, "config control row mismatch")
        assert_true(set(config["scorer_expected_answers"]) == {row["row_id"] for row in config["rows"]}, "scorer answer keyset mismatch")
        assert_true({arm["arm_id"] for arm in config["arms"]} == EXPECTED_ARMS, "config arm mismatch")
        assert_true(config["claim_boundary"]["selector_deployment_authority"] is False, "config claim boundary selector authority must be false")
        assert_true(config["causal_interpretation_law"]["status"] == "PASS", "causal law must be embedded")
        assert_true("PeftModel" not in runner, "KTCF runner must not load or mutate adapters")
        assert_true("load_in_4bit=True" in runner and "quantization_config" in runner, "runner must use quantization_config 4-bit loading")
        assert_true("checkpoint_state.json" in runner, "runner must support checkpoint/resume")
        assert_true("HF_UPLOAD_RECEIPT.json" in runner, "runner must emit HF upload receipt")
        assert_true("KT_CF_V1_ASSESSMENT_ONLY.zip" in runner, "runner must emit assessment zip")
        assert_true("KT_CANONICAL_RUNNER.py" in bootstrap, "bootstrap must invoke canonical runner")

    receipt = {
        "schema_id": "kt.ktcf.packet_validation_receipt.v1",
        "status": "PASS",
        "packet_path": "packets/ktcf_v1.zip",
        "packet_sha256": packet_sha,
        "packet_shape_status": "PASS",
        "target_control_status": "PASS",
        "no_gold_leakage_status": "PASS",
        "feature_legality_status": "PASS",
        "authority_flags_status": "PASS_FALSE",
        "claim_ceiling_status": "PRESERVED",
    }
    VALIDATION_RECEIPT_PATH.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
