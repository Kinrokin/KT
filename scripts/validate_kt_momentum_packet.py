from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "packets" / "ktcffix_v1.zip"
DECISION_PATH = ROOT / "reports" / "ktcf_next_runtime_packet_decision.json"
SUMMARY_PATH = ROOT / "reports" / "ktcf_momentum_builder_summary.json"
VALIDATION_PATH = ROOT / "reports" / "ktcf_momentum_packet_validation_receipt.json"

EXPECTED_PACKET_MEMBERS = {
    "README.md",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "KAGGLE_BOOTSTRAP_CELL.py",
    "requirements.txt",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/ktcffix_config.json",
    "data/counterfactual_row_trial_matrix.jsonl",
    "tests/smoke_test.py",
    "COPY_PASTE_NOW_ktcffix_v1.txt",
}

AUTHORITY_FIELDS = [
    "runtime_authority",
    "training_authority",
    "promotion_authority",
    "selector_deployment_authority",
    "adapter_mutation_authority",
    "production_prompt_mutation_authority",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate() -> dict[str, Any]:
    assert_true(PACKET_PATH.exists(), "packets/ktcffix_v1.zip is missing")
    decision = read_json(DECISION_PATH)
    summary = read_json(SUMMARY_PATH)
    import_receipt = read_json(ROOT / "reports" / "ktcf_assessment_import_receipt.json")
    reconciliation = read_json(ROOT / "reports" / "ktcf_scorecard_reconciliation.json")
    owner = read_json(ROOT / "reports" / "ktcf_owner_action_decision.json")
    finalizer_gate = read_json(ROOT / "reports" / "ktcf_finalizer_repair_gate.json")
    structured_gate = read_json(ROOT / "reports" / "ktcf_structured_prompt_gate.json")
    claim = read_json(ROOT / "reports" / "ktcf_momentum_claim_boundary_receipt.json")

    packet_sha = sha256_file(PACKET_PATH)
    assert_true(decision["packet_sha256"] == packet_sha, "decision packet SHA mismatch")
    assert_true(summary["packet_sha256_if_any"] == packet_sha, "summary packet SHA mismatch")
    assert_true(claim["packet_sha256_if_known"] == packet_sha, "claim boundary packet SHA mismatch")
    assert_true(decision["packet_path"] == "packets/ktcffix_v1.zip", "unexpected packet path")
    assert_true(decision["next_lawful_move"] == "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1", "unexpected next lawful move")
    assert_true(decision["kaggle_dataset_name"] == "ktcffix-v1", "unexpected Kaggle dataset name")
    assert_true(decision["model_generation_invoked"] is False, "KTCFFIX must not invoke generation")

    assert_true(import_receipt["status"] == "PASS", "assessment import must pass")
    assert_true(import_receipt["assessment_sha256"] == "ef5f7719bb35094eb66a53c6a780a36c5ec2d167577d4896e332ea59c13b247f", "assessment SHA mismatch")
    assert_true(reconciliation["status"] == "PASS", "scorecard reconciliation must pass")
    assert_true(reconciliation["generation_trial_count"] == 320, "generation trial count mismatch")
    assert_true(reconciliation["finalizer_recovered_count"] == 4, "finalizer recovered count mismatch")
    assert_true(reconciliation["a6_over_a0_total_delta"] == 2, "A6 total delta mismatch")
    assert_true(reconciliation["a6_over_a0_target_delta"] == 1, "A6 target delta mismatch")
    assert_true(reconciliation["a6_control_correct"] == 14, "A6 control count mismatch")
    assert_true(owner["selected_action"] == "AUTHOR_KTCF_FINALIZER_STOP_SEQUENCE_AND_CANONICALIZER_REPAIR_PACKET_V1", "wrong selected action")
    assert_true(finalizer_gate["status"] == "PASS", "finalizer gate must pass")
    assert_true(finalizer_gate["selected"] is True, "finalizer gate must be selected")
    assert_true(structured_gate["status"] == "PASS_NOT_SELECTED_FIRST_PREFERENCE_FINALIZER", "structured gate must be non-selected pass")

    for field in AUTHORITY_FIELDS:
        assert_true(decision[field] is False, f"{field} must be false in decision")
        assert_true(summary[field] is False, f"{field} must be false in summary")
        assert_true(claim[field] is False, f"{field} must be false in claim")

    with zipfile.ZipFile(PACKET_PATH) as zf:
        names = set(zf.namelist())
        assert_true(EXPECTED_PACKET_MEMBERS <= names, f"packet missing members: {sorted(EXPECTED_PACKET_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8"))
        sha_manifest = json.loads(zf.read("SHA256_MANIFEST.json").decode("utf-8"))
        config = json.loads(zf.read("runtime/ktcffix_config.json").decode("utf-8"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")

        assert_true(manifest["run_mode"] == "RUN_KTCF_FINALIZER_STOP_SEQUENCE_CANONICALIZER_REPAIR_V1", "manifest run mode mismatch")
        assert_true(manifest["model_generation_invoked"] is False, "manifest generation flag must be false")
        assert_true(config["expected_answers_are_scorer_side_only"] is True, "expected answers must be scorer-side only")
        assert_true(len(config["rows"]) == 40, "config row count mismatch")
        assert_true(set(config["scorer_expected_answers"]) == {row["row_id"] for row in config["rows"]}, "scorer answer keyset mismatch")
        assert_true("AutoModelForCausalLM" not in runner, "KTCFFIX runner must not load a model")
        assert_true("PeftModel" not in runner, "KTCFFIX runner must not load adapters")
        assert_true("final_marker_candidates" in runner, "runner must include canonicalizer candidate logic")
        assert_true("KTCFFIX_V1_ASSESSMENT_ONLY.zip" in runner, "runner must emit assessment zip")
        for field in AUTHORITY_FIELDS:
            assert_true(manifest[field] is False, f"{field} must be false in packet manifest")
            assert_true(config[field] is False, f"{field} must be false in packet config")
        for member, expected_sha in sha_manifest["members"].items():
            assert_true(member in names, f"SHA manifest references missing member {member}")
            assert_true(sha256_bytes(zf.read(member)) == expected_sha, f"member SHA mismatch: {member}")

    receipt = {
        "schema_id": "kt.ktcf_momentum.packet_validation_receipt.v1",
        "status": "PASS",
        "packet_path": "packets/ktcffix_v1.zip",
        "packet_sha256": packet_sha,
        "assessment_import_status": "PASS",
        "scorecard_reconciliation_status": "PASS",
        "owner_action_decision_status": "PASS",
        "packet_shape_status": "PASS",
        "authority_flags_status": "PASS_FALSE",
        "claim_ceiling_status": "PRESERVED",
    }
    VALIDATION_PATH.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
