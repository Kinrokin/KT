from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = ROOT / "packets" / "ktpareto_v1.zip"
DECISION_PATH = ROOT / "reports" / "ktpareto_packet_decision.json"
SUMMARY_PATH = ROOT / "reports" / "ktpareto_builder_summary.json"
ROW_POLICY_PATH = ROOT / "reports" / "ktpareto_row_policy_receipt.json"
ARM_MANIFEST_PATH = ROOT / "reports" / "ktpareto_arm_manifest.json"
CLAIM_BOUNDS_PATH = ROOT / "reports" / "ktpareto_per_arm_claim_bounds.json"
CLAIM_BOUNDARY_PATH = ROOT / "reports" / "ktpareto_claim_boundary_receipt.json"
VALIDATION_RECEIPT_PATH = ROOT / "reports" / "ktpareto_packet_validation_receipt.json"

REQUIRED_MEMBERS = {
    "runtime/KT_CANONICAL_RUNNER.py",
    "KAGGLE_BOOTSTRAP_CELL.py",
    "COPY_PASTE_NOW_ktpareto_v1.txt",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "requirements.txt",
    "tests/smoke_test.py",
}

EXPECTED_ARMS = {
    "A0_COT_96_FIXED",
    "A1_COT_192_FIXED",
    "A2_COT_256_FIXED",
    "A3_COT_320_FIXED",
    "A4_COT_384_FIXED",
    "A5_COT_448_FIXED",
    "A6_COT_512_FIXED_CONTROL",
    "A7_COT_640_FIXED_SENTINEL",
    "A8_ANSWER_ONLY_NO_COT",
    "A9_ORACLE_DIAGNOSTIC_PER_ARM",
}

AUTHORITY_FIELDS = [
    "runtime_authority",
    "dataset_generation_authority",
    "training_authority",
    "promotion_authority",
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
    return json.loads(path.read_text(encoding="utf-8"))


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate() -> dict[str, Any]:
    assert_true(PACKET_PATH.exists(), f"missing packet: {PACKET_PATH}")
    assert_true(DECISION_PATH.exists(), f"missing decision: {DECISION_PATH}")
    assert_true(SUMMARY_PATH.exists(), f"missing summary: {SUMMARY_PATH}")

    decision = read_json(DECISION_PATH)
    summary = read_json(SUMMARY_PATH)
    row_policy = read_json(ROW_POLICY_PATH)
    arms = read_json(ARM_MANIFEST_PATH)
    claim_bounds = read_json(CLAIM_BOUNDS_PATH)
    claim_boundary = read_json(CLAIM_BOUNDARY_PATH)

    actual_sha = sha256_file(PACKET_PATH)
    assert_true(decision["packet_sha256"] == actual_sha, "packet sha does not match ktpareto_packet_decision.json")
    assert_true(summary["packet_sha256_if_any"] == actual_sha, "packet sha does not match ktpareto_builder_summary.json")
    assert_true(decision["packet_path"] == "packets/ktpareto_v1.zip", "unexpected packet path")
    assert_true(decision["kaggle_dataset_name"] == "ktpareto-v1", "unexpected Kaggle dataset name")
    assert_true(decision["run_mode"] == "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100", "unexpected run mode")
    assert_true(decision["row_slice"] == "openai/gsm8k:test[325:425]", "unexpected row slice")
    assert_true(decision["next_lawful_move"] == "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100", "unexpected next lawful move")

    for field in AUTHORITY_FIELDS:
        assert_true(decision[field] is False, f"{field} must be false in decision")
        assert_true(summary[field] is False, f"{field} must be false in summary")
        assert_true(claim_boundary[field] is False, f"{field} must be false in claim boundary")

    assert_true(row_policy["slice_start"] == 325, "row slice start must be 325")
    assert_true(row_policy["slice_end"] == 425, "row slice end must be 425")
    assert_true(row_policy["row_count"] == 100, "row count must be 100")
    assert_true(row_policy["overlap_with_bud25"] is False, "BUD25 overlap must be false")
    assert_true(row_policy["overlap_with_bud100"] is False, "BUD100 overlap must be false")
    assert_true(row_policy["overlap_with_kt512base"] is False, "KT512BASE overlap must be false")

    observed_arms = {row["arm_id"] for row in arms["arms"]}
    assert_true(observed_arms == EXPECTED_ARMS, f"arm manifest mismatch: {sorted(observed_arms)}")
    assert_true(arms["fixed512_control_arm"] == "A6_COT_512_FIXED_CONTROL", "fixed512 control arm mismatch")
    assert_true(arms["cot640_sentinel_arm"] == "A7_COT_640_FIXED_SENTINEL", "COT640 sentinel arm mismatch")
    assert_true(arms["oracle_diagnostic_arm"] == "A9_ORACLE_DIAGNOSTIC_PER_ARM", "oracle arm mismatch")

    bound_arms = {row["arm_id"] for row in claim_bounds["rows"]}
    assert_true(bound_arms == EXPECTED_ARMS, "claim bounds must cover every arm")
    for row in claim_bounds["rows"]:
        assert_true(row["promotion_authority"] is False, f"{row['arm_id']} promotion authority must be false")
        assert_true(row["runtime_selector_deployment"] is False, f"{row['arm_id']} selector deployment must be false")

    with zipfile.ZipFile(PACKET_PATH) as zf:
        names = set(zf.namelist())
        assert_true(REQUIRED_MEMBERS <= names, f"packet missing members: {sorted(REQUIRED_MEMBERS - names)}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8"))
        sha_manifest = json.loads(zf.read("SHA256_MANIFEST.json").decode("utf-8"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8")
        bootstrap = zf.read("KAGGLE_BOOTSTRAP_CELL.py").decode("utf-8")

        assert_true(manifest["run_mode"] == "RUN_KT_BUDGET_PARETO_SWEEP_GSM8K_100", "packet manifest run mode mismatch")
        assert_true(manifest["row_slice"] == "openai/gsm8k:test[325:425]", "packet manifest row slice mismatch")
        assert_true(manifest["kaggle_dataset_name"] == "ktpareto-v1", "packet manifest dataset mismatch")
        for field in AUTHORITY_FIELDS:
            assert_true(manifest[field] is False, f"{field} must be false in packet manifest")
        assert_true(manifest["runtime_selector_deployment"] is False, "selector deployment must be false")
        assert_true(manifest["router_superiority_claim"] is False, "router superiority claim must be false")
        assert_true(manifest["frontier_claim"] is False, "frontier claim must be false")

        for member, expected_sha in sha_manifest["members"].items():
            assert_true(member in names, f"sha manifest member missing from zip: {member}")
            assert_true(sha256_bytes(zf.read(member)) == expected_sha, f"member sha mismatch: {member}")

        assert_true("ROW_START = 325" in runner, "runner must bind ROW_START = 325")
        assert_true("ROW_END = 425" in runner, "runner must bind ROW_END = 425")
        assert_true("A6_COT_512_FIXED_CONTROL" in runner, "runner must include fixed512 control")
        assert_true("A7_COT_640_FIXED_SENTINEL" in runner, "runner must include COT640 sentinel")
        assert_true("per_arm_oracle_rows.jsonl" in runner, "runner must emit per-arm oracle rows")
        assert_true("piecewise_linear_elbow_plus_marginal_efficiency" in runner, "runner must include knee detection")
        assert_true("hindsight_only_not_deployable" in runner, "runner must mark oracle as hindsight-only")
        assert_true("training_authority" in runner and "promotion_authority" in runner, "runner must emit authority flags")
        assert_true("KAGGLE_BOOTSTRAP_CELL.py" in bootstrap or "KT_CANONICAL_RUNNER.py" in bootstrap, "bootstrap must invoke canonical runner")

    receipt = {
        "schema_id": "kt.ktpareto.packet_validation_receipt.v1",
        "status": "PASS",
        "packet_path": "packets/ktpareto_v1.zip",
        "packet_sha256": actual_sha,
        "required_members_present": True,
        "sha256_manifest_status": "PASS",
        "row_policy_status": "PASS",
        "authority_flags_status": "PASS_FALSE",
        "claim_ceiling_preserved": True,
    }
    VALIDATION_RECEIPT_PATH.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
