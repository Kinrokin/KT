from __future__ import annotations

import json
import zipfile

from ktstop50_common import (
    KAGGLE_DATASET_NAME,
    PACKET_PATH,
    REPORTS,
    RUN_MODE,
    SCHEMAS,
    authority_payload,
    read_json,
    rel,
    sha256_file,
    write_json,
)


REQUIRED_MEMBERS = {
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/environment_preflight.py",
    "runtime/effective_config_receipt.py",
    "runtime/paired_timing.py",
    "runtime/final_answer_stop.py",
    "runtime/final_answer_stop_types.py",
    "runtime/final_answer_stop_metrics.py",
    "runtime/ktstop50_config.json",
    "requirements.txt",
    "tests/smoke_test.py",
}


def main() -> int:
    if not PACKET_PATH.exists():
        raise SystemExit(f"missing packet: {PACKET_PATH}")
    with zipfile.ZipFile(PACKET_PATH) as zf:
        members = set(zf.namelist())
        missing = sorted(REQUIRED_MEMBERS - members)
        if missing:
            raise SystemExit(f"packet missing required members: {missing}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop50_config.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        stop_source = zf.read("runtime/final_answer_stop.py").decode("utf-8-sig")
        requirements = zf.read("requirements.txt").decode("utf-8-sig")

    errors: list[str] = []
    if manifest.get("run_mode") != RUN_MODE:
        errors.append("run mode mismatch")
    if manifest.get("kaggle_dataset_name") != KAGGLE_DATASET_NAME:
        errors.append("dataset name mismatch")
    if manifest.get("row_count") != 50:
        errors.append("row count mismatch")
    if manifest.get("production_runtime_authority", manifest.get("runtime_authority")):
        errors.append("runtime/production authority must remain false")
    for key in [
        "training_authority",
        "promotion_authority",
        "selector_deployment_authority",
        "adapter_mutation_authority",
        "production_prompt_mutation_authority",
        "production_math_mode_claim",
    ]:
        if manifest.get(key):
            errors.append(f"{key} must remain false")
    rows = config.get("rows", [])
    if len(rows) != 50:
        errors.append("config rows must equal 50")
    expected_ids = [f"gsm8k_test_{idx}" for idx in range(425, 475)]
    if [row.get("row_id") for row in rows] != expected_ids:
        errors.append("row ids must be GSM8K test[425:475]")
    if any(row.get("expected_answer") for row in rows):
        errors.append("expected answers must not be embedded in packet rows")
    if "BitsAndBytesConfig" in runner:
        errors.append("runner must not pass runtime BitsAndBytesConfig for embedded 4-bit model")
    if "AutoModelForCausalLM.from_pretrained" not in runner:
        errors.append("runner must use AutoModelForCausalLM.from_pretrained")
    if "^[ \\t]*\" + re.escape(marker)" not in stop_source:
        errors.append("stop detector must use line-anchored marker matching")
    if "batch-size-one only" not in stop_source:
        errors.append("stop detector must fail closed on batch size greater than one")
    if "bitsandbytes==0.49.2" not in requirements:
        errors.append("requirements must bind bitsandbytes==0.49.2")

    row_policy = read_json(REPORTS / "ktstop50_row_policy.json")
    if row_policy.get("overlap_with_prior_rows") != 0:
        errors.append("row policy overlaps prior rows")
    env = read_json(REPORTS / "ktstop50_environment_contract.json")
    if env.get("runtime_packet_fails_closed_if_unmet") is not True:
        errors.append("environment contract must fail closed")
    protocol = read_json(REPORTS / "ktstop50_experiment_protocol.json")
    if protocol.get("randomized_synchronized_paired_timing") is not True or protocol.get("batch_size") != 1:
        errors.append("paired timing protocol must be randomized, synchronized, and batch size one")
    if not (SCHEMAS / "kt.stop50.environment_contract.schema.json").exists():
        errors.append("environment schema missing")

    receipt = {
        "schema_id": "kt.stop50.packet_validation_receipt.v1",
        "status": "PASS" if not errors else "FAIL",
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": sha256_file(PACKET_PATH),
        "required_members_present": sorted(REQUIRED_MEMBERS),
        "errors": errors,
        **authority_payload(),
    }
    write_json(REPORTS / "ktstop50_packet_validation_receipt.json", receipt)
    if errors:
        raise SystemExit("KTSTOP50 packet validation failed: " + "; ".join(errors))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
