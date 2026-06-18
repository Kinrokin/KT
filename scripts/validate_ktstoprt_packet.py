from __future__ import annotations

import json
import zipfile
from pathlib import Path

from ktstoprt_common import AUTHORITY_FALSE, PACKET_PATH, REPORTS, RUN_MODE, rel, write_json


REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/final_answer_stop.py",
    "runtime/final_answer_stop_types.py",
    "runtime/final_answer_stop_metrics.py",
    "runtime/ktstoprt_config.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstoprt_v1.txt",
}


def assert_false_authorities(payload: dict, label: str) -> None:
    for field in AUTHORITY_FALSE:
        if payload.get(field) is not False:
            raise SystemExit(f"{label}: authority drift in {field}")


def main() -> int:
    if not PACKET_PATH.exists():
        raise SystemExit(f"missing {PACKET_PATH}")
    decision = json.loads((REPORTS / "ktstoprt_next_runtime_packet_decision.json").read_text(encoding="utf-8"))
    if decision["packet_path"] != rel(PACKET_PATH):
        raise SystemExit("packet path mismatch")
    if decision["next_lawful_move"] != RUN_MODE:
        raise SystemExit("wrong next lawful move")
    assert_false_authorities(decision, "decision")
    if decision.get("sandbox_inference_authority") is not True:
        raise SystemExit("sandbox inference authority must be true for generated packet")
    with zipfile.ZipFile(PACKET_PATH) as zf:
        names = set(zf.namelist())
        missing = sorted(REQUIRED_MEMBERS - names)
        if missing:
            raise SystemExit(f"packet missing required members: {missing}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstoprt_config.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        stop_code = zf.read("runtime/final_answer_stop.py").decode("utf-8-sig")
        requirements = zf.read("requirements.txt").decode("utf-8-sig")
    if manifest["run_mode"] != RUN_MODE:
        raise SystemExit("manifest run mode mismatch")
    if manifest["kaggle_dataset_name"] != "ktstoprt-v1":
        raise SystemExit("wrong kaggle dataset name")
    assert_false_authorities(manifest, "manifest")
    if manifest.get("sandbox_inference_authority") is not True:
        raise SystemExit("manifest missing sandbox inference authority")
    if len(config["rows"]) != 10:
        raise SystemExit("runtime config must preserve exact 10 rows")
    if any("expected_answer" in row for row in config["rows"]):
        raise SystemExit("runtime rows leak expected answers")
    arms = config["arm_manifest"]["generation_arms"]
    if {arm["arm_id"] for arm in arms} != {"B0_CURRENT_PROMPT_LEGACY_GENERATION", "B1_CURRENT_PROMPT_FIRST_COMPLETE_FINAL_ANSWER_LINE_STOP"}:
        raise SystemExit("generation arms must be exactly B0/B1")
    if config["arm_manifest"]["offline_derived_arm"]["arm_id"] != "B2_B1_PLUS_CANONICALIZER_V2_REPLAY":
        raise SystemExit("missing B2 offline derived arm")
    if "After writing FINAL_ANSWER, stop immediately" in config["base_prompt_template"]:
        raise SystemExit("failed prompt-only stop instruction leaked into runtime prompt")
    if "StoppingCriteriaList" not in runner or "FirstCompleteFinalAnswerLineStoppingCriteria" not in runner:
        raise SystemExit("runner does not wire runtime stop criteria")
    if "generated_ids = ids[self.prompt_token_count" not in stop_code:
        raise SystemExit("stop code does not slice generated ids only")
    if "batch-size-one only" not in stop_code:
        raise SystemExit("batch-size-one guard missing")
    if "bitsandbytes>=0.46.1" not in requirements:
        raise SystemExit("bitsandbytes dependency gate missing")
    validation = {
        "schema_id": "kt.ktstoprt.packet_validation_receipt.v1",
        "status": "PASS",
        "packet_path": rel(PACKET_PATH),
        "packet_sha256": decision["packet_sha256"],
        "run_mode": RUN_MODE,
        "row_selection_status": "PASS_EXACT_10_ROWS",
        "runtime_stop_criteria_status": "PASS_GENERATED_TOKEN_ONLY_BATCH_SIZE_ONE",
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktstoprt_packet_validation_receipt.json", validation)
    print(json.dumps(validation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
