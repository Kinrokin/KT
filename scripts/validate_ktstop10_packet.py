from __future__ import annotations

import json
import zipfile
from pathlib import Path


PACKET = Path("packets/ktstop10_v1.zip")
REQUIRED_MEMBERS = {
    "KAGGLE_BOOTSTRAP_CELL.py",
    "runtime/KT_CANONICAL_RUNNER.py",
    "runtime/ktstop10_config.json",
    "requirements.txt",
    "tests/smoke_test.py",
    "PACKET_MANIFEST.json",
    "SHA256_MANIFEST.json",
    "README.md",
    "COPY_PASTE_NOW_ktstop10_v1.txt",
}
AUTHORITY_FIELDS = [
    "runtime_authority",
    "dataset_generation_authority",
    "training_authority",
    "promotion_authority",
    "selector_deployment_authority",
    "adapter_mutation_authority",
    "production_prompt_mutation_authority",
    "production_math_mode_claim",
]


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def assert_false_authorities(payload: dict, label: str) -> None:
    for field in AUTHORITY_FIELDS:
        if payload.get(field) is not False:
            raise SystemExit(f"{label}: authority drift in {field}")


def main() -> int:
    if not PACKET.exists():
        raise SystemExit(f"missing {PACKET}")
    decision = load(Path("reports/ktstop10_runtime_packet_decision.json"))
    if decision.get("packet_path") != PACKET.as_posix():
        raise SystemExit("packet decision path mismatch")
    if decision.get("packet_sha256") is None:
        raise SystemExit("packet decision missing sha256")
    if decision.get("next_lawful_move") != "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1":
        raise SystemExit("wrong next lawful move")
    assert_false_authorities(decision, "decision")

    with zipfile.ZipFile(PACKET) as zf:
        names = set(zf.namelist())
        missing = sorted(REQUIRED_MEMBERS - names)
        if missing:
            raise SystemExit(f"packet missing required files: {missing}")
        manifest = json.loads(zf.read("PACKET_MANIFEST.json").decode("utf-8-sig"))
        config = json.loads(zf.read("runtime/ktstop10_config.json").decode("utf-8-sig"))
        sha_manifest = json.loads(zf.read("SHA256_MANIFEST.json").decode("utf-8-sig"))
        runner = zf.read("runtime/KT_CANONICAL_RUNNER.py").decode("utf-8-sig")
        requirements = zf.read("requirements.txt").decode("utf-8-sig")

    if manifest.get("run_mode") != "RUN_STOPSEQ_10ROW_PROMPT_PROBE_V1":
        raise SystemExit("wrong packet run mode")
    if manifest.get("kaggle_dataset_name") != "ktstop10-v1":
        raise SystemExit("wrong kaggle dataset name")
    assert_false_authorities(manifest, "manifest")

    rows = config.get("rows", [])
    if len(rows) != 10:
        raise SystemExit("runtime config must contain exactly 10 rows")
    bucket_counts = {}
    for row in rows:
        bucket_counts[row["row_bucket"]] = bucket_counts.get(row["row_bucket"], 0) + 1
        if "expected_answer" in row:
            raise SystemExit("runtime row leaks expected_answer")
        if not row.get("question") or not row.get("expected_answer_hash"):
            raise SystemExit("runtime row missing question or expected_answer_hash")
    if bucket_counts != {
        "NO_CORRECT_OR_CANONICALIZER_RELEVANT": 4,
        "POST_FINAL_TRAILER_CONTAMINATION": 4,
        "FIXED512_CORRECT_CONTROL": 2,
    }:
        raise SystemExit(f"unexpected row bucket counts: {bucket_counts}")

    arms = config.get("prompt_arm_manifest", {}).get("arms", [])
    if {arm.get("arm_id") for arm in arms} != {"A0_CURRENT_PROMPT", "A1_STOP_AFTER_FINAL_ANSWER"}:
        raise SystemExit("prompt arms must be exactly A0/A1")
    prompt_text = "\n".join(arm["template_text"] for arm in arms)
    for forbidden in ["expected_answer", "expected_answer_hash", "row_id", "source_class", "measured_correctness"]:
        if forbidden in prompt_text:
            raise SystemExit(f"prompt template contains forbidden field name {forbidden}")
    if "After writing FINAL_ANSWER, stop immediately." not in prompt_text:
        raise SystemExit("A1 stop instruction missing")
    if config.get("expected_answers_are_scorer_side_only") is not True:
        raise SystemExit("expected answers must be scorer-side only")
    if set(config.get("scorer_expected_answers", {})) != {row["row_id"] for row in rows}:
        raise SystemExit("scorer expected answers must match selected rows")

    if "bitsandbytes>=0.46.1" not in requirements:
        raise SystemExit("bitsandbytes dependency gate missing")
    if "BitsAndBytesConfig" not in runner or "quantization_config" not in runner:
        raise SystemExit("runner must use BitsAndBytesConfig via quantization_config")
    if "load_in_4bit" not in runner:
        raise SystemExit("runner must expose 4-bit config")
    if sorted(sha_manifest.get("members", {})) != sorted(name for name in REQUIRED_MEMBERS if name != "SHA256_MANIFEST.json"):
        raise SystemExit("SHA manifest member set mismatch")

    receipt_paths = [
        "reports/ktstop10_truth_pin.json",
        "reports/ktstop10_predecessor_binding_receipt.json",
        "reports/ktstop10_row_selection_binding.json",
        "reports/ktstop10_prompt_arm_manifest.json",
        "reports/ktstop10_gold_prompt_leakage_firewall.json",
        "reports/ktstop10_claim_boundary_receipt.json",
    ]
    for path in receipt_paths:
        data = load(Path(path))
        if data.get("claim_ceiling_status") != "PRESERVED":
            raise SystemExit(f"{path}: claim ceiling drift")
        assert_false_authorities(data, path)

    validation = {
        "schema_id": "kt.ktstop10.packet_validation_receipt.v1",
        "status": "PASS",
        "packet_path": PACKET.as_posix(),
        "packet_sha256": decision["packet_sha256"],
        "row_selection_status": "PASS_EXACT_10_ROWS",
        "prompt_arm_manifest_status": "PASS",
        "gold_prompt_leakage_firewall_status": "PASS",
        "claim_ceiling_status": "PRESERVED",
    }
    Path("reports/ktstop10_packet_validation_receipt.json").write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(validation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
