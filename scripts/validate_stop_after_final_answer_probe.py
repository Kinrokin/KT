from __future__ import annotations

import json
from pathlib import Path


REPORTS = Path("reports")
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
    required = [
        REPORTS / "ktstop_truth_pin.json",
        REPORTS / "ktstop_cffix_hash_lock_receipt.json",
        REPORTS / "ktstop_10row_selection.json",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit(f"missing required KTSTOP receipts: {missing}")

    truth = load(REPORTS / "ktstop_truth_pin.json")
    hash_lock = load(REPORTS / "ktstop_cffix_hash_lock_receipt.json")
    selection = load(REPORTS / "ktstop_10row_selection.json")
    for label, payload in [("truth", truth), ("hash_lock", hash_lock), ("selection", selection)]:
        if payload.get("claim_ceiling_status") != "PRESERVED":
            raise SystemExit(f"{label}: claim ceiling drift")
        assert_false_authorities(payload, label)

    if hash_lock.get("patch_authority_from_old_cffix") is not False:
        raise SystemExit("old CFFIX patch authority must be blocked")

    rows = selection.get("rows", [])
    if selection.get("status") != "PASS" or selection.get("row_count") != 10 or len(rows) != 10:
        raise SystemExit("KTSTOP row selection must contain exactly 10 rows")
    if not all(row.get("gold_prompt_leakage_free") is True for row in rows):
        raise SystemExit("gold prompt leakage flag must be true for every selected row")
    if not all(row.get("expected_answer_hash") and not row.get("expected_answer") for row in rows):
        raise SystemExit("selection rows must bind expected_answer_hash without model-visible expected answer")

    probe = REPORTS / "stop_after_final_answer_10row_probe.json"
    blocker = REPORTS / "stop_after_final_answer_probe_blocker.json"
    patch = REPORTS / "stop_after_final_answer_patch_receipt.json"
    if blocker.exists():
        data = load(blocker)
        if data.get("status") != "BLOCKED_LOCAL_MODEL_RUNTIME_UNAVAILABLE__STOPSEQ_PROBE_HARNESS_READY":
            raise SystemExit("unexpected KTSTOP blocker status")
        if data.get("prompt_delta_committed") is not False:
            raise SystemExit("blocked KTSTOP run cannot commit prompt delta")
        assert_false_authorities(data, "blocker")
    elif probe.exists():
        data = load(probe)
        if data.get("control_damage_count") != 0:
            raise SystemExit("control damage detected")
        if data.get("pass_gate") is True and data.get("a1_correct", 0) < data.get("a0_correct", 0):
            raise SystemExit("passing probe cannot reduce correctness")
        if data.get("pass_gate") is True and not patch.exists():
            raise SystemExit("passing probe must emit patch receipt")
    else:
        raise SystemExit("missing probe result or blocker receipt")

    summary = REPORTS / "ktstop_lab_summary.json"
    if summary.exists():
        data = load(summary)
        if data.get("claim_ceiling_status") != "PRESERVED":
            raise SystemExit("summary claim ceiling drift")
        assert_false_authorities(data, "summary")

    print("ktstop_validation_pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
