from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.w4_truth_common import (
    ACTUAL_CATEGORY,
    BENCHMARK_CONSTITUTION_REL,
    COMPARATOR_REGISTRY_REL,
    NEGATIVE_LEDGER_REL,
    TRUTH_LOCK_REL,
    USEFUL_OUTPUT_BENCHMARK_REL,
    benchmark_required_fields,
    build_benchmark_negative_result_ledger,
)


DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/benchmark_constitution_receipt.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _field_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def build_receipt(*, root: Path, negative_ledger: Dict[str, Any]) -> Dict[str, Any]:
    constitution = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry = load_json(root / COMPARATOR_REGISTRY_REL)
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    useful_output_benchmark = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)

    field_checks = [
        {
            "check_id": f"constitution_field_{field}",
            "pass": _field_present(constitution.get(field)),
        }
        for field in benchmark_required_fields()
    ]
    negative_rows = negative_ledger.get("rows", [])
    negative_row_count = len(negative_rows) if isinstance(negative_rows, list) else 0

    checks = field_checks + [
        {
            "check_id": "constitution_status_frozen_for_current_head",
            "pass": str(constitution.get("status", "")).strip() == "FROZEN_W4_CURRENT_HEAD",
        },
        {
            "check_id": "constitution_head_matches_truth_lock",
            "pass": str(constitution.get("current_git_head", "")).strip() == str(truth_lock.get("current_repo_head", "")).strip(),
        },
        {
            "check_id": "constitution_category_matches_actual_category",
            "pass": str(constitution.get("actual_category", "")).strip() == ACTUAL_CATEGORY,
        },
        {
            "check_id": "comparator_registry_active",
            "pass": _status_is(comparator_registry.get("status"), "ACTIVE"),
        },
        {
            "check_id": "useful_output_benchmark_passes",
            "pass": _status_is(useful_output_benchmark.get("status"), "PASS"),
        },
        {
            "check_id": "negative_result_ledger_present",
            "pass": _status_is(negative_ledger.get("status"), "PASS") and negative_row_count >= 5,
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w4.benchmark_constitution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": str(truth_lock.get("current_repo_head", "")).strip(),
        "status": status,
        "actual_category": ACTUAL_CATEGORY,
        "negative_result_row_count": negative_row_count,
        "checks": checks,
        "claim_boundary": (
            "W4 freezes benchmark law, preserves negative rows, and binds the actual category to current-head truth. "
            "It does not unlock comparative widening or superiority language."
        ),
        "source_refs": [
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
            TRUTH_LOCK_REL,
        ],
        "stronger_claims_not_made": [
            "category_leadership_earned",
            "router_superiority_earned",
            "c006_closed",
            "commercial_widening_unlocked",
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the active benchmark constitution and preserve negative-result law.")
    parser.add_argument("--negative-ledger-output", default=NEGATIVE_LEDGER_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    negative_ledger = build_benchmark_negative_result_ledger(root=root)
    receipt = build_receipt(root=root, negative_ledger=negative_ledger)

    write_json_stable(_resolve(root, args.negative_ledger_output), negative_ledger)
    write_json_stable(_resolve(root, args.receipt_output), receipt)

    summary = {
        "actual_category": receipt["actual_category"],
        "negative_result_row_count": receipt["negative_result_row_count"],
        "status": receipt["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
