"""
Stage 3: Dataset Coercion

Transforms raw Policy-C dataset (metadata-heavy JSONL) into canonical training format.

Interface Contract:
  Input:  kt_policy_c_dataset_v1.jsonl (Policy-C records with metadata refs)
  Output: dataset_coerced.jsonl (EXACT format: {"text": "<string>"} per line)

Coercion Priority (when extracting text):
  1. "text" field (if exists and non-empty)
  2. "prompt" field
  3. "input" field
  4. "output" field
  5. "completion" field
  6. Fallback: json.dumps(full_record, sort_keys=True)

This stage bridges layer separation:
  Policy-C owns behavioral signals
  Dataset owns translation to LLM format
  Training owns learning (never sees raw signals)

Gate D2 enforces: 100% schema compliance, no empty strings.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict
from datetime import datetime

from operation_a_gates import gate_d2_coercion, GateFailure


def coerce_record_to_text(record: Any) -> str:
    """
    Extract training text from Policy-C record using priority order.

    Returns non-empty string suitable for LLM fine-tuning.
    """
    # Handle string records
    if isinstance(record, str):
        return record.strip()

    if not isinstance(record, dict):
        # Fallback: serialize to JSON
        return json.dumps(record, sort_keys=True)

    # Priority order
    priority_keys = ["text", "prompt", "input", "output", "completion"]

    for key in priority_keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    # No inline text found - serialize full record
    serialized = json.dumps(record, sort_keys=True)
    return serialized


def stage3_coerce_dataset(
    raw_dataset_path: Path,
    output_path: Path,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Stage 3: Dataset Coercion

    Reads raw JSONL, applies text extraction, validates output, produces coerced dataset.

    Returns dict with coercion metadata (line_count, coercion_rate, etc).
    """
    raw_dataset_path = Path(raw_dataset_path)
    output_path = Path(output_path)

    if not raw_dataset_path.exists():
        raise FileNotFoundError(f"Raw dataset not found: {raw_dataset_path}")

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats = {
        "stage": "Stage 3: Dataset Coercion",
        "started_at": datetime.utcnow().isoformat(),
        "input_file": str(raw_dataset_path),
        "output_file": str(output_path),
        "total_lines": 0,
        "coerced_lines": 0,
        "failed_lines": 0,
        "coercion_methods": {
            "text": 0,
            "prompt": 0,
            "input": 0,
            "output": 0,
            "completion": 0,
            "fallback_json": 0,
        },
    }

    try:
        with open(raw_dataset_path, "r", encoding="utf-8") as f_in:
            with open(output_path, "w", encoding="utf-8") as f_out:
                for line_num, line in enumerate(f_in, 1):
                    line = line.strip()
                    stats["total_lines"] = line_num

                    # Skip empty lines
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as e:
                        if verbose:
                            print(f"  [SKIP] Line {line_num}: Invalid JSON - {e}", file=sys.stderr)
                        stats["failed_lines"] += 1
                        continue

                    try:
                        # Extract text
                        text = coerce_record_to_text(record)

                        # Validate non-empty
                        if not text or not text.strip():
                            if verbose:
                                print(
                                    f"  [SKIP] Line {line_num}: Empty after coercion",
                                    file=sys.stderr,
                                )
                            stats["failed_lines"] += 1
                            continue

                        # Write canonical format
                        canonical = {"text": text.strip()}
                        f_out.write(json.dumps(canonical, ensure_ascii=False) + "\n")
                        stats["coerced_lines"] += 1

                        # Track coercion method
                        if isinstance(record, dict):
                            for key in ["text", "prompt", "input", "output", "completion"]:
                                if key in record and isinstance(record[key], str) and record[key].strip():
                                    stats["coercion_methods"][key] += 1
                                    break
                            else:
                                stats["coercion_methods"]["fallback_json"] += 1

                    except Exception as e:
                        if verbose:
                            print(f"  [ERROR] Line {line_num}: {e}", file=sys.stderr)
                        stats["failed_lines"] += 1
                        continue

    except Exception as e:
        raise RuntimeError(f"Coercion failed: {e}")

    stats["completed_at"] = datetime.utcnow().isoformat()

    return stats


def main():
    """CLI entry point for Stage 3."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Stage 3: Dataset Coercion",
        epilog="Output: dataset_coerced.jsonl with 100%% compliance to {\"text\": str} schema",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to raw dataset JSONL (from Stage 2)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to coerced dataset JSONL (Stage 3 output)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed coercion logs",
    )
    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help="Skip D2 gate validation (not recommended)",
    )

    args = parser.parse_args()

    print(f"\n{'='*70}", file=sys.stderr)
    print(f"  Stage 3: Dataset Coercion", file=sys.stderr)
    print(f"{'='*70}\n", file=sys.stderr)

    # Run coercion
    stats = stage3_coerce_dataset(args.input, args.output, verbose=args.verbose)

    print(
        f"Coerced {stats['coerced_lines']}/{stats['total_lines']} lines",
        file=sys.stderr,
    )
    print(f"Coercion methods: {stats['coercion_methods']}", file=sys.stderr)

    # Validate with Gate D2
    if not args.skip_gate:
        try:
            gate_result = gate_d2_coercion(args.output)
            print(f"\n✓ Gate D2 PASSED: {gate_result['reason']}\n", file=sys.stderr)
        except GateFailure as e:
            print(f"\n✗ Gate D2 FAILED: {e.reason}\n", file=sys.stderr)
            sys.exit(1)

    # Output JSON receipt
    receipt = {
        "stage": "Stage 3: Dataset Coercion",
        "status": "PASS",
        "output_file": str(args.output),
        "stats": stats,
    }

    print(json.dumps(receipt, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
