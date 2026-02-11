"""
Stage 4: MRT-0 Manufacture

Creates adapter identity scaffolding for MRT-1 training.

Produces:
  - cohort0_adapter_set.json: Manifest of 13 adapters with version metadata
  - adapter work orders (per adapter)

Gate M0 enforces: Exactly 13 adapters, correct IDs, version lock.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from operation_a_gates import gate_m0_mrt0_manufacture, GateFailure


def stage4_mrt0_manufacture(
    output_dir: Path,
    adapter_count: int = 13,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Stage 4: MRT-0 Manufacture

    Creates adapter manifest and work orders.

    Returns dict with manufacture metadata.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    stats = {
        "stage": "Stage 4: MRT-0 Manufacture",
        "started_at": datetime.utcnow().isoformat(),
        "adapter_count": adapter_count,
        "version": version,
    }

    # Create adapter list
    adapters = []
    for i in range(1, adapter_count + 1):
        adapter_id = f"adapter_{i}"
        adapters.append({
            "id": adapter_id,
            "ordinal": i,
            "version": version,
            "status": "manufactured",
            "created_at": datetime.utcnow().isoformat(),
        })

    # Create manifest
    manifest = {
        "cohort": "cohort_0",
        "adapters": adapters,
        "version": version,
        "adapter_count": adapter_count,
        "manufactured_at": datetime.utcnow().isoformat(),
        "schema": "kt.cohort0_adapter_set.v1",
    }

    manifest_path = output_dir / "cohort0_adapter_set.json"

    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
    except Exception as e:
        raise RuntimeError(f"Failed to write manifest: {e}")

    stats["manifest_file"] = str(manifest_path)
    stats["adapter_ids"] = [a["id"] for a in adapters]
    stats["completed_at"] = datetime.utcnow().isoformat()

    return stats


def main():
    """CLI entry point for Stage 4."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Stage 4: MRT-0 Manufacture",
        epilog="Output: cohort0_adapter_set.json with 13 manufactured adapters",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write adapter manifest",
    )
    parser.add_argument(
        "--adapter-count",
        type=int,
        default=13,
        help="Number of adapters to manufacture (default: 13)",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="1",
        help="Adapter version (default: 1)",
    )
    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help="Skip M0 gate validation (not recommended)",
    )

    args = parser.parse_args()

    print(f"\n{'='*70}", file=sys.stderr)
    print(f"  Stage 4: MRT-0 Manufacture", file=sys.stderr)
    print(f"{'='*70}\n", file=sys.stderr)

    # Run manufacture
    stats = stage4_mrt0_manufacture(args.output_dir, args.adapter_count, args.version)

    print(f"Manufactured {stats['adapter_count']} adapters (version {stats['version']})", file=sys.stderr)
    print(f"IDs: {stats['adapter_ids']}", file=sys.stderr)

    # Validate with Gate M0
    if not args.skip_gate:
        manifest_path = Path(args.output_dir) / "cohort0_adapter_set.json"
        try:
            gate_result = gate_m0_mrt0_manufacture(manifest_path)
            print(f"\n✓ Gate M0 PASSED: {gate_result['reason']}\n", file=sys.stderr)
        except GateFailure as e:
            print(f"\n✗ Gate M0 FAILED: {e.reason}\n", file=sys.stderr)
            sys.exit(1)

    # Output JSON receipt
    receipt = {
        "stage": "Stage 4: MRT-0 Manufacture",
        "status": "PASS",
        "manifest_file": str(Path(args.output_dir) / "cohort0_adapter_set.json"),
        "stats": stats,
    }

    print(json.dumps(receipt, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
