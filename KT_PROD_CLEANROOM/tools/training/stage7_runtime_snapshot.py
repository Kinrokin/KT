"""
Stage 7: Runtime Snapshot

Builds immutable, version-locked MRT-1 runtime registry.

Input: promotion_registry.jsonl
Output: mrt1_runtime_snapshot.json (frozen, no edits allowed)

Gate RS1 enforces: All 13 adapters present, version lock, timestamp frozen.

This is the final canonical registry that trains and evaluators will use.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from operation_a_gates import gate_rs1_runtime_snapshot, GateFailure


def stage7_runtime_snapshot(
    promotion_registry_path: Path,
    output_path: Path,
    version: str = "1",
) -> Dict[str, Any]:
    """
    Stage 7: Runtime Snapshot

    Reads promotion registry, builds frozen runtime snapshot.

    Returns dict with snapshot metadata.
    """
    promotion_registry_path = Path(promotion_registry_path)
    output_path = Path(output_path)

    if not promotion_registry_path.exists():
        raise FileNotFoundError(f"Promotion registry not found: {promotion_registry_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats = {
        "stage": "Stage 7: Runtime Snapshot",
        "started_at": datetime.utcnow().isoformat(),
        "adapter_count": 0,
        "adapters": [],
    }

    # Read promotion registry
    adapters = []
    try:
        with open(promotion_registry_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                promotion = json.loads(line.strip())
                adapters.append(promotion)
    except Exception as e:
        raise RuntimeError(f"Failed to read promotion registry: {e}")

    if len(adapters) != 13:
        raise RuntimeError(f"Expected 13 adapters in registry, got {len(adapters)}")

    # Create runtime snapshot (immutable, version-locked)
    snapshot = {
        "schema": "kt.mrt1_runtime_snapshot.v1",
        "version": version,
        "adapters": adapters,
        "adapter_count": len(adapters),
        "frozen_at": datetime.utcnow().isoformat(),
        "status": "frozen",
        "_note": "IMMUTABLE - Do not edit. Use for training, evaluation, and inference only.",
    }

    # Write snapshot
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
    except Exception as e:
        raise RuntimeError(f"Failed to write runtime snapshot: {e}")

    stats["adapter_count"] = len(adapters)
    stats["adapters"] = [a["adapter_id"] for a in adapters]
    stats["snapshot_file"] = str(output_path)
    stats["completed_at"] = datetime.utcnow().isoformat()

    return stats


def main():
    """CLI entry point for Stage 7."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Stage 7: Runtime Snapshot",
        epilog="Output: mrt1_runtime_snapshot.json (immutable, frozen registry)",
    )
    parser.add_argument("--allow-legacy", action="store_true", help="Acknowledge this is a legacy training entrypoint.")
    parser.add_argument(
        "--registry",
        type=Path,
        required=True,
        help="Path to promotion_registry.jsonl (from Stage 6)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to mrt1_runtime_snapshot.json (Stage 7 output)",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="1",
        help="Snapshot version (default: 1)",
    )
    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help="Skip RS1 gate validation (not recommended)",
    )

    args = parser.parse_args()

    from tools.training.legacy_guard import require_legacy_allow

    require_legacy_allow(allow_legacy=bool(args.allow_legacy), tool_name="tools.training.stage7_runtime_snapshot")

    print(f"\n{'='*70}", file=sys.stderr)
    print(f"  Stage 7: Runtime Snapshot", file=sys.stderr)
    print(f"{'='*70}\n", file=sys.stderr)

    # Run snapshot
    stats = stage7_runtime_snapshot(args.registry, args.output, args.version)

    print(f"Snapshot built: {stats['adapter_count']} adapters (version {args.version})", file=sys.stderr)
    print(f"Adapters: {stats['adapters']}", file=sys.stderr)

    # Validate with Gate RS1
    if not args.skip_gate:
        try:
            gate_result = gate_rs1_runtime_snapshot(args.output)
            print(f"\n✓ Gate RS1 PASSED: {gate_result['reason']}\n", file=sys.stderr)
        except GateFailure as e:
            print(f"\n✗ Gate RS1 FAILED: {e.reason}\n", file=sys.stderr)
            sys.exit(1)

    # Output JSON receipt
    receipt = {
        "stage": "Stage 7: Runtime Snapshot",
        "status": "PASS",
        "snapshot_file": stats["snapshot_file"],
        "adapter_count": stats["adapter_count"],
        "version": args.version,
        "stats": stats,
    }

    print(json.dumps(receipt, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
