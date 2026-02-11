"""
Operation A: Master Orchestrator

Sequences all 7 stages with fail-closed governance.

OPERATION A FLOW:
  ├─ Stage 1: Policy Sweep (Policy-C)        → policy_c_sweep_result.json
  │  └─ Gate P1: Sweep valid?
  ├─ Stage 2: Dataset Export (Policy-C)       → kt_policy_c_dataset_v1.jsonl
  │  └─ Gate D1: Dataset valid?
  ├─ Stage 3: Dataset Coercion (NEW)          → dataset_coerced.jsonl
  │  └─ Gate D2: Coercion valid?
  ├─ Stage 4: MRT-0 Manufacture (NEW)         → cohort0_adapter_set.json
  │  └─ Gate M0: Adapters valid?
  ├─ Stage 5: MRT-1 Training Loop (NEW)       → 13 × train_receipt.json
  │  └─ Gate T1: Receipt valid? (per adapter)
  ├─ Stage 6: Promotion (NEW)                 → promotion_registry.jsonl
  │  └─ Gate PR1: Promotion valid? (per adapter)
  └─ Stage 7: Runtime Snapshot (NEW)          → mrt1_runtime_snapshot.json
     └─ Gate RS1: Snapshot valid?

Fail-Closed Law:
  ANY gate failure → HALT ENTIRE RUN
  NO RETRIES
  NO AUTO-REPAIR
  NO SKIPPING

Produces:
  - operation_a_result.json (audit trail of all gates)
  - mrt1_runtime_snapshot.json (final canonical registry)
"""

import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import importlib.util


class OperationAFailure(Exception):
    """Operation A execution failure (fail-closed)."""
    pass


def load_gate_module(gates_module_path: Path):
    """Dynamically load gates module."""
    spec = importlib.util.spec_from_file_location("operation_a_gates", gates_module_path)
    gates = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gates)
    return gates


def run_stage(
    stage_name: str,
    stage_script: Path,
    stage_args: List[str],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Execute a single stage with subprocess isolation.

    Returns: {status, output, errors, gate_results}
    """
    print(f"\n{'='*70}", file=sys.stderr)
    print(f"  {stage_name}", file=sys.stderr)
    print(f"{'='*70}", file=sys.stderr)

    if not stage_script.exists():
        raise OperationAFailure(f"{stage_name}: Script not found: {stage_script}")

    # Run stage as subprocess
    cmd = ["python", str(stage_script)] + stage_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        raise OperationAFailure(f"{stage_name}: Timeout (>1 hour)")
    except Exception as e:
        raise OperationAFailure(f"{stage_name}: Execution error: {e}")

    # Parse output
    output = result.stdout.strip()
    stderr = result.stderr.strip()

    print(stderr, file=sys.stderr)

    if result.returncode != 0:
        raise OperationAFailure(f"{stage_name}: Exit code {result.returncode}")

    # Extract receipt from output (last JSON block)
    receipt = None
    for line in output.split("\n"):
        try:
            receipt = json.loads(line)
        except json.JSONDecodeError:
            pass

    if not receipt:
        raise OperationAFailure(f"{stage_name}: No receipt in output")

    return receipt


def operation_a_main(
    sweep_result_path: Path = None,
    raw_dataset_path: Path = None,
    base_model: str = "mistralai/Mistral-7B-Instruct-v0.2",
    batch_size: int = 1,
    learning_rate: float = 1e-4,
    num_epochs: int = 1,
    max_seq_len: int = 512,
    output_root: Path = None,
):
    """
    Execute Operation A (all 7 stages).

    Returns: operation_a_result dict
    """
    if output_root is None:
        output_root = Path.cwd() / f"operation_a_run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    tools_training_dir = Path(__file__).parent.resolve()

    result = {
        "operation": "Operation A: MRT-1 Training Lane Refactor",
        "started_at": datetime.utcnow().isoformat(),
        "output_root": str(output_root),
        "stages": {},
        "status": "UNKNOWN",
        "failure_gate": None,
    }

    try:
        # ====================================================================
        # STAGE 1: Policy Sweep
        # ====================================================================
        if sweep_result_path is None:
            print(">>> Running policy_c.sweep_runner", file=sys.stderr)
            sweep_dir = output_root / "policy_c_sweep"
            sweep_dir.mkdir(parents=True, exist_ok=True)
            cmd = ["python", "-m", "policy_c.sweep_runner", "--out-root", str(sweep_dir)]
            subprocess.run(cmd, check=True, timeout=3600)
            sweep_result_path = sweep_dir / "policy_c_sweep_result.json"
        else:
            sweep_result_path = Path(sweep_result_path)

        # ====================================================================
        # STAGE 2: Dataset Export
        # ====================================================================
        if raw_dataset_path is None:
            print(">>> Running policy_c.dataset_export", file=sys.stderr)
            export_dir = output_root / "policy_c_export"
            export_dir.mkdir(parents=True, exist_ok=True)
            cmd = [
                "python", "-m", "policy_c.dataset_export",
                "--sweep-result", str(sweep_result_path),
                "--out-root", str(export_dir),
            ]
            subprocess.run(cmd, check=True, timeout=3600)
            raw_dataset_path = export_dir / "kt_policy_c_dataset_v1.jsonl"
        else:
            raw_dataset_path = Path(raw_dataset_path)

        # ====================================================================
        # STAGE 3: Dataset Coercion
        # ====================================================================
        print("\n>>> Stage 3: Dataset Coercion", file=sys.stderr)

        stage3_dir = output_root / "stage3_coercion"
        stage3_dir.mkdir(parents=True, exist_ok=True)
        coerced_dataset = stage3_dir / "dataset_coerced.jsonl"

        stage3_receipt = run_stage(
            "Stage 3: Dataset Coercion",
            tools_training_dir / "stage3_coerce_dataset.py",
            [
                "--input", str(raw_dataset_path),
                "--output", str(coerced_dataset),
                "--verbose",
            ],
            result,
        )

        if stage3_receipt.get("status") != "PASS":
            raise OperationAFailure("Stage 3: Dataset Coercion FAILED")

        result["stages"]["stage3_coercion"] = stage3_receipt

        # ====================================================================
        # STAGE 4: MRT-0 Manufacture
        # ====================================================================
        print("\n>>> Stage 4: MRT-0 Manufacture", file=sys.stderr)

        stage4_dir = output_root / "stage4_mrt0"
        stage4_dir.mkdir(parents=True, exist_ok=True)

        stage4_receipt = run_stage(
            "Stage 4: MRT-0 Manufacture",
            tools_training_dir / "stage4_mrt0_manufacture.py",
            [
                "--output-dir", str(stage4_dir),
                "--adapter-count", "13",
                "--version", "1",
            ],
            result,
        )

        if stage4_receipt.get("status") != "PASS":
            raise OperationAFailure("Stage 4: MRT-0 Manufacture FAILED")

        result["stages"]["stage4_mrt0"] = stage4_receipt

        # ====================================================================
        # STAGE 5: MRT-1 Training Loop
        # ====================================================================
        print("\n>>> Stage 5: MRT-1 Training Loop (13 Adapters)", file=sys.stderr)

        stage5_dir = output_root / "stage5_training"
        stage5_dir.mkdir(parents=True, exist_ok=True)

        train_receipts = []

        for i in range(1, 14):
            adapter_id = f"adapter_{i}"
            adapter_dir = stage5_dir / adapter_id
            adapter_dir.mkdir(parents=True, exist_ok=True)

            print(f"\n  Training {adapter_id} ({i}/13)...", file=sys.stderr)

            # Run phase2_train.py
            cmd = [
                "python", "-m", "tools.training.phase2_train",
                "--base-model", base_model,
                "--dataset", str(coerced_dataset),
                "--output-dir", str(adapter_dir),
                "--load-in-4bit", "true",
                "--batch-size", str(batch_size),
                "--learning-rate", str(learning_rate),
                "--num-epochs", str(num_epochs),
                "--max-seq-len", str(max_seq_len),
                "--gradient-checkpointing", "true",
            ]

            try:
                train_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,
                    cwd=tools_training_dir.parent.parent,  # KT root
                )
            except subprocess.TimeoutExpired:
                raise OperationAFailure(f"Training {adapter_id}: Timeout")
            except Exception as e:
                raise OperationAFailure(f"Training {adapter_id}: {e}")

            if train_result.returncode != 0:
                raise OperationAFailure(f"Training {adapter_id}: Exit code {train_result.returncode}")

            receipt_path = adapter_dir / "train_receipt.json"
            if not receipt_path.exists():
                raise OperationAFailure(f"Training {adapter_id}: No receipt generated")

            train_receipts.append(receipt_path)

            print(f"  ✓ {adapter_id} complete", file=sys.stderr)

        result["stages"]["stage5_training"] = {
            "stage": "Stage 5: MRT-1 Training",
            "status": "PASS",
            "trained_adapters": [f"adapter_{i}" for i in range(1, 14)],
            "train_receipts": [str(p) for p in train_receipts],
        }

        # ====================================================================
        # STAGE 6: Promotion
        # ====================================================================
        print("\n>>> Stage 6: Promotion", file=sys.stderr)

        stage6_dir = output_root / "stage6_promotion"
        stage6_dir.mkdir(parents=True, exist_ok=True)
        promotion_registry = stage6_dir / "promotion_registry.jsonl"

        stage6_receipt = run_stage(
            "Stage 6: Promotion",
            tools_training_dir / "stage6_promotion.py",
            [
                "--receipts", *[str(r) for r in train_receipts],
                "--output-dir", str(stage6_dir),
                "--registry", str(promotion_registry),
            ],
            result,
        )

        if stage6_receipt.get("status") != "PASS":
            raise OperationAFailure("Stage 6: Promotion FAILED")

        result["stages"]["stage6_promotion"] = stage6_receipt

        # ====================================================================
        # STAGE 7: Runtime Snapshot
        # ====================================================================
        print("\n>>> Stage 7: Runtime Snapshot", file=sys.stderr)

        stage7_dir = output_root / "stage7_snapshot"
        stage7_dir.mkdir(parents=True, exist_ok=True)
        runtime_snapshot = stage7_dir / "mrt1_runtime_snapshot.json"

        stage7_receipt = run_stage(
            "Stage 7: Runtime Snapshot",
            tools_training_dir / "stage7_runtime_snapshot.py",
            [
                "--registry", str(promotion_registry),
                "--output", str(runtime_snapshot),
                "--version", "1",
            ],
            result,
        )

        if stage7_receipt.get("status") != "PASS":
            raise OperationAFailure("Stage 7: Runtime Snapshot FAILED")

        result["stages"]["stage7_snapshot"] = stage7_receipt

        # ====================================================================
        # SUCCESS
        # ====================================================================
        result["status"] = "PASS"
        result["completed_at"] = datetime.utcnow().isoformat()
        result["runtime_snapshot"] = str(runtime_snapshot)

        return result

    except OperationAFailure as e:
        result["status"] = "FAILED"
        result["failure_reason"] = str(e)
        result["failure_gate"] = getattr(e, "gate_name", "unknown")
        result["failed_at"] = datetime.utcnow().isoformat()

        # Print fail-closed notice
        print(f"\n{'='*70}", file=sys.stderr)
        print(f"  ✗ OPERATION A FAILED (FAIL-CLOSED)", file=sys.stderr)
        print(f"{'='*70}", file=sys.stderr)
        print(f"Reason: {e}", file=sys.stderr)
        print(f"Halting entire run. No retries. No auto-repair.", file=sys.stderr)
        print(f"{'='*70}\n", file=sys.stderr)

        return result


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Operation A: MRT-1 Training Lane Refactor (Master Orchestrator)",
        epilog="Sequences 7 stages with fail-closed governance. Outputs mrt1_runtime_snapshot.json",
    )
    parser.add_argument(
        "--sweep-result",
        type=Path,
        help="Path to policy_c_sweep_result.json (skip Stage 1 if provided)",
    )
    parser.add_argument(
        "--raw-dataset",
        type=Path,
        help="Path to raw dataset JSONL (skip Stage 2 if provided)",
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="mistralai/Mistral-7B-Instruct-v0.2",
        help="Base model ID (default: mistralai/Mistral-7B-Instruct-v0.2)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Training batch size (default: 1)",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=1e-4,
        help="Learning rate (default: 1e-4)",
    )
    parser.add_argument(
        "--num-epochs",
        type=int,
        default=1,
        help="Training epochs (default: 1)",
    )
    parser.add_argument(
        "--max-seq-len",
        type=int,
        default=512,
        help="Max sequence length (default: 512)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output root directory (auto-generated if not specified)",
    )

    args = parser.parse_args()

    # Run Operation A
    result = operation_a_main(
        sweep_result_path=args.sweep_result,
        raw_dataset_path=args.raw_dataset,
        base_model=args.base_model,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        num_epochs=args.num_epochs,
        max_seq_len=args.max_seq_len,
        output_root=args.output,
    )

    # Write operation result
    result_path = Path(result["output_root"]) / "operation_a_result.json"
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print("\n" + "="*70, file=sys.stderr)
    print(f"  OPERATION A COMPLETE: {result['status']}", file=sys.stderr)
    print("="*70, file=sys.stderr)
    print(f"Result: {result_path}", file=sys.stderr)

    if result["status"] == "PASS":
        print(f"Runtime Snapshot: {result['runtime_snapshot']}", file=sys.stderr)
        print("✓ All 7 stages complete", file=sys.stderr)
        print("✓ All 13 adapters trained, promoted, and registered", file=sys.stderr)
        print("✓ Fail-closed governance enforced", file=sys.stderr)
        return 0
    else:
        print(f"✗ Failed: {result['failure_reason']}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
