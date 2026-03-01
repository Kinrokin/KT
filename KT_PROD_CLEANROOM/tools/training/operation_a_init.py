"""
KT OPERATION A: MRT-1 Training Lane Refactor

Complete governance framework for Policy-C → Dataset → Training → Promotion → Snapshot.

Modules:
  operation_a_gates.py       - 7 fail-closed gates (P1, D1, D2, M0, T1, PR1, RS1)
  stage3_coerce_dataset.py   - Dataset coercion (raw JSONL → {"text": str})
  stage4_mrt0_manufacture.py - Adapter scaffolding (13 adapters)
  stage6_promotion.py        - Adapter registration (SHA256-hashed)
  stage7_runtime_snapshot.py - Frozen runtime registry (immutable)
  operation_a_runner.py      - Master orchestrator (CLI)

Key Principle: Fail-closed governance. ANY gate failure halts entire run.

Reference: OPERATION_A_REFERENCE.md (complete architecture document)
"""

__all__ = [
    "operation_a_gates",
    "stage3_coerce_dataset",
    "stage4_mrt0_manufacture",
    "stage6_promotion",
    "stage7_runtime_snapshot",
    "operation_a_runner",
]
