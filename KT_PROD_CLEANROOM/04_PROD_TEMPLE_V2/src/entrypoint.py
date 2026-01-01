from __future__ import annotations

from typing import Any, Dict

from core.invariants_gate import InvariantsGate


def invoke(context: Dict[str, Any]) -> None:
    InvariantsGate.assert_runtime_invariants(context)

