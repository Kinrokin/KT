from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Dict

from core.import_truth_guard import ImportTruthError, ImportTruthGuard
from core.runtime_registry import RuntimeRegistryError, load_runtime_registry


@dataclass(frozen=True)
class EntryError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


def invoke(context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        registry = load_runtime_registry()
    except RuntimeRegistryError as exc:
        return {"status": "FAIL", "error": str(exc), "where": "load_runtime_registry"}

    try:
        ImportTruthGuard.install(registry)
    except ImportTruthError as exc:
        return {"status": "FAIL", "error": str(exc), "where": "ImportTruthGuard.install"}

    from core.invariants_gate import ContractViolationError, InvariantsGate  # noqa: E402

    try:
        InvariantsGate.assert_runtime_invariants(context)
    except ContractViolationError as exc:
        return {"status": "FAIL", "error": str(exc), "where": "InvariantsGate.assert_runtime_invariants"}

    try:
        spine_mod = importlib.import_module(registry.canonical_spine.module)
        spine_fn = getattr(spine_mod, registry.canonical_spine.callable)
    except Exception as exc:
        return {"status": "FAIL", "error": f"Unable to resolve canonical Spine callable: {exc.__class__.__name__}", "where": "import spine"}

    if not callable(spine_fn):
        return {"status": "FAIL", "error": "Canonical Spine target is not callable (fail-closed)", "where": "spine_fn"}

    try:
        result = spine_fn(context)
    except Exception as exc:
        return {"status": "FAIL", "error": str(exc), "where": "spine_fn(context)"}
    if result is None:
        return {"status": "FAIL", "error": "spine_fn(context) returned None", "where": "spine_fn(context)"}
    return result

