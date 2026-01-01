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
        raise EntryError(str(exc))

    try:
        ImportTruthGuard.install(registry)
    except ImportTruthError as exc:
        raise EntryError(str(exc))

    from core.invariants_gate import ContractViolationError, InvariantsGate  # noqa: E402

    try:
        InvariantsGate.assert_runtime_invariants(context)
    except ContractViolationError as exc:
        raise EntryError(str(exc))

    try:
        spine_mod = importlib.import_module(registry.canonical_spine.module)
        spine_fn = getattr(spine_mod, registry.canonical_spine.callable)
    except Exception as exc:
        raise EntryError(f"Unable to resolve canonical Spine callable: {exc.__class__.__name__}")

    if not callable(spine_fn):
        raise EntryError("Canonical Spine target is not callable (fail-closed)")

    return spine_fn(context)

