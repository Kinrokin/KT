from __future__ import annotations

import builtins
import importlib.abc
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from core.runtime_registry import RuntimeRegistry


@dataclass(frozen=True)
class ImportTruthError(RuntimeError):
    message: str

    def __str__(self) -> str:
        return self.message


_ORIGINAL_IMPORT: Optional[Callable[..., Any]] = None
_FINDER: Optional[importlib.abc.MetaPathFinder] = None
_INSTALLED: bool = False


def _src_root() -> Path:
    # .../04_PROD_TEMPLE_V2/src/core/import_truth_guard.py -> .../src
    return Path(__file__).resolve().parents[1]


def _is_internal_top_level(top: str) -> bool:
    if not isinstance(top, str) or not top:
        return False
    src = _src_root()
    return (src / top).is_dir() or (src / f"{top}.py").is_file()


class _ImportTruthFinder(importlib.abc.MetaPathFinder):
    def __init__(self, registry: RuntimeRegistry) -> None:
        self._allowed_roots = set(registry.runtime_import_roots)
        self._organs_by_root = dict(registry.organs_by_root)
        self._matrix = {k: set(v) for k, v in registry.import_truth_matrix.items()}

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:  # noqa: ANN401
        top = fullname.split(".", 1)[0]

        # Runtime Surface allowlist: block any *internal* top-level modules not explicitly approved.
        if _is_internal_top_level(top) and top not in self._allowed_roots:
            raise ImportError(f"Import Truth: top-level root not allowlisted: {top!r}")

        # Organ import matrix: best-effort importer inference from call stack; fail-closed when importer is internal.
        importer_mod = self._infer_importer_internal_module()
        if importer_mod:
            importer_top = importer_mod.split(".", 1)[0]
            if importer_top in self._allowed_roots and top in self._allowed_roots:
                src_organ = self._organs_by_root.get(importer_top)
                dst_organ = self._organs_by_root.get(top)
                if not src_organ or not dst_organ:
                    raise ImportError("Import Truth: organ mapping missing (fail-closed)")
                allowed = self._matrix.get(src_organ)
                if allowed is None:
                    raise ImportError("Import Truth: importer organ missing matrix row (fail-closed)")
                if dst_organ not in allowed:
                    raise ImportError(
                        f"Import Truth: illegal import {src_organ!r} -> {dst_organ!r} via {fullname!r} (fail-closed)"
                    )

        return None

    def _infer_importer_internal_module(self) -> Optional[str]:
        # Walk up a bounded slice of the call stack and pick the first internal
        # runtime module encountered (best-effort). External importers (tests/tools)
        # are out of scope for organ-matrix enforcement.
        for depth in range(2, 64):
            try:
                frame = sys._getframe(depth)
            except ValueError:
                break
            name = frame.f_globals.get("__name__")
            if not isinstance(name, str) or not name:
                continue
            if name.startswith("importlib.") or name.startswith("core.import_truth_guard"):
                continue
            top = name.split(".", 1)[0]
            if top in self._allowed_roots:
                return name
        return None


class ImportTruthGuard:
    @staticmethod
    def install(registry: RuntimeRegistry) -> None:
        global _INSTALLED, _ORIGINAL_IMPORT, _FINDER
        if _INSTALLED:
            return

        allowed_roots = set(registry.runtime_import_roots)
        organs_by_root = dict(registry.organs_by_root)
        matrix = {k: set(v) for k, v in registry.import_truth_matrix.items()}

        original = builtins.__import__

        def guarded_import(
            name: str,
            globals: Optional[dict] = None,
            locals: Optional[dict] = None,
            fromlist: Sequence[str] = (),
            level: int = 0,
        ) -> Any:
            importer_mod = globals.get("__name__") if isinstance(globals, dict) else None
            importer_pkg = globals.get("__package__") if isinstance(globals, dict) else None

            try:
                resolved = importlib.util.resolve_name(name, importer_pkg) if level else name
            except Exception:
                raise ImportError("Import Truth: unable to resolve relative import (fail-closed)")

            top = resolved.split(".", 1)[0]

            # Runtime Surface allowlist: block any *internal* top-level modules not explicitly approved.
            if _is_internal_top_level(top) and top not in allowed_roots:
                raise ImportError(f"Import Truth: top-level root not allowlisted: {top!r}")

            importer_top = importer_mod.split(".", 1)[0] if isinstance(importer_mod, str) and importer_mod else ""
            if _is_internal_top_level(importer_top) and importer_top in allowed_roots and top in allowed_roots:
                src_organ = organs_by_root.get(importer_top)
                dst_organ = organs_by_root.get(top)
                if not src_organ or not dst_organ:
                    raise ImportError("Import Truth: organ mapping missing (fail-closed)")
                allowed = matrix.get(src_organ)
                if allowed is None:
                    raise ImportError("Import Truth: importer organ missing matrix row (fail-closed)")
                if dst_organ not in allowed:
                    raise ImportError(
                        f"Import Truth: illegal import {src_organ!r} -> {dst_organ!r} via {resolved!r} (fail-closed)"
                    )

            return original(name, globals, locals, fromlist, level)

        _ORIGINAL_IMPORT = original
        builtins.__import__ = guarded_import
        _FINDER = _ImportTruthFinder(registry)
        sys.meta_path.insert(0, _FINDER)
        _INSTALLED = True

    @staticmethod
    def uninstall_for_tests() -> None:
        global _INSTALLED, _ORIGINAL_IMPORT, _FINDER
        if not _INSTALLED:
            return
        if _ORIGINAL_IMPORT is not None:
            builtins.__import__ = _ORIGINAL_IMPORT
        if _FINDER is not None:
            try:
                sys.meta_path.remove(_FINDER)
            except ValueError:
                pass
        _ORIGINAL_IMPORT = None
        _FINDER = None
        _INSTALLED = False
