from __future__ import annotations

from pathlib import Path
import sys


def _add_src_to_syspath() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src_root = repo_root / "src"
    sys.path.insert(0, str(src_root))


_add_src_to_syspath()

from core.runtime_registry import load_runtime_registry  # noqa: E402


def test_runtime_registry_separates_canonical_and_compatibility_roots() -> None:
    registry = load_runtime_registry()

    assert "tools" not in registry.runtime_import_roots
    assert registry.compatibility_allowlist_roots == ("tools",)
