from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from core.runtime_registry import RuntimeRegistry, load_runtime_registry


@dataclass(frozen=True)
class SafetyCheckResult:
    ok: bool
    errors: List[str]


_IMPORT_RE = re.compile(r"^\s*(import|from)\s+([A-Za-z0-9_\.]+)")


def cleanroom_root() -> Path:
    return Path(__file__).resolve().parents[1]


def policy_c_module_paths() -> List[Path]:
    policy_c_dir = Path(__file__).resolve().parent
    return sorted(policy_c_dir.glob("*.py"))


def resolve_allowed_roots(roots: Sequence[str]) -> List[Path]:
    base = cleanroom_root()
    resolved: List[Path] = []
    for root in roots:
        p = Path(root)
        if p.is_absolute():
            resolved.append(p.resolve())
        else:
            resolved.append((base / p).resolve())
    return resolved


def assert_export_root_allowed(path: Path, allowed_roots: Sequence[str]) -> None:
    resolved = path.resolve()
    for root in resolve_allowed_roots(allowed_roots):
        try:
            resolved.relative_to(root)
            return
        except Exception:
            continue
    raise RuntimeError(f"Export root not allowlisted (fail-closed): {resolved.as_posix()}")


def scan_forbidden_imports(paths: Iterable[Path], forbidden: Sequence[str]) -> List[str]:
    forbidden_set = set(forbidden)
    violations: List[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            m = _IMPORT_RE.match(line)
            if not m:
                continue
            mod = m.group(2).split(".", 1)[0]
            if mod in forbidden_set:
                violations.append(f"{path.as_posix()}: {mod}")
    return violations


def assert_schema_lock(schema_paths: Iterable[Path]) -> None:
    for path in schema_paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("additionalProperties", True) is not False:
            raise RuntimeError(f"Schema not strict (additionalProperties!=false): {path.as_posix()}")


def run_static_safety_check(
    *,
    registry: RuntimeRegistry | None = None,
    module_paths: Iterable[Path],
    schema_paths: Iterable[Path] | None = None,
) -> SafetyCheckResult:
    reg = registry or load_runtime_registry()
    errors: List[str] = []
    if not reg.policy_c.static_safety.enabled:
        return SafetyCheckResult(ok=True, errors=[])

    violations = scan_forbidden_imports(module_paths, reg.policy_c.static_safety.forbidden_imports)
    if violations:
        errors.extend([f"forbidden_import:{v}" for v in violations])

    if schema_paths is not None:
        try:
            assert_schema_lock(schema_paths)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"schema_lock:{exc}")

    return SafetyCheckResult(ok=(len(errors) == 0), errors=errors)
