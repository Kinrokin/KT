from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str


def _iter_py_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        yield p


def _local_module_names(root: Path, py_files: Sequence[Path]) -> Set[str]:
    names: Set[str] = set()
    for p in py_files:
        try:
            rel = p.relative_to(root)
        except Exception:
            continue
        if rel.suffix != ".py":
            continue
        if rel.name == "__init__.py":
            continue
        names.add(rel.stem)
    return names


def _extract_imports(tree: ast.AST) -> Iterable[Tuple[int, str, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield (getattr(node, "lineno", 1), "import", alias.name)
        elif isinstance(node, ast.ImportFrom):
            level = getattr(node, "level", 0) or 0
            module = node.module
            if level and module is None:
                continue
            if module is None:
                continue
            yield (getattr(node, "lineno", 1), "from", module)


def _is_allowed_import(*, module: str, local_modules: Set[str], stdlib: Set[str], banned_prefixes: Tuple[str, ...]) -> bool:
    top = module.split(".", 1)[0]
    if any(module == p or module.startswith(p + ".") for p in banned_prefixes):
        return False
    if top in local_modules:
        return True
    if top in stdlib:
        return True
    return False


def check(root: Path) -> Tuple[bool, Sequence[Violation]]:
    py_files = sorted(_iter_py_files(root))
    local = _local_module_names(root, py_files)

    stdlib: Set[str] = set(getattr(sys, "stdlib_module_names", set()))
    if not stdlib:
        return (
            False,
            [
                Violation(
                    path=str(root),
                    line=1,
                    kind="STDLIB_DISCOVERY_FAIL",
                    detail="sys.stdlib_module_names unavailable; cannot prove tooling-only import surface",
                )
            ],
        )

    banned_prefixes = (
        # Runtime/kernel organs (must never be imported by growth tooling).
        "kt",
        "core",
        "schemas",
        "memory",
        "governance",
        "llm",
        "cognition",
        "council",
        "paradox",
        "temporal",
        "multiverse",
        "thermodynamics",
        # Tooling must not execute the kernel.
        "subprocess",
        # Tooling must not perform network I/O.
        "socket",
        "http",
        "urllib",
        "requests",
    )

    violations: list[Violation] = []
    for p in py_files:
        try:
            text = p.read_text(encoding="utf-8", errors="strict")
        except Exception as exc:
            violations.append(Violation(path=str(p), line=1, kind="READ_FAIL", detail=exc.__class__.__name__))
            continue

        try:
            tree = ast.parse(text, filename=str(p))
        except SyntaxError as exc:
            violations.append(Violation(path=str(p), line=getattr(exc, "lineno", 1) or 1, kind="SYNTAX_ERROR", detail=exc.msg))
            continue

        for lineno, kind, module in _extract_imports(tree):
            if not _is_allowed_import(module=module, local_modules=local, stdlib=stdlib, banned_prefixes=banned_prefixes):
                violations.append(Violation(path=str(p), line=lineno, kind="ILLEGAL_IMPORT", detail=f"{kind} {module}"))

    return (not violations), violations


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv or sys.argv[1:])
    root = Path(argv[0]).resolve() if argv else Path(__file__).resolve().parent / "eval_harness"
    ok, violations = check(root)
    if ok:
        print("# C023 CONSTITUTIONAL GUARD: PASS")
        print(f"- root: {root.as_posix()}")
        print(f"- files_scanned: {len(list(_iter_py_files(root)))}")
        return 0
    print("# C023 CONSTITUTIONAL GUARD: FAIL")
    for v in violations:
        print(f"- {v.kind}: {v.path}:{v.line} :: {v.detail}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

