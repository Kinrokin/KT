from __future__ import annotations

import argparse
import ast
import datetime as _dt
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class Violation:
    tag: str
    rel_path: str
    detail: str


MAIN_GUARD_RE = re.compile(r'__name__\s*==\s*["\']__main__["\']')
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----")
APIKEY_LITERAL_RE = re.compile(r"(?i)(api[_-]?key|apikey|token|secret)\s*[:=]\s*[\"'][^\"'\n]{16,}")

# Provider SDKs must never be imported at *module import time* from runtime src.
PROVIDER_IMPORT_BANS = (
    "openai",
    "groq",
    "anthropic",
    "cerebras",
    "google.generativeai",
    "vertexai",
)

TRAINING_MARKERS = ("curriculum", "epoch", "dataset", "benchmarks", "trainer", "finetune")

# External training frameworks are forbidden in runtime regardless of Import Truth.
TRAINING_IMPORT_BANS = (
    "torch",
    "tensorflow",
    "jax",
    "transformers",
    "datasets",
    "accelerate",
    "pytorch_lightning",
    "lightning",
)

TEXT_EXTENSIONS = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
}


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts:
            continue
        yield path


def _iter_py_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path


def _read_prefix_text(path: Path, max_bytes: int) -> str:
    try:
        raw = path.read_bytes()
    except Exception:
        return ""
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


class _ImportCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self._scope_depth = 0
        self.all_imports: List[Tuple[str, bool]] = []  # (module, is_top_level)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_Import(self, node: ast.Import) -> None:
        is_top_level = self._scope_depth == 0
        for alias in node.names:
            if alias.name:
                self.all_imports.append((alias.name, is_top_level))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        is_top_level = self._scope_depth == 0
        if node.module:
            self.all_imports.append((node.module, is_top_level))


def _module_top(import_module: str) -> str:
    return import_module.split(".", 1)[0]


def _is_provider_banned(import_module: str) -> bool:
    for banned in PROVIDER_IMPORT_BANS:
        if import_module == banned or import_module.startswith(banned + "."):
            return True
    return False


def _is_training_import(import_module: str) -> bool:
    lowered = import_module.lower()
    top = _module_top(import_module).lower()
    if top in TRAINING_IMPORT_BANS:
        return True
    return any(marker in lowered for marker in TRAINING_MARKERS)


def _organ_for_rel_path(rel_path: str) -> str:
    # File-path based organ mapping (fail-closed: UNKNOWN => violation).
    # Mirrors the style of KT_TEMPLE_V1 import-truth reporting: some organs
    # are distinguished by specific file paths, not only by package root.
    rel_path = rel_path.replace("\\", "/").lstrip("/")

    if rel_path == "entrypoint.py":
        return "Entry Point"
    if rel_path == "orchestrator.py":
        return "Spine"

    if rel_path.startswith("kt/"):
        return "Entry Point"
    if rel_path == "core/schemas.py":
        return "Schemas / Contracts"
    if rel_path.startswith("core/"):
        return "Spine"
    if rel_path.startswith("schemas/"):
        return "Schemas / Contracts"
    if rel_path.startswith("versioning/"):
        return "Schemas / Contracts"
    if rel_path.startswith("memory/"):
        return "Receipts / Ledger"
    if rel_path.startswith("curriculum/"):
        return "Curriculum Boundary"
    if rel_path.startswith("cognition/") or rel_path.startswith("kings_theorem/"):
        return "Crucible Engine"
    if rel_path.startswith("llm/"):
        return "Router"
    if rel_path.startswith("paradox/"):
        return "Paradox Engine"
    if rel_path.startswith("council/"):
        return "Council Router Engine"
    if rel_path.startswith("multiverse/"):
        return "Multiverse Engine"
    if rel_path.startswith("temporal/"):
        return "Temporal Engine"
    if rel_path.startswith("governance/"):
        return "Governance Kernel"
    if rel_path.startswith("thermodynamics/"):
        return "Thermodynamics / Budget"
    if rel_path.startswith("operators/") or rel_path.startswith("physics/"):
        return "Thermodynamics / Budget"
    return "UNKNOWN"


def _organ_for_import_module(import_module: str, internal_roots: Set[str]) -> Optional[str]:
    top = _module_top(import_module)
    if top not in internal_roots:
        return None

    if top == "entrypoint":
        return "Entry Point"
    if top == "orchestrator":
        return "Spine"

    if top == "kt":
        return "Entry Point"
    if top == "core":
        if import_module == "core.schemas" or import_module.startswith("core.schemas."):
            return "Schemas / Contracts"
        return "Spine"
    if top in {"schemas", "versioning"}:
        return "Schemas / Contracts"
    if top == "memory":
        return "Receipts / Ledger"
    if top == "curriculum":
        return "Curriculum Boundary"
    if top in {"cognition", "kings_theorem"}:
        return "Crucible Engine"
    if top == "llm":
        return "Router"
    if top == "paradox":
        return "Paradox Engine"
    if top == "council":
        return "Council Router Engine"
    if top == "multiverse":
        return "Multiverse Engine"
    if top == "temporal":
        return "Temporal Engine"
    if top == "governance":
        return "Governance Kernel"
    if top == "thermodynamics":
        return "Thermodynamics / Budget"
    if top in {"operators", "physics"}:
        return "Thermodynamics / Budget"
    return "UNKNOWN"


def _allowed_internal_imports_by_organ() -> dict[str, Set[str]]:
    # Conservative Import Truth matrix (runtime only).
    # - Entry Point may import Spine only.
    # - Spine may import Crucible, Router, Governance, Receipts, Schemas, Thermodynamics.
    # - Router must not import Governance/Spine/Crucible directly (it can be called by Spine).
    # - Receipts may import Schemas only.
    # - Schemas must be self-contained (stdlib only).
    return {
        "Entry Point": {"Entry Point", "Spine"},
        "Spine": {
            "Spine",
            "Crucible Engine",
            "Curriculum Boundary",
            "Router",
            "Governance Kernel",
            "Paradox Engine",
            "Multiverse Engine",
            "Council Router Engine",
            "Temporal Engine",
            "Receipts / Ledger",
            "Schemas / Contracts",
            "Thermodynamics / Budget",
        },
        "Curriculum Boundary": {"Curriculum Boundary", "Schemas / Contracts"},
        "Paradox Engine": {"Paradox Engine", "Schemas / Contracts"},
        "Multiverse Engine": {"Multiverse Engine", "Schemas / Contracts"},
        "Temporal Engine": {"Temporal Engine", "Schemas / Contracts"},
        "Council Router Engine": {"Council Router Engine", "Schemas / Contracts"},
        "Crucible Engine": {"Crucible Engine", "Schemas / Contracts", "Thermodynamics / Budget"},
        "Router": {"Router", "Schemas / Contracts", "Thermodynamics / Budget"},
        "Governance Kernel": {"Governance Kernel", "Schemas / Contracts", "Receipts / Ledger"},
        "Receipts / Ledger": {"Receipts / Ledger", "Schemas / Contracts"},
        "Schemas / Contracts": {"Schemas / Contracts"},
        "Thermodynamics / Budget": {"Thermodynamics / Budget", "Schemas / Contracts"},
    }


def check(
    *,
    src_root: Path,
    canonical_entry_rel: Set[str],
    report_path: Path,
    max_prefix_bytes: int = 256_000,
    max_python_bytes: int = 5_000_000,
) -> List[Violation]:
    violations: List[Violation] = []

    src_root = src_root.resolve()

    # Internal top-level package roots (for organ-level import checks).
    internal_roots: Set[str] = set()
    for child in src_root.iterdir() if src_root.exists() else []:
        if child.is_dir():
            internal_roots.add(child.name)
        elif child.is_file() and child.suffix == ".py":
            internal_roots.add(child.stem)

    allowed_matrix = _allowed_internal_imports_by_organ()

    # Secrets file locators (.env) in runtime surface.
    for path in _iter_files(src_root):
        rel = path.relative_to(src_root).as_posix()
        if path.name == ".env" or path.suffix.lower() == ".env":
            violations.append(Violation("SECRET_FILE_LOCATOR", rel, "dotenv file present in runtime src"))

    # Scan Python modules (imports + entrypoint coupling + secrets prefix scan).
    for py in _iter_py_files(src_root):
        rel = py.relative_to(src_root).as_posix()

        try:
            size = py.stat().st_size
        except Exception:
            violations.append(Violation("READ_ERROR", rel, "stat failure"))
            continue
        if size > max_python_bytes:
            violations.append(Violation("FILE_TOO_LARGE", rel, f"python file exceeds {max_python_bytes} bytes"))
            continue

        prefix = _read_prefix_text(py, max_prefix_bytes)
        if MAIN_GUARD_RE.search(prefix):
            if rel not in canonical_entry_rel:
                violations.append(Violation("ENTRYPOINT_COUPLING", rel, "non-canonical __main__ guard"))

        if PRIVATE_KEY_RE.search(prefix):
            violations.append(Violation("PRIVATE_KEY_BLOCK_LOCATOR", rel, "private key block detected"))
        if APIKEY_LITERAL_RE.search(prefix):
            violations.append(Violation("SECRET_LITERAL_LOCATOR", rel, "apikey/token/secret literal pattern"))

        try:
            text = py.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            violations.append(Violation("READ_ERROR", rel, f"read_text:{e.__class__.__name__}"))
            continue

        try:
            tree = ast.parse(text, filename=str(py))
        except SyntaxError as e:
            violations.append(Violation("AST_SYNTAX_ERROR", rel, f"{e.__class__.__name__}"))
            continue

        organ = _organ_for_rel_path(rel)
        if organ == "UNKNOWN":
            violations.append(Violation("UNKNOWN_ORGAN", rel, "path does not map to a known organ root"))
            continue

        collector = _ImportCollector()
        collector.visit(tree)

        # Training/runtime bleed: forbidden anywhere in runtime (even if nested imports).
        for imp, _is_top_level in collector.all_imports:
            top = _module_top(imp)
            # Internal modules are governed by runtime allowlist + organ matrix; training bans apply to external deps.
            if top not in internal_roots and _is_training_import(imp):
                violations.append(Violation("TRAINING_RUNTIME_BLEED", rel, f"import={imp}"))

        # Provider SDK coupling: forbidden at module import time (top-level imports).
        for imp, is_top_level in collector.all_imports:
            if not is_top_level:
                continue
            if _is_provider_banned(imp):
                violations.append(Violation("PROVIDER_IMPORT_TIME", rel, f"import={imp}"))

        # Import Truth matrix (internal imports only; best-effort).
        allowed_targets = allowed_matrix.get(organ)
        if allowed_targets is None:
            violations.append(Violation("UNKNOWN_ORGAN_MATRIX", rel, f"no matrix row for organ={organ}"))
            continue

        for imp, _is_top_level in collector.all_imports:
            target_organ = _organ_for_import_module(imp, internal_roots)
            if target_organ is None:
                continue
            if target_organ == "UNKNOWN":
                violations.append(Violation("UNKNOWN_INTERNAL_IMPORT", rel, f"import={imp}"))
                continue
            if target_organ not in allowed_targets:
                violations.append(
                    Violation(
                        "ILLEGAL_IMPORT_MATRIX",
                        rel,
                        f"{organ} imports {target_organ} via {imp}",
                    )
                )

    # Secrets scanning for non-python text-like files (prefix only).
    for path in _iter_files(src_root):
        if path.suffix.lower() == ".py":
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name != ".env":
            continue
        rel = path.relative_to(src_root).as_posix()
        prefix = _read_prefix_text(path, max_prefix_bytes)
        if PRIVATE_KEY_RE.search(prefix):
            violations.append(Violation("PRIVATE_KEY_BLOCK_LOCATOR", rel, "private key block detected"))
        if APIKEY_LITERAL_RE.search(prefix):
            violations.append(Violation("SECRET_LITERAL_LOCATOR", rel, "apikey/token/secret literal pattern"))

    # Write report (always).
    report_path.parent.mkdir(parents=True, exist_ok=True)
    status = "PASS" if not violations else "FAIL"

    lines: List[str] = []
    lines.append("# CONSTITUTIONAL GUARD REPORT (W4 S3)")
    lines.append("")
    lines.append(f"Status: {status}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Generated at (UTC): {_utc_now_iso()}")
    lines.append(f"- Runtime src root: `{src_root.as_posix()}`")
    lines.append("")
    lines.append("## Canonical Entry Allowlist")
    if canonical_entry_rel:
        for p in sorted(canonical_entry_rel):
            lines.append(f"- `{p}`")
    else:
        lines.append("- (none configured)")
    lines.append("")
    lines.append("## Import Truth Matrix (Conservative)")
    for src_organ in sorted(allowed_matrix):
        dsts = ", ".join(sorted(allowed_matrix[src_organ]))
        lines.append(f"- {src_organ} -> {dsts}")
    lines.append("")

    if violations:
        lines.append("## Violations")
        for v in sorted(violations, key=lambda x: (x.tag, x.rel_path, x.detail)):
            lines.append(f"- {v.tag}: `{v.rel_path}` :: {v.detail}")
        lines.append("")
    else:
        lines.append("## Violations")
        lines.append("- None")
        lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")

    return violations


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="KT V2 constitutional guard (fail-closed)")
    parser.add_argument(
        "--src-root",
        default=None,
        help="Runtime src root to scan (default: <repo>/04_PROD_TEMPLE_V2/src).",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Report output path (default: <repo>/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md).",
    )
    parser.add_argument(
        "--canonical-entry",
        action="append",
        default=[],
        help="Relative path (from src root) allowed to contain __main__ guard (repeatable).",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    default_src_root = repo_root / "04_PROD_TEMPLE_V2" / "src"
    default_report = repo_root / "04_PROD_TEMPLE_V2" / "docs" / "CONSTITUTIONAL_GUARD_REPORT.md"

    src_root = Path(args.src_root).resolve() if args.src_root else default_src_root
    report_path = Path(args.report).resolve() if args.report else default_report

    canonical_entry_rel: Set[str] = {p.replace("\\", "/").lstrip("/") for p in args.canonical_entry}
    # Default allowlist (explicit): common canonical entry location.
    if not canonical_entry_rel and (src_root / "kt" / "entrypoint.py").exists():
        canonical_entry_rel.add("kt/entrypoint.py")
    if not canonical_entry_rel and (src_root / "entrypoint.py").exists():
        canonical_entry_rel.add("entrypoint.py")

    violations = check(
        src_root=src_root,
        canonical_entry_rel=canonical_entry_rel,
        report_path=report_path,
    )
    if violations:
        print("# CONSTITUTIONAL GUARD: FAIL")
        print(f"- report: {report_path.as_posix()}")
        return 2
    print("# CONSTITUTIONAL GUARD: PASS")
    print(f"- report: {report_path.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
