from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


@dataclass(frozen=True)
class ForbiddenPattern:
    pattern_id: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    pattern_id: str
    snippet: str


_DEFAULT_FORBIDDEN: Tuple[ForbiddenPattern, ...] = (
    ForbiddenPattern("SED_INPLACE", re.compile(r"\bsed\s+-i\b")),
    ForbiddenPattern("SILENT_OR_TRUE", re.compile(r"\|\|\s*true\b")),
    # Heuristic: one-liners that patch tracked source files.
    ForbiddenPattern("PY_WRITE_SOURCE", re.compile(r"python\s+-c.*open\([^)]*\.(?:py|json)[\"']\s*,\s*[\"']w[\"']")),
)


def _iter_scan_files(root: Path, *, include_globs: Sequence[str], exclude_substrings: Sequence[str]) -> Iterable[Path]:
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.as_posix()
        if any(s in rel for s in exclude_substrings):
            continue
        if not any(p.match(g) for g in include_globs):
            continue
        yield p


def scan_no_hidden_mutation(
    *,
    root: Path,
    forbidden: Sequence[ForbiddenPattern] = _DEFAULT_FORBIDDEN,
    include_globs: Sequence[str] = ("*.sh", "*.bash", "*.py", "*.md", "*.txt", "*.ipynb"),
    exclude_substrings: Sequence[str] = (
        "/.git/",
        "/__pycache__/",
        "/.pytest_cache/",
        "/KT_PROD_CLEANROOM/tools/growth/artifacts/",
        "/KT_PROD_CLEANROOM/exports/",
        "/KT_PROD_CLEANROOM/AUDITS/",
        "/_runtime_artifacts/",
        "/tests/",
        "/schemas/",  # schemas can contain regex-like strings; scan enforcement focuses on execution surfaces.
    ),
) -> List[Finding]:
    """
    Fail-closed scanner for "runbook mutation" patterns.

    Scope: execution surfaces (scripts/docs/notebooks), not generated artifacts.
    Deterministic: file iteration order is stable.
    """
    root = root.resolve()
    findings: List[Finding] = []
    for p in _iter_scan_files(root, include_globs=include_globs, exclude_substrings=exclude_substrings):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            for fp in forbidden:
                if fp.regex.search(line):
                    findings.append(
                        Finding(
                            path=p.as_posix(),
                            line=idx,
                            pattern_id=fp.pattern_id,
                            snippet=line.strip()[:300],
                        )
                    )
    return findings


def assert_no_hidden_mutation(*, root: Path) -> None:
    findings = scan_no_hidden_mutation(root=root)
    if not findings:
        return
    preview = "\n".join(f"{f.path}:{f.line} {f.pattern_id} {f.snippet}" for f in findings[:20])
    raise RuntimeError(f"No-hidden-mutation gate FAILED (fail-closed). Findings:\n{preview}")
