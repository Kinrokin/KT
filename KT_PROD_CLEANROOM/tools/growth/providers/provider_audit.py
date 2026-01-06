from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


SCHEMA_ID = "kt.provider_audit"
SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: str  # PASS | FAIL
    details: Dict[str, Any]


def _repo_root() -> Path:
    # .../KT_PROD_CLEANROOM/tools/growth/providers/provider_audit.py -> repo root
    return Path(__file__).resolve().parents[4]


def _cleanroom_root() -> Path:
    # .../KT_PROD_CLEANROOM/tools/growth/providers/provider_audit.py -> KT_PROD_CLEANROOM
    return Path(__file__).resolve().parents[3]


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(_repo_root().resolve()).as_posix()
    except Exception:
        return path.as_posix()


def _read_text_prefix(path: Path, *, max_bytes: int = 256_000) -> str:
    data = path.read_bytes()
    return data[:max_bytes].decode("utf-8", errors="replace")


def _check_file_exists(check_id: str, path: Path) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        status="PASS" if path.exists() else "FAIL",
        details={"path": _rel(path)},
    )


def _scan_forbidden_imports(*, roots: Sequence[Path]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    forbidden_modules = {
        "requests",
        "openai",
        "anthropic",
        "groq",
        "cerebras",
        "google.generativeai",
        "vertexai",
        "tiktoken",
    }
    allow_stdlib_network = {"http.client", "ssl", "socket", "urllib.request", "urllib.error"}

    violations: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    import_re = re.compile(r"^\s*(from|import)\s+([a-zA-Z0-9_\.]+)", re.MULTILINE)

    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            text = _read_text_prefix(path)
            for m in import_re.finditer(text):
                mod = m.group(2)
                top = mod.split(".", 1)[0]
                if mod in allow_stdlib_network or top in allow_stdlib_network:
                    continue
                if mod in forbidden_modules or top in forbidden_modules:
                    violations.append(
                        {
                            "path": _rel(path),
                            "import": mod,
                        }
                    )
            if "NOT_IMPLEMENTED" in text:
                warnings.append({"path": _rel(path), "tag": "NOT_IMPLEMENTED"})
    return violations, warnings


def _check_provider_registry() -> CheckResult:
    try:
        # Import runtime provider registry without executing any network calls.
        # Ensure the V2 runtime src/ is importable for this audit.
        repo_root = _repo_root()
        cleanroom_root = _cleanroom_root()
        runtime_src = cleanroom_root / "04_PROD_TEMPLE_V2" / "src"
        sys.path.insert(0, str(runtime_src))
        sys.path.insert(0, str(repo_root))
        from council.providers.provider_registry import ProviderRegistry  # type: ignore

        registry = ProviderRegistry.build_default()
        provider_ids = sorted(registry.providers.keys())
        required = {"dry_run", "openai"}
        missing = sorted(required - set(provider_ids))
        return CheckResult(
            check_id="provider_registry",
            status="PASS" if not missing else "FAIL",
            details={
                "registered_provider_ids": provider_ids,
                "missing_required": missing,
                "note": "Registry import performed without network calls (tooling audit assumption).",
            },
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            check_id="provider_registry",
            status="FAIL",
            details={"error": f"{exc.__class__.__name__}: {exc}"},
        )


def _check_live_hashed_paths() -> CheckResult:
    live_hashed_run = _cleanroom_root() / "tools" / "live" / "live_hashed_run.py"
    provider_impl = _cleanroom_root() / "04_PROD_TEMPLE_V2" / "src" / "council" / "providers" / "live_provider_openai_hashed.py"
    ok = live_hashed_run.exists() and provider_impl.exists()
    return CheckResult(
        check_id="live_hashed_presence",
        status="PASS" if ok else "FAIL",
        details={
            "live_hashed_run": _rel(live_hashed_run),
            "live_provider_openai_hashed": _rel(provider_impl),
        },
    )


def _check_growth_does_not_import_runtime() -> CheckResult:
    growth_root = _cleanroom_root() / "tools" / "growth"
    violations: List[Dict[str, Any]] = []
    if growth_root.exists():
        for path in growth_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            # This audit script is allowed to import runtime modules for inspection.
            if path.name == "provider_audit.py" and "providers" in path.parts:
                continue
            text = _read_text_prefix(path)
            if re.search(r"^\s*(from|import)\s+council\.", text, flags=re.MULTILINE):
                violations.append({"path": _rel(path), "import": "council.*"})
            if re.search(r"^\s*(from|import)\s+kt\.", text, flags=re.MULTILINE):
                violations.append({"path": _rel(path), "import": "kt.*"})
    return CheckResult(
        check_id="growth_runtime_import_wall",
        status="PASS" if not violations else "FAIL",
        details={"violations": violations},
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KT provider presence audit (read-only; no network).")
    p.add_argument("--out", default="", help="Write JSON report to path (optional).")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    repo_root = _repo_root()
    cleanroom_root = _cleanroom_root()

    checks: List[CheckResult] = []

    providers_root = cleanroom_root / "04_PROD_TEMPLE_V2" / "src" / "council" / "providers"
    checks.append(_check_file_exists("providers_dir_exists", providers_root))
    checks.append(_check_file_exists("provider_registry_py_exists", providers_root / "provider_registry.py"))
    checks.append(_check_file_exists("live_provider_openai_py_exists", providers_root / "live_provider_openai.py"))
    checks.append(_check_live_hashed_paths())
    checks.append(_check_provider_registry())
    checks.append(_check_growth_does_not_import_runtime())

    forbidden, warnings = _scan_forbidden_imports(roots=[providers_root])
    checks.append(
        CheckResult(
            check_id="provider_forbidden_imports",
            status="PASS" if not forbidden else "FAIL",
            details={"violations": forbidden, "warnings": warnings},
        )
    )

    failures = [c for c in checks if c.status != "PASS"]
    report = {
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not failures else "FAIL",
        "repo_root": _rel(repo_root),
        "cleanroom_root": _rel(cleanroom_root),
        "checks": [
            {"check_id": c.check_id, "status": c.status, "details": c.details}
            for c in checks
        ],
        "failure_count": len(failures),
    }

    text = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True)
    if args.out:
        out_path = (Path(args.out).resolve() if not Path(args.out).is_absolute() else Path(args.out))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        print(text)

    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
