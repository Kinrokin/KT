from __future__ import annotations

import argparse
import ast
import importlib.metadata as importlib_metadata
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_SCAN_ROOTS = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src",
    "KT_PROD_CLEANROOM/tools/operator",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests",
    "KT_PROD_CLEANROOM/tests/operator",
)


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return "NON_GIT_WORKTREE"


def _iter_python_files(root: Path, scan_roots: Iterable[str]) -> Iterable[Path]:
    for rel in scan_roots:
        base = (root / rel).resolve()
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if path.is_file():
                yield path


def _extract_import_roots(path: Path) -> Set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    out: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_name = str(alias.name).split(".", 1)[0].strip()
                if root_name:
                    out.add(root_name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and not node.module:
                continue
            module_name = str(node.module or "").split(".", 1)[0].strip()
            if module_name:
                out.add(module_name)
    return out


def _is_first_party(root: Path, module_name: str) -> bool:
    module_path = Path(*module_name.split("."))
    candidates = [
        root / "KT_PROD_CLEANROOM" / module_path,
        root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src" / module_path,
        root / module_path,
    ]
    for candidate in candidates:
        if candidate.exists():
            return True
        if candidate.with_suffix(".py").exists():
            return True
    return False


def _packages_map() -> Dict[str, List[str]]:
    try:
        mapping = importlib_metadata.packages_distributions()
    except Exception:  # noqa: BLE001
        mapping = {}
    return {str(key): [str(item) for item in value] for key, value in mapping.items()}


def _component_for_module(module_name: str, packages_map: Dict[str, List[str]]) -> Dict[str, Any]:
    dist_name = (packages_map.get(module_name) or [module_name])[0]
    try:
        version = importlib_metadata.version(dist_name)
    except Exception:  # noqa: BLE001
        version = "UNKNOWN"
    purl = f"pkg:pypi/{dist_name}@{version}" if version != "UNKNOWN" else f"pkg:pypi/{dist_name}"
    return {
        "type": "library",
        "name": dist_name,
        "version": version,
        "purl": purl,
        "properties": [
            {"name": "kt.import_root", "value": module_name},
        ],
    }


def build_dependency_reports(*, root: Path, scan_roots: Sequence[str] = DEFAULT_SCAN_ROOTS) -> Dict[str, Dict[str, Any]]:
    stdlib_names = set(getattr(sys, "stdlib_module_names", set()))
    packages_map = _packages_map()
    module_files: Dict[str, Set[str]] = {}
    for path in _iter_python_files(root, scan_roots):
        rel = path.relative_to(root).as_posix()
        for module_name in _extract_import_roots(path):
            module_files.setdefault(module_name, set()).add(rel)

    first_party: List[Dict[str, Any]] = []
    stdlib: List[Dict[str, Any]] = []
    third_party: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = []

    for module_name in sorted(module_files.keys()):
        row = {
            "module": module_name,
            "referenced_by": sorted(module_files[module_name]),
        }
        if module_name in stdlib_names:
            stdlib.append(row)
        elif _is_first_party(root, module_name):
            first_party.append(row)
        else:
            third_party.append(row)
            components.append(_component_for_module(module_name, packages_map))

    head_sha = _git_head(root)
    generated_utc = utc_now_iso_z()
    inventory = {
        "schema_id": "kt.operator.dependency_inventory.v1",
        "generated_utc": generated_utc,
        "pinned_head_sha": head_sha,
        "head_source": "git" if head_sha != "NON_GIT_WORKTREE" else "synthetic",
        "scan_roots": [str(item) for item in scan_roots],
        "summary": {
            "first_party_count": len(first_party),
            "stdlib_count": len(stdlib),
            "third_party_count": len(third_party),
        },
        "first_party_modules": first_party,
        "stdlib_modules": stdlib,
        "third_party_modules": third_party,
    }
    environment = {
        "schema_id": "kt.operator.python_environment_manifest.v1",
        "generated_utc": generated_utc,
        "pinned_head_sha": head_sha,
        "head_source": "git" if head_sha != "NON_GIT_WORKTREE" else "synthetic",
        "python_version": sys.version,
        "platform": platform.platform(),
        "third_party_components": [
            {"name": row["name"], "version": row["version"], "purl": row["purl"]}
            for row in components
        ],
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": generated_utc,
            "component": {
                "type": "application",
                "name": "KT",
                "version": head_sha,
            },
            "tools": [
                {
                    "vendor": "KT",
                    "name": "dependency_inventory_emit",
                    "version": "1",
                }
            ],
        },
        "components": components,
        "properties": [
            {"name": "kt.pinned_head_sha", "value": head_sha},
        ],
    }
    return {"inventory": inventory, "environment": environment, "sbom": sbom}


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit deterministic dependency inventory and baseline SBOM preview.")
    ap.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report_root = Path(str(args.report_root)).expanduser()
    if not report_root.is_absolute():
        report_root = (root / report_root).resolve()
    report_root.mkdir(parents=True, exist_ok=True)
    reports = build_dependency_reports(root=root)
    write_json_stable(report_root / "dependency_inventory.json", reports["inventory"])
    write_json_stable(report_root / "python_environment_manifest.json", reports["environment"])
    write_json_stable(report_root / "sbom_cyclonedx.json", reports["sbom"])
    print(json.dumps({"head_sha": reports["inventory"]["pinned_head_sha"], "status": "PASS"}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
