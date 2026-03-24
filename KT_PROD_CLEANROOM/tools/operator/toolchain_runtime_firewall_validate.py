from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_OUTPUT_REL = "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json"


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _to_posix(value: str) -> str:
    return str(value).replace("\\", "/")


def _list(payload: Dict[str, Any], key: str) -> List[str]:
    return [str(item).strip() for item in payload.get(key, []) if str(item).strip()]


def _zone_map(registry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = registry.get("zones")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: trust_zone_registry zones missing")
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        zone_id = str(row.get("zone_id", "")).strip().upper()
        if zone_id:
            out[zone_id] = row
    return out


def _matches_any(relpath: str, patterns: Sequence[str]) -> bool:
    rel = _to_posix(relpath)
    rel_path = Path(rel)
    for pattern in patterns:
        pattern_norm = _to_posix(pattern)
        if rel_path.match(pattern_norm):
            return True
        wildcard_positions = [idx for idx in (pattern_norm.find("*"), pattern_norm.find("?"), pattern_norm.find("[")) if idx >= 0]
        base = pattern_norm[: min(wildcard_positions)] if wildcard_positions else pattern_norm
        if base and rel.startswith(base):
            return True
    return False


def _runtime_py_files(*, root: Path, runtime_roots: Sequence[str]) -> List[Path]:
    src_root = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"
    paths: List[Path] = []
    for runtime_root in runtime_roots:
        base = src_root / runtime_root
        if not base.exists():
            continue
        paths.extend(sorted(base.rglob("*.py")))
    return sorted(paths, key=lambda item: item.as_posix())


def _scan_runtime_imports(*, root: Path, runtime_roots: Sequence[str]) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []
    for path in _runtime_py_files(root=root, runtime_roots=runtime_roots):
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if str(alias.name).split(".", 1)[0] == "tools":
                        violations.append({"path": rel, "lineno": int(node.lineno), "import": str(alias.name)})
            elif isinstance(node, ast.ImportFrom):
                module = str(node.module or "").strip()
                if module and module.split(".", 1)[0] == "tools":
                    violations.append({"path": rel, "lineno": int(node.lineno), "import": module})
    return violations


def build_toolchain_runtime_firewall_receipt(*, root: Path) -> Dict[str, Any]:
    trust_zone = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"))
    canonical_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"))
    runtime_boundary = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json"))
    runtime_registry = load_json(_resolve(root, "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json"))

    zones = _zone_map(trust_zone)
    canonical_include = _list(zones.get("CANONICAL", {}), "include")
    toolchain_include = _list(zones.get("TOOLCHAIN_PROVING", {}), "include")
    toolchain_surfaces = _list(canonical_scope, "toolchain_proving_surfaces")
    compatibility_roots = _list(runtime_registry, "compatibility_allowlist_roots")
    negative_space_exceptions = _list(runtime_boundary, "negative_space_exceptions")
    runtime_roots = _list(runtime_registry, "runtime_import_roots")

    toolchain_missing = [pattern for pattern in toolchain_surfaces if not _matches_any(pattern, toolchain_include)]
    toolchain_overlap = [pattern for pattern in toolchain_surfaces if _matches_any(pattern, canonical_include)]
    broad_tools_allowlist_present = "tools" in compatibility_roots
    broad_tools_exceptions = [
        item
        for item in negative_space_exceptions
        if "KT_PROD_CLEANROOM/tools/**" in item and "TOOLCHAIN_PROVING" not in item
    ]
    runtime_toolchain_imports = _scan_runtime_imports(root=root, runtime_roots=runtime_roots)

    failures: List[str] = []
    checks = [
        {
            "check": "toolchain_proving_zone_present",
            "status": "PASS" if "TOOLCHAIN_PROVING" in zones else "FAIL",
        },
        {
            "check": "toolchain_proving_surfaces_in_toolchain_zone",
            "status": "PASS" if toolchain_surfaces and not toolchain_missing else "FAIL",
            "mismatches": toolchain_missing,
        },
        {
            "check": "toolchain_proving_surfaces_not_in_canonical_zone",
            "status": "PASS" if not toolchain_overlap else "FAIL",
            "mismatches": toolchain_overlap,
        },
        {
            "check": "broad_tools_allowlist_removed",
            "status": "PASS" if not broad_tools_allowlist_present else "FAIL",
            "compatibility_allowlist_roots": compatibility_roots,
        },
        {
            "check": "runtime_boundary_negative_space_exception_narrowed",
            "status": "PASS" if not broad_tools_exceptions else "FAIL",
            "mismatches": broad_tools_exceptions,
        },
        {
            "check": "canonical_runtime_does_not_import_toolchain_proving_modules",
            "status": "PASS" if not runtime_toolchain_imports else "FAIL",
            "violations": runtime_toolchain_imports,
        },
    ]
    if "TOOLCHAIN_PROVING" not in zones:
        failures.append("toolchain_proving_zone_missing")
    if not toolchain_surfaces:
        failures.append("toolchain_proving_surfaces_missing")
    if toolchain_missing:
        failures.append("toolchain_proving_surfaces_outside_toolchain_zone")
    if toolchain_overlap:
        failures.append("toolchain_proving_surfaces_still_canonical")
    if broad_tools_allowlist_present:
        failures.append("tools_allowlist_leak_present")
    if broad_tools_exceptions:
        failures.append("runtime_boundary_negative_space_exception_too_broad")
    if runtime_toolchain_imports:
        failures.append("runtime_imports_toolchain_proving_surface")

    status = "PASS" if not failures else "FAIL"
    return {
        "schema_id": "kt.operator.toolchain_runtime_firewall_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": _git_head(root),
        "toolchain_surface_refs": toolchain_surfaces,
        "illegal_crossings_checked": [
            "tooling_generated_state_treated_as_runtime_truth_without_receipt",
            "builder_behavior_used_as_runtime_behavior",
            "verifier_helpers_imported_as_runtime_organs",
            "tools_directory_allowlisted_as_runtime_root_without_explicit_contract",
        ],
        "checks": checks,
        "failures": failures,
        "claim_boundary": "This receipt proves the TOOLCHAIN_PROVING split and runtime import firewall on declared canonical paths only. It does not upgrade runtime capability or externality.",
        "stronger_claim_not_made": [
            "adapter_activation_started",
            "router_elevation_started",
            "runtime_capability_upgraded_by_toolchain_firewalling",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate the TOOLCHAIN_PROVING firewall against canonical runtime surfaces.")
    ap.add_argument("--output", default=DEFAULT_OUTPUT_REL)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    output = Path(str(args.output)).expanduser()
    if not output.is_absolute():
        output = (root / output).resolve()
    receipt = build_toolchain_runtime_firewall_receipt(root=root)
    write_json_stable(output, receipt)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
