from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm


REQUIRED_ZONES = ("CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL")


def _resolve(root: Path, rel: str) -> Path:
    return (root / rel).resolve()


def _to_posix(path: str) -> str:
    return str(path).replace("\\", "/")


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
        if rel_path.match(_to_posix(pattern)):
            return True
    return False


def validate_trust_zones(*, root: Path) -> Dict[str, Any]:
    registry = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"))
    canonical_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"))
    readiness_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"))
    runtime_boundary = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json"))

    zones = _zone_map(registry)
    failures: List[str] = []
    checks: List[Dict[str, Any]] = []

    missing_zones = [zone for zone in REQUIRED_ZONES if zone not in zones]
    checks.append({"check": "required_zones_present", "status": "PASS" if not missing_zones else "FAIL", "missing": missing_zones})
    if missing_zones:
        failures.append(f"missing_zones:{','.join(missing_zones)}")

    readiness_includes = [str(x).strip().upper() for x in readiness_scope.get("readiness_includes_zones", []) if str(x).strip()]
    readiness_excludes = [str(x).strip().upper() for x in readiness_scope.get("readiness_excludes_zones", []) if str(x).strip()]
    bad_readiness = [zone for zone in readiness_includes + readiness_excludes if zone not in zones]
    checks.append(
        {
            "check": "readiness_zones_declared_in_registry",
            "status": "PASS" if not bad_readiness else "FAIL",
            "includes": readiness_includes,
            "excludes": readiness_excludes,
        }
    )
    if bad_readiness:
        failures.append(f"unknown_readiness_zones:{','.join(sorted(set(bad_readiness)))}")

    authoritative = [str(x).strip() for x in canonical_scope.get("authoritative_surfaces", []) if str(x).strip()]
    canonical_include = [str(x).strip() for x in zones.get("CANONICAL", {}).get("include", []) if str(x).strip()]
    canonical_exclude = [str(x).strip() for x in zones.get("CANONICAL", {}).get("exclude", []) if str(x).strip()]

    authoritative_mismatches = [pattern for pattern in authoritative if not _matches_any(pattern, canonical_include)]
    checks.append(
        {
            "check": "canonical_authoritative_surfaces_in_canonical_zone",
            "status": "PASS" if not authoritative_mismatches else "FAIL",
            "mismatches": authoritative_mismatches,
        }
    )
    if authoritative_mismatches:
        failures.append("canonical_authoritative_surfaces_outside_canonical_zone")

    quarantined = [str(x).strip() for x in canonical_scope.get("quarantined_from_canonical_truth", []) if str(x).strip()]
    unexcluded_quarantine = [pattern for pattern in quarantined if not _matches_any(pattern, canonical_exclude)]
    checks.append(
        {
            "check": "quarantine_patterns_excluded_from_canonical_zone",
            "status": "PASS" if not unexcluded_quarantine else "FAIL",
            "mismatches": unexcluded_quarantine,
        }
    )
    if unexcluded_quarantine:
        failures.append("quarantine_not_excluded_from_canonical_zone")

    boundary_excludes = [str(x).strip() for x in runtime_boundary.get("canonical_runtime_excludes", []) if str(x).strip()]
    missing_boundary_excludes = [pattern for pattern in boundary_excludes if pattern not in canonical_exclude]
    checks.append(
        {
            "check": "runtime_boundary_excludes_reflected_in_canonical_zone",
            "status": "PASS" if not missing_boundary_excludes else "FAIL",
            "mismatches": missing_boundary_excludes,
        }
    )
    if missing_boundary_excludes:
        failures.append("runtime_boundary_excludes_missing_from_zone")

    canonical_only = readiness_includes == ["CANONICAL"]
    checks.append({"check": "readiness_scoped_to_canonical_only", "status": "PASS" if canonical_only else "FAIL"})
    if not canonical_only:
        failures.append("readiness_scope_not_canonical_only")

    status = "PASS" if not failures else "FAIL"
    return {
        "schema_id": "kt.operator.trust_zone_validation_receipt.v1",
        "status": status,
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate canonical trust-zone and readiness-scope contracts.")
    ap.add_argument("--run-root", default="")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    run_dir = make_run_dir(cmd_name="trust-zone-validate", requested_run_root=str(args.run_root))
    try:
        report = validate_trust_zones(root=repo_root())
        write_json_worm(run_dir / "reports" / "trust_zone_validation_receipt.json", report, label="trust_zone_validation_receipt.json")
        if report["status"] != "PASS":
            return write_failure_artifacts(
                run_dir=run_dir,
                program_id="program.truth.zone_validate",
                failure_name="STOP_GATE_BLOCKED",
                message="; ".join(report.get("failures", [])),
                next_actions=["Repair trust-zone, canonical scope, or readiness scope contracts and rerun trust_zone_validate."],
            )
        print(json.dumps(report, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return write_failure_artifacts(
            run_dir=run_dir,
            program_id="program.truth.zone_validate",
            failure_name="STOP_GATE_BLOCKED",
            message=str(exc),
            next_actions=["Inspect KT_PROD_CLEANROOM/governance/trust_zone_registry.json and related contracts."],
        )


if __name__ == "__main__":
    raise SystemExit(main())
