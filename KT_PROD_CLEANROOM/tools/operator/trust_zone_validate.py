from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.runtime_boundary_integrity import build_runtime_boundary_integrity_receipt
from tools.operator.titanium_common import load_json, make_run_dir, repo_root, write_failure_artifacts, write_json_worm
from tools.operator.truth_authority import expected_readiness_excludes, frozen_surface_coverage


REQUIRED_ZONES = ("CANONICAL", "LAB", "ARCHIVE", "COMMERCIAL", "TOOLCHAIN_PROVING", "GENERATED_RUNTIME_TRUTH", "QUARANTINED")


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
        pattern_norm = _to_posix(pattern)
        if rel_path.match(pattern_norm):
            return True
        wildcard_positions = [idx for idx in (pattern_norm.find("*"), pattern_norm.find("?"), pattern_norm.find("[")) if idx >= 0]
        base = pattern_norm[: min(wildcard_positions)] if wildcard_positions else pattern_norm
        if base and rel.startswith(base):
            return True
    return False


def _list(payload: Dict[str, Any], key: str) -> List[str]:
    return [str(x).strip() for x in payload.get(key, []) if str(x).strip()]


def _canonical_primary_surfaces(canonical_scope: Dict[str, Any]) -> List[str]:
    primary = _list(canonical_scope, "canonical_primary_surfaces")
    if primary:
        return primary
    authoritative = _list(canonical_scope, "authoritative_surfaces")
    return [item for item in authoritative if not item.startswith("KT_PROD_CLEANROOM/reports/")]


def _generated_truth_surfaces(canonical_scope: Dict[str, Any]) -> List[str]:
    derived = _list(canonical_scope, "generated_truth_surfaces")
    if derived:
        return derived
    authoritative = _list(canonical_scope, "authoritative_surfaces")
    return [item for item in authoritative if item.startswith("KT_PROD_CLEANROOM/reports/")]


def _toolchain_proving_surfaces(canonical_scope: Dict[str, Any]) -> List[str]:
    return _list(canonical_scope, "toolchain_proving_surfaces")


def validate_trust_zones(*, root: Path) -> Dict[str, Any]:
    registry = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"))
    canonical_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json"))
    readiness_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/readiness_scope_manifest.json"))
    runtime_boundary = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json"))
    freeze_manifest = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/canonical_freeze_manifest.json"))
    amendment_scope = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/amendment_scope_manifest.json"))
    settled_truth = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/settled_truth_source_contract.json"))
    execution_board = load_json(_resolve(root, "KT_PROD_CLEANROOM/governance/execution_board.json"))

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

    canonical_include = _list(zones.get("CANONICAL", {}), "include")
    canonical_exclude = _list(zones.get("CANONICAL", {}), "exclude")
    toolchain_include = _list(zones.get("TOOLCHAIN_PROVING", {}), "include")
    generated_include = _list(zones.get("GENERATED_RUNTIME_TRUTH", {}), "include")
    quarantine_include = _list(zones.get("QUARANTINED", {}), "include")
    commercial_include = _list(zones.get("COMMERCIAL", {}), "include")

    primary_surfaces = _canonical_primary_surfaces(canonical_scope)
    primary_mismatches = [pattern for pattern in primary_surfaces if not _matches_any(pattern, canonical_include)]
    checks.append(
        {
            "check": "canonical_primary_surfaces_in_canonical_zone",
            "status": "PASS" if not primary_mismatches else "FAIL",
            "mismatches": primary_mismatches,
        }
    )
    if primary_mismatches:
        failures.append("canonical_primary_surfaces_outside_canonical_zone")

    toolchain_surfaces = _toolchain_proving_surfaces(canonical_scope)
    toolchain_declared = bool(toolchain_surfaces)
    toolchain_mismatches = [pattern for pattern in toolchain_surfaces if not _matches_any(pattern, toolchain_include)]
    toolchain_canonical_overlap = [pattern for pattern in toolchain_surfaces if _matches_any(pattern, canonical_include)]
    checks.append(
        {
            "check": "toolchain_proving_surfaces_declared",
            "status": "PASS" if toolchain_declared else "FAIL",
            "count": len(toolchain_surfaces),
        }
    )
    checks.append(
        {
            "check": "toolchain_proving_surfaces_in_toolchain_zone",
            "status": "PASS" if not toolchain_mismatches else "FAIL",
            "mismatches": toolchain_mismatches,
        }
    )
    checks.append(
        {
            "check": "toolchain_proving_surfaces_not_in_canonical_zone",
            "status": "PASS" if not toolchain_canonical_overlap else "FAIL",
            "mismatches": toolchain_canonical_overlap,
        }
    )
    if not toolchain_declared:
        failures.append("toolchain_proving_surfaces_missing")
    if toolchain_mismatches:
        failures.append("toolchain_proving_surfaces_outside_toolchain_zone")
    if toolchain_canonical_overlap:
        failures.append("toolchain_proving_surfaces_still_canonical")

    generated_truth_surfaces = _generated_truth_surfaces(canonical_scope)
    generated_mismatches = [pattern for pattern in generated_truth_surfaces if not _matches_any(pattern, generated_include)]
    checks.append(
        {
            "check": "generated_truth_surfaces_in_generated_zone",
            "status": "PASS" if not generated_mismatches else "FAIL",
            "mismatches": generated_mismatches,
        }
    )
    if generated_mismatches:
        failures.append("generated_truth_surfaces_outside_generated_zone")

    documentary_only = _list(canonical_scope, "documentary_only_surfaces")
    documentary_mismatches = [pattern for pattern in documentary_only if not _matches_any(pattern, commercial_include)]
    checks.append(
        {
            "check": "documentary_only_surfaces_in_commercial_zone",
            "status": "PASS" if not documentary_mismatches else "FAIL",
            "mismatches": documentary_mismatches,
        }
    )
    if documentary_mismatches:
        failures.append("documentary_surfaces_outside_commercial_zone")

    quarantined = _list(canonical_scope, "quarantined_from_canonical_truth")
    unexcluded_quarantine = [pattern for pattern in quarantined if not _matches_any(pattern, canonical_exclude)]
    quarantine_zone_mismatches = [pattern for pattern in quarantined if not _matches_any(pattern, quarantine_include)]
    checks.append(
        {
            "check": "quarantine_patterns_excluded_from_canonical_zone",
            "status": "PASS" if not unexcluded_quarantine else "FAIL",
            "mismatches": unexcluded_quarantine,
        }
    )
    checks.append(
        {
            "check": "quarantine_patterns_in_quarantined_zone",
            "status": "PASS" if not quarantine_zone_mismatches else "FAIL",
            "mismatches": quarantine_zone_mismatches,
        }
    )
    if unexcluded_quarantine:
        failures.append("quarantine_not_excluded_from_canonical_zone")
    if quarantine_zone_mismatches:
        failures.append("quarantine_not_in_quarantined_zone")

    boundary_excludes = _list(runtime_boundary, "canonical_runtime_excludes")
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
    expected_excludes = expected_readiness_excludes()
    readiness_excludes_ok = sorted(readiness_excludes) == expected_excludes
    checks.append({"check": "readiness_scoped_to_canonical_only", "status": "PASS" if canonical_only else "FAIL"})
    checks.append(
        {
            "check": "readiness_excludes_all_noncanonical_zones",
            "status": "PASS" if readiness_excludes_ok else "FAIL",
            "expected": expected_excludes,
            "actual": sorted(readiness_excludes),
        }
    )
    if not canonical_only:
        failures.append("readiness_scope_not_canonical_only")
    if not readiness_excludes_ok:
        failures.append("readiness_excludes_incomplete")

    frozen_surfaces = _list(freeze_manifest, "frozen_surfaces")
    frozen_allowed_zone_patterns = [*canonical_include, *toolchain_include]
    frozen_outside_allowed_zones = [pattern for pattern in frozen_surfaces if not _matches_any(pattern, frozen_allowed_zone_patterns)]
    missing_protection = frozen_surface_coverage(
        frozen_surfaces=frozen_surfaces,
        protected_surfaces=_list(amendment_scope, "protected_surfaces"),
    )
    checks.append(
        {
            "check": "frozen_surfaces_live_in_canonical_or_toolchain_zone",
            "status": "PASS" if not frozen_outside_allowed_zones else "FAIL",
            "mismatches": frozen_outside_allowed_zones,
        }
    )
    checks.append(
        {
            "check": "frozen_surfaces_covered_by_amendment_scope",
            "status": "PASS" if not missing_protection else "FAIL",
            "mismatches": missing_protection,
        }
    )
    if frozen_outside_allowed_zones:
        failures.append("frozen_surfaces_outside_authoritative_or_toolchain_zone")
    if missing_protection:
        failures.append("frozen_surfaces_missing_amendment_protection")

    truth_root = str(settled_truth.get("current_head_truth_root", "")).strip()
    truth_root_ok = bool(truth_root) and _matches_any(truth_root, generated_include)
    checks.append(
        {
            "check": "settled_truth_root_in_generated_zone",
            "status": "PASS" if truth_root_ok else "FAIL",
            "truth_root": truth_root,
        }
    )
    if not truth_root_ok:
        failures.append("settled_truth_root_outside_generated_zone")

    board_truth_source = str(execution_board.get("authoritative_current_head_truth_source", "")).strip()
    if board_truth_source:
        board_truth_source_ok = _matches_any(board_truth_source, generated_include)
    else:
        board_truth_source_ok = True
    checks.append(
        {
            "check": "execution_board_truth_source_in_generated_zone",
            "status": "PASS" if board_truth_source_ok else "FAIL",
            "truth_source": board_truth_source,
        }
    )
    if not board_truth_source_ok:
        failures.append("execution_board_truth_source_outside_generated_zone")

    runtime_boundary = build_runtime_boundary_integrity_receipt(root=root)
    checks.extend(list(runtime_boundary.get("checks", [])))
    for failure in runtime_boundary.get("failures", []):
        failure_text = str(failure).strip()
        if failure_text:
            failures.append(failure_text)

    status = "PASS" if not failures else "FAIL"
    return {
        "schema_id": "kt.operator.trust_zone_validation_receipt.v2",
        "status": status,
        "checks": checks,
        "failures": failures,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate seven-zone law, readiness scope, truth authority, and sacred-surface boundaries.")
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
                next_actions=["Repair trust-zone, canonical scope, readiness scope, or truth-authority contracts and rerun trust_zone_validate."],
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
