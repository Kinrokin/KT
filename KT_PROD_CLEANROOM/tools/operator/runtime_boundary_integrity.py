from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"

RUNTIME_BOUNDARY_VERDICT_SETTLED = "CANONICAL_RUNTIME_BOUNDARY_SETTLED"
RUNTIME_BOUNDARY_VERDICT_UNPROVEN = "RUNTIME_BOUNDARY_NOT_PROVEN"

RUNTIME_BOUNDARY_HEAD_VERDICT_SUBJECT = "HEAD_HAS_RUNTIME_BOUNDARY_PROOF"
RUNTIME_BOUNDARY_HEAD_VERDICT_CONTAINS = "HEAD_CONTAINS_RUNTIME_BOUNDARY_EVIDENCE_FOR_SUBJECT"
RUNTIME_BOUNDARY_HEAD_VERDICT_UNPROVEN = "HEAD_RUNTIME_BOUNDARY_CLAIM_UNPROVEN"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _to_posix(path: str) -> str:
    return str(path).replace("\\", "/")


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


def _compatibility_pattern(root_name: str) -> str:
    return f"KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/{root_name}/**"


def build_runtime_boundary_integrity_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    contract = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "runtime_boundary_contract.json")
    runtime_registry = load_json(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json")
    canonical_scope = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "canonical_scope_manifest.json")
    trust_zone_registry = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "trust_zone_registry.json")

    zones = _zone_map(trust_zone_registry)
    canonical_zone = zones.get("CANONICAL", {})
    quarantined_zone = zones.get("QUARANTINED", {})

    contract_canonical_roots = _list(contract, "canonical_runtime_roots")
    contract_compatibility_roots = _list(contract, "compatibility_allowlist_roots")
    contract_excludes = _list(contract, "canonical_runtime_excludes")

    registry_canonical_roots = _list(runtime_registry, "runtime_import_roots")
    registry_compatibility_roots = _list(runtime_registry, "compatibility_allowlist_roots")

    quarantined_from_canonical_truth = _list(canonical_scope, "quarantined_from_canonical_truth")
    canonical_excludes = _list(canonical_zone, "exclude")
    quarantined_includes = _list(quarantined_zone, "include")

    compatibility_patterns = [_compatibility_pattern(root_name) for root_name in registry_compatibility_roots]

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    canonical_match = registry_canonical_roots == contract_canonical_roots
    checks.append(
        {
            "check": "runtime_registry_canonical_roots_match_contract",
            "status": "PASS" if canonical_match else "FAIL",
            "expected": contract_canonical_roots,
            "actual": registry_canonical_roots,
        }
    )
    if not canonical_match:
        failures.append("runtime_registry_canonical_roots_mismatch")

    compatibility_match = registry_compatibility_roots == contract_compatibility_roots
    checks.append(
        {
            "check": "runtime_registry_compatibility_roots_match_contract",
            "status": "PASS" if compatibility_match else "FAIL",
            "expected": contract_compatibility_roots,
            "actual": registry_compatibility_roots,
        }
    )
    if not compatibility_match:
        failures.append("runtime_registry_compatibility_roots_mismatch")

    overlap = sorted(set(registry_canonical_roots).intersection(registry_compatibility_roots))
    checks.append(
        {
            "check": "compatibility_roots_not_canonical",
            "status": "PASS" if not overlap else "FAIL",
            "overlap": overlap,
        }
    )
    if overlap:
        failures.append("compatibility_roots_overlap_canonical_runtime")

    missing_scope_quarantine = [pattern for pattern in compatibility_patterns if pattern not in quarantined_from_canonical_truth]
    checks.append(
        {
            "check": "compatibility_roots_quarantined_in_scope_manifest",
            "status": "PASS" if not missing_scope_quarantine else "FAIL",
            "mismatches": missing_scope_quarantine,
        }
    )
    if missing_scope_quarantine:
        failures.append("compatibility_roots_missing_from_scope_quarantine")

    missing_contract_excludes = [pattern for pattern in compatibility_patterns if pattern not in contract_excludes]
    checks.append(
        {
            "check": "compatibility_roots_excluded_by_runtime_boundary_contract",
            "status": "PASS" if not missing_contract_excludes else "FAIL",
            "mismatches": missing_contract_excludes,
        }
    )
    if missing_contract_excludes:
        failures.append("compatibility_roots_missing_from_runtime_boundary_contract")

    missing_canonical_excludes = [pattern for pattern in compatibility_patterns if not _matches_any(pattern, canonical_excludes)]
    checks.append(
        {
            "check": "compatibility_roots_excluded_from_canonical_zone",
            "status": "PASS" if not missing_canonical_excludes else "FAIL",
            "mismatches": missing_canonical_excludes,
        }
    )
    if missing_canonical_excludes:
        failures.append("compatibility_roots_not_excluded_from_canonical_zone")

    missing_quarantine_zone = [pattern for pattern in compatibility_patterns if not _matches_any(pattern, quarantined_includes)]
    checks.append(
        {
            "check": "compatibility_roots_present_in_quarantined_zone",
            "status": "PASS" if not missing_quarantine_zone else "FAIL",
            "mismatches": missing_quarantine_zone,
        }
    )
    if missing_quarantine_zone:
        failures.append("compatibility_roots_missing_from_quarantined_zone")

    status = "PASS" if not failures else "FAIL"
    validated_head_sha = _git_head(root)
    claim_admissible = status == "PASS"
    verdict = RUNTIME_BOUNDARY_VERDICT_SETTLED if claim_admissible else RUNTIME_BOUNDARY_VERDICT_UNPROVEN
    boundary = (
        "Canonical runtime roots exclude compatibility-only roots, and every compatibility root is quarantined outside canonical runtime truth."
        if claim_admissible
        else "Runtime boundary proof is not admissible; do not claim compatibility-only roots as canonical runtime."
    )

    return {
        "schema_id": "kt.operator.runtime_boundary_integrity_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": validated_head_sha,
        "runtime_boundary_subject_commit": validated_head_sha,
        "contract_id": str(contract.get("contract_id", "")).strip(),
        "runtime_boundary_verdict": verdict,
        "runtime_boundary_claim_admissible": claim_admissible,
        "runtime_boundary_claim_boundary": boundary,
        "canonical_runtime_roots": registry_canonical_roots,
        "compatibility_allowlist_roots": registry_compatibility_roots,
        "authority_refs": [
            "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
        ],
        "checks": checks,
        "failures": failures,
        "report_root": report_root_rel,
    }


def build_runtime_boundary_claims(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    receipt_ref = str((Path(report_root_rel) / "runtime_boundary_integrity_receipt.json").as_posix())
    receipt_path = (root / Path(receipt_ref)).resolve()
    current_head_commit = _git_head(root)

    runtime_boundary_evidence_commit = ""
    runtime_boundary_subject_commit = current_head_commit
    runtime_boundary_verdict = RUNTIME_BOUNDARY_VERDICT_UNPROVEN
    runtime_boundary_claim_admissible = False
    runtime_boundary_claim_boundary = "No passing runtime boundary integrity receipt is present; do not claim canonical runtime settlement."
    canonical_runtime_roots: List[str] = []
    compatibility_allowlist_roots: List[str] = []
    runtime_boundary_evidence_equals_subject = False

    if receipt_path.exists():
        receipt = load_json(receipt_path)
        runtime_boundary_evidence_commit = _git_last_commit_for_paths(root, (receipt_ref,))
        runtime_boundary_subject_commit = str(receipt.get("runtime_boundary_subject_commit", "")).strip() or str(
            receipt.get("validated_head_sha", "")
        ).strip() or current_head_commit
        runtime_boundary_verdict = str(receipt.get("runtime_boundary_verdict", "")).strip() or RUNTIME_BOUNDARY_VERDICT_UNPROVEN
        runtime_boundary_claim_admissible = bool(receipt.get("runtime_boundary_claim_admissible"))
        runtime_boundary_claim_boundary = str(receipt.get("runtime_boundary_claim_boundary", "")).strip() or runtime_boundary_claim_boundary
        canonical_runtime_roots = [str(item).strip() for item in receipt.get("canonical_runtime_roots", []) if str(item).strip()]
        compatibility_allowlist_roots = [
            str(item).strip() for item in receipt.get("compatibility_allowlist_roots", []) if str(item).strip()
        ]
        runtime_boundary_evidence_equals_subject = bool(runtime_boundary_evidence_commit) and (
            runtime_boundary_evidence_commit == runtime_boundary_subject_commit
        )

    return {
        "runtime_boundary_evidence_commit": runtime_boundary_evidence_commit,
        "runtime_boundary_subject_commit": runtime_boundary_subject_commit,
        "runtime_boundary_verdict": runtime_boundary_verdict,
        "runtime_boundary_claim_admissible": runtime_boundary_claim_admissible,
        "runtime_boundary_claim_boundary": runtime_boundary_claim_boundary,
        "runtime_boundary_evidence_equals_subject": runtime_boundary_evidence_equals_subject,
        "runtime_boundary_receipt_refs": [receipt_ref],
        "canonical_runtime_roots": canonical_runtime_roots,
        "compatibility_allowlist_roots": compatibility_allowlist_roots,
    }


def build_runtime_boundary_report(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    current_head_commit = _git_head(root)
    claims = build_runtime_boundary_claims(root=root, report_root_rel=report_root_rel)

    subject_commit = str(claims.get("runtime_boundary_subject_commit", "")).strip()
    head_equals_subject = bool(current_head_commit) and bool(subject_commit) and current_head_commit == subject_commit
    verdict = str(claims.get("runtime_boundary_verdict", "")).strip() or RUNTIME_BOUNDARY_VERDICT_UNPROVEN
    claim_admissible = bool(claims.get("runtime_boundary_claim_admissible"))

    if verdict == RUNTIME_BOUNDARY_VERDICT_SETTLED and claim_admissible and subject_commit:
        head_claim_verdict = (
            RUNTIME_BOUNDARY_HEAD_VERDICT_SUBJECT if head_equals_subject else RUNTIME_BOUNDARY_HEAD_VERDICT_CONTAINS
        )
        head_claim_boundary = (
            "Current HEAD equals runtime_boundary_subject_commit and has fresh runtime-boundary proof."
            if head_equals_subject
            else "Current HEAD contains runtime-boundary evidence for runtime_boundary_subject_commit; it is not itself freshly boundary-proven."
        )
    else:
        head_claim_verdict = RUNTIME_BOUNDARY_HEAD_VERDICT_UNPROVEN
        head_claim_boundary = "Current HEAD has no proven runtime-boundary claim boundary."

    return {
        "schema_id": "kt.operator.runtime_boundary_report.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if claim_admissible else "HOLD",
        "current_head_commit": current_head_commit,
        "runtime_boundary_evidence_commit": str(claims.get("runtime_boundary_evidence_commit", "")).strip(),
        "runtime_boundary_subject_commit": subject_commit,
        "runtime_boundary_verdict": verdict,
        "runtime_boundary_claim_admissible": claim_admissible,
        "runtime_boundary_claim_boundary": str(claims.get("runtime_boundary_claim_boundary", "")).strip(),
        "runtime_boundary_head_equals_subject": head_equals_subject,
        "runtime_boundary_head_claim_verdict": head_claim_verdict,
        "runtime_boundary_head_claim_boundary": head_claim_boundary,
        "canonical_runtime_roots": list(claims.get("canonical_runtime_roots", [])),
        "compatibility_allowlist_roots": list(claims.get("compatibility_allowlist_roots", [])),
        "runtime_boundary_receipt_refs": list(claims.get("runtime_boundary_receipt_refs", [])),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify canonical runtime boundary settlement against registry and quarantine law.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    parser.add_argument("--output", default="")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    receipt = build_runtime_boundary_integrity_receipt(root=root, report_root_rel=str(args.report_root))
    output = str(args.output).strip() or str((Path(str(args.report_root)) / "runtime_boundary_integrity_receipt.json").as_posix())
    output_path = Path(output).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()
    write_json_stable(output_path, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
