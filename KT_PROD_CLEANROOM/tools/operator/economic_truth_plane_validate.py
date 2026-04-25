from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.w4_truth_common import (
    CAPABILITY_ATLAS_CONTRACT_REL,
    ECONOMIC_TRUTH_CONTRACT_REL,
    ECONOMIC_TRUTH_PLANE_REL,
    TRUTH_LOCK_REL,
    build_capability_atlas,
    build_economic_truth_plane,
    required_economic_profile_fields,
    row_missing_fields,
)


DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/economic_truth_plane_receipt.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def build_receipt(*, root: Path, plane: dict, atlas: dict) -> dict:
    profile_ids = {str(profile.get("profile_id", "")).strip() for profile in plane.get("profiles", []) if isinstance(profile, dict)}
    missing_profiles = []
    incomplete_profiles = []
    for row in atlas.get("topology", []):
        if not isinstance(row, dict):
            continue
        profile_id = str(row.get("economic_profile_id", "")).strip()
        if profile_id and profile_id not in profile_ids:
            missing_profiles.append({"surface_id": row.get("surface_id", ""), "economic_profile_id": profile_id})

    for profile in plane.get("profiles", []):
        if not isinstance(profile, dict):
            continue
        missing = row_missing_fields(profile, required_fields=required_economic_profile_fields())
        if missing:
            incomplete_profiles.append({"profile_id": profile.get("profile_id", ""), "missing": missing})

    checks = [
        {
            "check_id": "economic_plane_schema_current",
            "pass": plane.get("schema_id") == "kt.economic_truth_plane.v1",
        },
        {
            "check_id": "economic_plane_has_profiles",
            "pass": isinstance(plane.get("profiles"), list) and len(plane.get("profiles", [])) >= 4,
        },
        {
            "check_id": "all_profiles_have_uncertainty_and_escalation_inputs",
            "pass": not incomplete_profiles,
        },
        {
            "check_id": "atlas_rows_map_to_existing_economic_profiles",
            "pass": not missing_profiles,
        },
        {
            "check_id": "economic_plane_is_bound_to_contracts",
            "pass": (root / ECONOMIC_TRUTH_CONTRACT_REL).exists() and (root / CAPABILITY_ATLAS_CONTRACT_REL).exists(),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    return {
        "schema_id": "kt.w4.economic_truth_plane_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": str(truth_lock.get("current_repo_head", "")).strip(),
        "status": status,
        "profile_count": len(plane.get("profiles", [])),
        "checks": checks,
        "missing_profiles": missing_profiles,
        "incomplete_profiles": incomplete_profiles,
        "claim_boundary": (
            "W4 makes cost-of-uncertainty machine-visible for same-host runtime, verifier handoff, mutation civilization, and cross-host reentry. "
            "It does not widen claims or prove category leadership."
        ),
        "source_refs": [
            ECONOMIC_TRUTH_PLANE_REL,
            ECONOMIC_TRUTH_CONTRACT_REL,
            CAPABILITY_ATLAS_CONTRACT_REL,
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate the economic truth plane.")
    parser.add_argument("--plane-output", default=ECONOMIC_TRUTH_PLANE_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    atlas_path = root / "KT_PROD_CLEANROOM/reports/capability_atlas.json"
    atlas = load_json(atlas_path) if atlas_path.exists() else build_capability_atlas(root=root)
    plane = build_economic_truth_plane(root=root, atlas=atlas)
    receipt = build_receipt(root=root, plane=plane, atlas=atlas)

    write_json_stable(_resolve(root, args.plane_output), plane)
    write_json_stable(_resolve(root, args.receipt_output), receipt)

    summary = {
        "profile_count": receipt["profile_count"],
        "status": receipt["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
