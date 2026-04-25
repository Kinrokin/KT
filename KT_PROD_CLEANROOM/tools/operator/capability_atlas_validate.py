from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.w4_truth_common import (
    CAPABILITY_ATLAS_CONTRACT_REL,
    E2_RECEIPT_REL,
    NEGATIVE_LEDGER_REL,
    TRUTH_LOCK_REL,
    build_capability_atlas,
    required_atlas_row_fields,
    row_missing_fields,
)


DEFAULT_ATLAS_REL = "KT_PROD_CLEANROOM/reports/capability_atlas.json"
DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/capability_atlas_receipt.json"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def build_receipt(*, root: Path, atlas: dict) -> dict:
    missing_rows = []
    missing_refs = []
    for row in atlas.get("topology", []):
        if not isinstance(row, dict):
            continue
        row_missing = row_missing_fields(row, required_fields=required_atlas_row_fields())
        if row_missing:
            missing_rows.append({"surface_id": row.get("surface_id", ""), "missing": row_missing})
            continue
        for key in (
            "execution_path_ref",
            "governing_law_ref",
            "receipt",
            "challenge_pack_ref",
            "benchmark_pack_ref",
        ):
            ref = str(row.get(key, "")).strip()
            if ref and not (root / ref).exists():
                missing_refs.append({"surface_id": row.get("surface_id", ""), "field": key, "ref": ref})

    checks = [
        {
            "check_id": "atlas_schema_id_current",
            "pass": atlas.get("schema_id") == "kt.capability_atlas.v1",
        },
        {
            "check_id": "atlas_has_topology_rows",
            "pass": isinstance(atlas.get("topology"), list) and len(atlas.get("topology", [])) >= 10,
        },
        {
            "check_id": "all_rows_have_path_law_evidence_challenge_benchmark_claim_mapping",
            "pass": not missing_rows,
        },
        {
            "check_id": "all_referenced_support_paths_exist",
            "pass": not missing_refs,
        },
        {
            "check_id": "atlas_evidence_binds_w4_surfaces",
            "pass": CAPABILITY_ATLAS_CONTRACT_REL in atlas.get("evidence_refs", []) and NEGATIVE_LEDGER_REL in atlas.get("evidence_refs", []) and E2_RECEIPT_REL in atlas.get("evidence_refs", []),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    return {
        "schema_id": "kt.w4.capability_atlas_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": str(truth_lock.get("current_repo_head", "")).strip(),
        "status": status,
        "surface_count": len(atlas.get("topology", [])),
        "checks": checks,
        "missing_rows": missing_rows,
        "missing_refs": missing_refs,
        "claim_boundary": (
            "W4 makes the capability atlas answer hostile questions per surface: execution path, law, evidence, challenge pack, benchmark pack, and claim ceiling. "
            "It does not by itself unlock comparative widening."
        ),
        "source_refs": [
            DEFAULT_ATLAS_REL,
            CAPABILITY_ATLAS_CONTRACT_REL,
            NEGATIVE_LEDGER_REL,
            E2_RECEIPT_REL,
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate the current-head capability atlas.")
    parser.add_argument("--atlas-output", default=DEFAULT_ATLAS_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    atlas = build_capability_atlas(root=root)
    receipt = build_receipt(root=root, atlas=atlas)

    write_json_stable(_resolve(root, args.atlas_output), atlas)
    write_json_stable(_resolve(root, args.receipt_output), receipt)

    summary = {
        "status": receipt["status"],
        "surface_count": receipt["surface_count"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
