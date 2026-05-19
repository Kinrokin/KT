from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


OUTPUT_RECEIPT = "KT_PROD_CLEANROOM/reports/context_budget_gate_receipt.json"

CURRENT_CONTEXT_INPUTS = (
    "governance/current_claim_ceiling.json",
    "governance/allowed_launch_claims.json",
    "governance/forbidden_launch_claims.json",
    "KT_PROD_CLEANROOM/reports/bounded_launch_readiness_delta_receipt.json",
    "KT_PROD_CLEANROOM/reports/language_normalization_receipt.json",
    "external/attestation_collection_packet.json",
    "commercial/bounded_launch_language_pack.md",
    "docs/current/kt_plain_language_glossary.md",
)

ARCHIVE_INDEX_INPUTS = (
    "repo_cleanup/archive_manifest.json",
    "repo_cleanup/historical_receipt_index.json",
    "repo_cleanup/generated_artifact_retirement_plan.json",
)

LONG_GATE_SHARDS = {
    "FAST": ["focused lane tests", "claim scanner", "JSON parse"],
    "MEDIUM": ["bounded workstream tests", "trust-zone"],
    "LONG": ["truth-barrier", "repo-wide operator sweeps"],
}


def _existing_size(root: Path, paths: Sequence[str]) -> int:
    total = 0
    for raw in paths:
        path = root / raw
        if path.is_file():
            total += path.stat().st_size
    return total


def evaluate(*, root: Path | None = None) -> Dict[str, Any]:
    base = root or repo_root()
    current_present = [raw for raw in CURRENT_CONTEXT_INPUTS if (base / raw).is_file()]
    archive_present = [raw for raw in ARCHIVE_INDEX_INPUTS if (base / raw).is_file()]
    current_missing = [raw for raw in CURRENT_CONTEXT_INPUTS if raw not in current_present]
    archive_missing = [raw for raw in ARCHIVE_INDEX_INPUTS if raw not in archive_present]
    current_bytes = _existing_size(base, CURRENT_CONTEXT_INPUTS)
    archive_index_bytes = _existing_size(base, ARCHIVE_INDEX_INPUTS)
    agentignore = base / ".agentignore"
    agentignore_text = agentignore.read_text(encoding="utf-8-sig") if agentignore.is_file() else ""
    archive_default_ignored = "KT_ARCHIVE/" in agentignore_text and "reports/archive_index/" in agentignore_text
    status = "PASS" if not current_missing and not archive_missing and archive_default_ignored else "BLOCKED"
    return {
        "schema_id": "kt.repo_cleanup.context_budget_gate_receipt.v1",
        "artifact_id": "KT_CONTEXT_BUDGET_GATE_RECEIPT",
        "authority": "CONTEXT_HYGIENE_ONLY_NO_DELETE",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_context_first": True,
        "delete_authorized": False,
        "archive_default_loaded": False,
        "archive_default_ignored": archive_default_ignored,
        "current_inputs_present": current_present,
        "current_inputs_missing": current_missing,
        "archive_index_inputs_present": archive_present,
        "archive_index_inputs_missing": archive_missing,
        "estimated_current_context_bytes": current_bytes,
        "estimated_archive_index_bytes": archive_index_bytes,
        "long_gate_shards": LONG_GATE_SHARDS,
        "blockers": [
            *[
                {"blocker_id": "current_context_input_missing", "path": raw, "status": "BLOCKING"}
                for raw in current_missing
            ],
            *[
                {"blocker_id": "archive_index_input_missing", "path": raw, "status": "BLOCKING"}
                for raw in archive_missing
            ],
            *(
                []
                if archive_default_ignored
                else [{"blocker_id": "agentignore_does_not_exclude_archive_context", "status": "BLOCKING"}]
            ),
        ],
    }


def write_receipt(root: Path, receipt: Dict[str, Any]) -> None:
    write_json_stable(root / OUTPUT_RECEIPT, receipt)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate KT current-vs-archive context budget hygiene.")
    parser.add_argument("--write-receipt", action="store_true")
    args = parser.parse_args(argv)
    root = repo_root()
    receipt = evaluate(root=root)
    if args.write_receipt:
        write_receipt(root, receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
