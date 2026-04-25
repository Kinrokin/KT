from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools.operator.titanium_common import repo_root, write_json_stable
from tools.operator.w3_civilization_common import (
    ADAPTER_REGISTRY_REL,
    UNIVERSAL_ADAPTER_ABI_V2_REL,
    build_adapter_abi_v2,
    run_w3_cycle,
    validate_projection_fields,
)


DEFAULT_UNIVERSAL_ADAPTER_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/universal_adapter_receipt.json"
DEFAULT_PROVIDER_INVENTORY_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/provider_inventory_vs_live_receipt.json"


def _load_json(path: Path) -> Dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"FAIL_CLOSED: expected JSON object: {path.as_posix()}")
    return obj


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / rel).resolve(), payload)


def build_provider_inventory_vs_live_receipt(*, root: Path, abi_v2: Dict[str, Any], cycle: Dict[str, Any]) -> Dict[str, Any]:
    governance_registry = _load_json((root / ADAPTER_REGISTRY_REL).resolve())
    inventory_ids = sorted(
        {
            str(item).strip()
            for key in ("ratified_adapter_ids", "experimental_adapter_ids")
            for item in governance_registry.get(key, [])
            if str(item).strip()
        }
    )
    runtime_entries = list(cycle["runtime_registry"].adapters.entries)
    runtime_entry_ids = sorted(entry.adapter_id for entry in runtime_entries)
    live_ids = sorted(cycle["live_manifests"].keys())

    checks = [
        {
            "check_id": "universal_adapter_abi_v2_active",
            "pass": abi_v2["status"] == "ACTIVE",
            "ref": UNIVERSAL_ADAPTER_ABI_V2_REL,
        },
        {
            "check_id": "runtime_registry_matches_active_manifest_ids",
            "pass": runtime_entry_ids == live_ids,
        },
        {
            "check_id": "runtime_registry_live_count_is_exact",
            "pass": len(runtime_entry_ids) == 2,
        },
        {
            "check_id": "governance_inventory_ids_do_not_launder_into_live_runtime",
            "pass": not set(inventory_ids).intersection(runtime_entry_ids),
            "inventory_only_adapter_ids": inventory_ids,
        },
        {
            "check_id": "generated_candidate_is_bound_but_not_live_runtime",
            "pass": cycle["generated_candidate"]["adapter_id"] not in runtime_entry_ids
            or cycle["generated_candidate"]["version"] not in {entry.version for entry in runtime_entries},
            "generated_candidate_status": cycle["generated_candidate"]["status"],
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w3.provider_inventory_vs_live_receipt.v1",
        "generated_utc": abi_v2["generated_utc"],
        "current_git_head": cycle["current_git_head"],
        "status": status,
        "live_runtime_adapter_ids": live_ids,
        "runtime_registry_entry_ids": runtime_entry_ids,
        "inventory_only_adapter_ids": inventory_ids,
        "generated_candidate_ref": cycle["job_dir_ref"],
        "checks": checks,
        "claim_boundary": (
            "W3 proves two active live runtime adapters plus one bounded generated candidate under one contract. "
            "It does not claim that governance inventory breadth is live runtime breadth."
        ),
        "forbidden_claims_not_made": [
            "all_registry_adapters_are_live_runtime",
            "generated_candidate_is_already_cut_over_live_runtime",
            "provider_breadth_exceeds_two_active_same_host_live_manifests",
        ],
    }


def build_universal_adapter_receipt(*, root: Path, abi_v2: Dict[str, Any], cycle: Dict[str, Any]) -> Dict[str, Any]:
    live_required = abi_v2["required_live_manifest_fields"]
    generated_required = abi_v2["required_generated_candidate_fields"]
    live_rows = []
    for adapter_id, row in sorted(cycle["live_manifests"].items()):
        missing = validate_projection_fields(row=row, required_fields=live_required)
        live_rows.append(
            {
                "adapter_id": adapter_id,
                "adapter_class": row["adapter_class"],
                "manifest_path_ref": row["manifest_path_ref"],
                "missing_fields": missing,
                "pass": not missing and row["execution_mode"] == "LIVE" and row["status"] == "ACTIVE",
            }
        )

    generated_missing = validate_projection_fields(row=cycle["generated_candidate"], required_fields=generated_required)
    runtime_hash_rows = []
    for entry in cycle["runtime_registry"].adapters.entries:
        artifact_path = (root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / entry.artifact_path).resolve()
        runtime_hash_rows.append(
            {
                "adapter_id": entry.adapter_id,
                "artifact_path_ref": f"KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/{entry.artifact_path}",
                "artifact_hash_matches": artifact_path.exists()
                and entry.artifact_hash == hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        )

    checks = [
        {
            "check_id": "live_adapter_rows_meet_universal_contract",
            "pass": all(bool(row["pass"]) for row in live_rows),
        },
        {
            "check_id": "runtime_registry_artifact_hashes_match_live_manifests",
            "pass": all(bool(row["artifact_hash_matches"]) for row in runtime_hash_rows),
        },
        {
            "check_id": "generated_candidate_meets_universal_contract",
            "pass": not generated_missing,
            "missing_fields": generated_missing,
        },
        {
            "check_id": "generated_candidate_is_promotion_receipted",
            "pass": cycle["promotion"]["decision"] == "PROMOTE" and cycle["eval_report"]["final_verdict"] == "PASS",
            "job_dir_ref": cycle["job_dir_ref"],
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w3.universal_adapter_receipt.v1",
        "generated_utc": abi_v2["generated_utc"],
        "current_git_head": cycle["current_git_head"],
        "status": status,
        "universal_adapter_abi_ref": UNIVERSAL_ADAPTER_ABI_V2_REL,
        "live_adapter_count": len(live_rows),
        "live_adapter_rows": live_rows,
        "runtime_registry_hash_rows": runtime_hash_rows,
        "generated_candidate": cycle["generated_candidate"],
        "generated_candidate_job_dir_ref": cycle["job_dir_ref"],
        "checks": checks,
        "claim_boundary": (
            "W3 proves one universal adapter contract is executable across the two active live adapters and one bounded "
            "factory-generated candidate. It does not claim broad live adapter activation or runtime cutover."
        ),
        "source_refs": [
            UNIVERSAL_ADAPTER_ABI_V2_REL,
            ADAPTER_REGISTRY_REL,
            cycle["job_dir_ref"],
            cycle["runtime_registry_path_ref"],
        ],
        "forbidden_claims_not_made": [
            "all_inventory_adapters_are_active_runtime",
            "generated_candidate_is_a_live_runtime_adapter",
            "adapter_contract_proves_externality_above_E1",
        ],
    }


def build_universal_adapter_outputs(*, root: Path) -> Dict[str, Any]:
    abi_v2 = build_adapter_abi_v2(root=root)
    cycle = run_w3_cycle(root=root)
    return {
        "abi_v2": abi_v2,
        "provider_inventory_receipt": build_provider_inventory_vs_live_receipt(root=root, abi_v2=abi_v2, cycle=cycle),
        "universal_adapter_receipt": build_universal_adapter_receipt(root=root, abi_v2=abi_v2, cycle=cycle),
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate W3 universal adapter contract and inventory honesty.")
    parser.add_argument("--abi-output", default=UNIVERSAL_ADAPTER_ABI_V2_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_UNIVERSAL_ADAPTER_RECEIPT_REL)
    parser.add_argument("--inventory-output", default=DEFAULT_PROVIDER_INVENTORY_RECEIPT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_universal_adapter_outputs(root=root)
    _write(root, str(args.abi_output), outputs["abi_v2"])
    _write(root, str(args.inventory_output), outputs["provider_inventory_receipt"])
    _write(root, str(args.receipt_output), outputs["universal_adapter_receipt"])
    summary = {
        "generated_candidate_status": outputs["universal_adapter_receipt"]["generated_candidate"]["status"],
        "live_adapter_count": outputs["universal_adapter_receipt"]["live_adapter_count"],
        "status": outputs["universal_adapter_receipt"]["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["universal_adapter_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
