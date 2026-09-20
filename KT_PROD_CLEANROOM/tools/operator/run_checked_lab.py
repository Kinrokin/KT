"""Run a pinned, finite laboratory contract through the original canonical entry.

No contract is invented here. Review and freeze it before using this operator.
Model assets must already be materialized locally; this command has no download,
upload, secret, training, promotion, or canonical-law activation facility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    src = Path(__file__).resolve().parents[2] / "04_PROD_TEMPLE_V2" / "src"
    sys.path.insert(0, str(src))
    from core.checked_generation import verify_operation
    from core.invariants_gate import CONSTITUTION_VERSION_HASH
    from governance.lab_admission import REQUEST_SCHEMA, operator_session, validate_contract
    from kt.entrypoint import invoke
    from memory.lab_effect import read_record, write_record
    from schemas.checked_task import canonical_bytes, strict_json
    from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH

    raw = args.contract.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.contract_sha256:
        raise RuntimeError("OPERATOR_CONTRACT_PIN")
    contract = validate_contract(strict_json(raw, max_bytes=2 * 1024 * 1024))
    root = Path(contract["output_root"])
    if args.verify_only:
        results = {op: verify_operation(root / op, expected_contract_sha256=args.contract_sha256)
                   for op in contract["operations"]}
        print(json.dumps({"mode": "DETACHED_REPLAY_NO_INFERENCE_NO_EFFECT", "operations": len(results),
                          "original_statuses": {op: value["original"]["status"] for op, value in results.items()}}, sort_keys=True))
        return 0
    statuses = {}
    started = time.perf_counter()
    with operator_session(args.contract, expected_sha256=args.contract_sha256):
        for operation_id in contract["operations"]:
            context = {"schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
                       "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
                       "constitution_version_hash": CONSTITUTION_VERSION_HASH,
                       "artifact_root": str(root), "envelope": {"input": canonical_bytes({
                           "schema_id": REQUEST_SCHEMA, "operation_id": operation_id}).decode()}}
            result = invoke(context)
            status = result.get("status", "MISSING_STATUS")
            statuses[operation_id] = status
            print(json.dumps({"operation_id": operation_id, "status": status}), flush=True)
            # Scientific task failures are retained and the frozen denominator continues.
            # Admission, transport, partial-outcome or recovery failures stop this run.
            if status not in {"CHECKED_EFFECT_RESTORED", "HELD_TASK_PREDICATE", "CHECKED_NONCONSUMING", "REPLAY_NO_INFERENCE_NO_EFFECT"}:
                return 2
    manifest_path = root / "operator_complete.json"
    if manifest_path.exists():
        prior = read_record(manifest_path)
        if prior["contract_sha256"] != args.contract_sha256:
            raise RuntimeError("OPERATOR_COMPLETION_COLLISION")
    else:
        write_record(manifest_path, {"schema_id": "kt.lab.operator_complete.v1", "contract_sha256": args.contract_sha256,
                     "operation_statuses": statuses, "operator_seconds": time.perf_counter() - started,
                     "training_steps": 0, "paid_api_calls": 0,
                     "claim_ceiling": "BOUNDED_LABORATORY_ONLY_NOT_FULL_H4_OR_SCIENTIFIC_SEAL"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
