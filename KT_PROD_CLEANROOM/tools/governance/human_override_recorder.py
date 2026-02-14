from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.verification.attestation_hmac import env_key_name_for_key_id, sign_hmac
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


def _utc_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mk_signoff(*, key_id: str, payload_hash: str, attestation_mode: str, created_at: str) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "schema_id": "kt.human_signoff.v2",
        "schema_version_hash": schema_version_hash("fl3/kt.human_signoff.v2.json"),
        "signoff_id": "",
        "attestation_mode": attestation_mode,
        "key_id": key_id,
        "payload_hash": payload_hash,
        "created_at": created_at,
    }
    if attestation_mode == "SIMULATED":
        entry["simulated_signature"] = sha256_hex_of_obj({"key_id": key_id, "payload_hash": payload_hash}, drop_keys=set())
    elif attestation_mode == "HMAC":
        env_key = env_key_name_for_key_id(key_id)
        key_val = os.environ.get(env_key)
        if not key_val:
            raise FL3ValidationError(f"Missing {env_key} for HMAC override receipt signing (fail-closed)")
        sig, fp = sign_hmac(key_bytes=key_val.encode("utf-8"), key_id=key_id, payload_hash=payload_hash)
        entry["hmac_signature"] = sig
        entry["hmac_key_fingerprint"] = fp
    else:
        raise FL3ValidationError("PKI mode is declared but not implemented by this recorder (fail-closed)")

    entry["signoff_id"] = sha256_hex_of_obj(entry, drop_keys={"created_at", "signoff_id"})
    validate_schema_bound_object(entry)
    return entry


def build_human_override_receipt(
    *,
    run_id: str,
    lane_id: str,
    override_kind: str,
    override_reason: str,
    evidence_paths: List[str],
    attestation_mode: str,
    key_ids: List[str],
    created_at: str,
) -> Dict[str, Any]:
    ev_sorted = sorted({p.strip() for p in evidence_paths if isinstance(p, str) and p.strip()})
    if len(key_ids) < 2:
        raise FL3ValidationError("override receipt requires >=2 key_ids (fail-closed)")
    if len(set(key_ids)) < 2:
        raise FL3ValidationError("override receipt requires two distinct key_ids (fail-closed)")

    obj: Dict[str, Any] = {
        "schema_id": "kt.human_override_receipt.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.human_override_receipt.v1.json"),
        "override_receipt_id": "",
        "run_id": str(run_id),
        "lane_id": str(lane_id),
        "override_kind": str(override_kind),
        "override_reason": str(override_reason),
        "evidence_paths": ev_sorted,
        "attestation_mode": str(attestation_mode),
        "signoffs": [],
        "created_at": created_at,
        "notes": None,
    }
    payload_hash = sha256_hex_of_obj({k: v for k, v in obj.items() if k not in {"override_receipt_id", "signoffs"}}, drop_keys=set())
    obj["signoffs"] = [_mk_signoff(key_id=k, payload_hash=payload_hash, attestation_mode=attestation_mode, created_at=created_at) for k in key_ids]
    obj["override_receipt_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "override_receipt_id"})
    validate_schema_bound_object(obj)
    return obj


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Record a schema-bound human override receipt (append-only).")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--lane-id", default="FL4_SEAL")
    ap.add_argument("--override-kind", required=True)
    ap.add_argument("--override-reason", required=True)
    ap.add_argument("--evidence-paths", default="", help="Comma-separated evidence relpaths/pointers.")
    ap.add_argument("--attestation-mode", default="SIMULATED", choices=["SIMULATED", "HMAC", "PKI"])
    ap.add_argument("--key-ids", default="SIGNER_A,SIGNER_B", help="Comma-separated key ids (must include >=2 distinct).")
    ap.add_argument("--out", required=True, help="Output path for human_override_receipt.json")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    evidence_paths = [x.strip() for x in str(args.evidence_paths).split(",") if x.strip()]
    key_ids = [x.strip() for x in str(args.key_ids).split(",") if x.strip()]
    created_at = _utc_now_z()
    obj = build_human_override_receipt(
        run_id=str(args.run_id),
        lane_id=str(args.lane_id),
        override_kind=str(args.override_kind),
        override_reason=str(args.override_reason),
        evidence_paths=evidence_paths,
        attestation_mode=str(args.attestation_mode),
        key_ids=key_ids,
        created_at=created_at,
    )
    out_path = Path(args.out).resolve()
    write_text_worm(path=out_path, text=json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", label="human_override_receipt.json")
    print(out_path.as_posix())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc

