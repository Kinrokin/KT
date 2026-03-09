from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.governance.lane_policy import repo_clean_gate_for_current_lane
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import canonical_json, repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


_SCHEMA_ID = "kt.training_admission_receipt.v1"
_SCHEMA_FILE = "fl3/kt.training_admission_receipt.v1.json"
_SCHEMA_VERSION_HASH = schema_version_hash(_SCHEMA_FILE)

_RC_DENIED = "TRAINING_ADMISSION_DENIED"
_RC_CONFIG_INVALID = "TRAINING_ADMISSION_CONFIG_INVALID"
_RC_NONREPRODUCIBLE = "TRAINING_ADMISSION_NONREPRODUCIBLE"
_RC_LAW_BUNDLE_HASH_MISMATCH = "LAW_BUNDLE_HASH_MISMATCH"
_RC_TIME_CONTRACT_VIOLATION = "TIME_CONTRACT_VIOLATION"


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _sha256_job_obj(job: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(job))


def _allowed_reason_codes(*, taxonomy: Dict[str, Any]) -> Set[str]:
    mappings = taxonomy.get("mappings") if isinstance(taxonomy.get("mappings"), list) else []
    out: Set[str] = set()
    for m in mappings:
        if isinstance(m, dict):
            rc = m.get("reason_code")
            if isinstance(rc, str) and rc.strip():
                out.add(rc.strip())
    return out


def build_training_admission_receipt(
    *,
    repo_root: Path,
    job_path: Path,
    lane_id: str,
    expected_law_bundle_hash: Optional[str] = None,
    law_bundle_sha_rel: str = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
    failure_taxonomy_rel: str = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
    time_contract_rel: str = "KT_PROD_CLEANROOM/AUDITS/FL4_TIME_CONTRACT.json",
) -> Dict[str, Any]:
    """
    Deterministic master valve for training/evaluation/merge/promotion entry.

    FAIL-CLOSED doctrine:
      - Any structural defect, invalid schema, or dirty repo -> FAIL_CLOSED.
      - Reason codes must be closed over FAILURE_TAXONOMY_FL3.

    Determinism:
      - created_at is fixed (1970 epoch) via factory timeutil.
      - admission_receipt_id is derived from a canonical hash surface that drops created_at.
    """
    reasons: List[str] = []
    notes: Optional[str] = None

    # 1) Load and validate required global governance inputs.
    time_contract_path = (repo_root / time_contract_rel).resolve()
    time_contract = _read_json_dict(time_contract_path, name="time_contract")
    try:
        validate_schema_bound_object(time_contract)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_TIME_CONTRACT_VIOLATION)

    failure_taxonomy = load_failure_taxonomy(repo_root=repo_root, relpath=failure_taxonomy_rel)
    allowed_rc = _allowed_reason_codes(taxonomy=failure_taxonomy)

    # 2) Read jobspec and validate schema binding.
    job_path = job_path.resolve()
    try:
        job = _read_json_dict(job_path, name="job")
        validate_schema_bound_object(job)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_CONFIG_INVALID)
        job = {}

    # 3) Canonical lane requires a clean repo; local/test lanes do not.
    ok, _err = repo_clean_gate_for_current_lane(repo_root)
    if not ok:
        reasons.append(_RC_DENIED)

    # 4) Law bundle pin.
    law_sha_path = (repo_root / law_bundle_sha_rel).resolve()
    try:
        law_bundle_hash = law_sha_path.read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        law_bundle_hash = ""
    if len(law_bundle_hash) != 64 or any(c not in "0123456789abcdef" for c in law_bundle_hash.lower()):
        reasons.append(_RC_CONFIG_INVALID)
    if expected_law_bundle_hash and law_bundle_hash and str(expected_law_bundle_hash) != law_bundle_hash:
        reasons.append(_RC_LAW_BUNDLE_HASH_MISMATCH)

    # 5) Deterministic receipt payload.
    created_at = utc_now_z()
    decision = "PASS" if not reasons else "FAIL_CLOSED"

    # Close reason codes over the failure taxonomy.
    reasons = sorted(set(reasons))
    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        # Fail-closed but never emit unknown reason codes.
        decision = "FAIL_CLOSED"
        reasons = sorted(set([_RC_CONFIG_INVALID]))
        notes = "closed_reason_codes_violation"

    job_sha256 = _sha256_job_obj(job) if isinstance(job, dict) else sha256_text("null")

    job_ref: str
    try:
        job_ref = str(job_path.relative_to(repo_root).as_posix())
    except Exception:
        job_ref = f"external_job_sha256:{job_sha256}"
    failure_taxonomy_id = str(failure_taxonomy.get("taxonomy_id", ""))

    obj: Dict[str, Any] = {
        "schema_id": _SCHEMA_ID,
        "schema_version_hash": _SCHEMA_VERSION_HASH,
        "admission_receipt_id": "",
        "lane_id": str(lane_id),
        "decision": decision,
        "reason_codes": reasons,
        "job_ref": job_ref,
        "job_sha256": job_sha256,
        "law_bundle_hash": str(law_bundle_hash),
        "failure_taxonomy_id": failure_taxonomy_id,
        "created_at": created_at,
    }
    if notes is not None:
        obj["notes"] = notes

    obj["admission_receipt_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "admission_receipt_id"})

    # Fail closed if receipt itself is not schema-valid.
    validate_schema_bound_object(obj)
    return obj


def ensure_training_admission_receipt(
    *,
    repo_root: Path,
    job_path: Path,
    job_dir: Path,
    lane_id: str,
    expected_law_bundle_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Write `training_admission_receipt.json` into the job_dir (WORM).

    If decision is FAIL_CLOSED, this function writes the receipt (evidence) then raises FL3ValidationError.
    """
    receipt = build_training_admission_receipt(
        repo_root=repo_root,
        job_path=job_path,
        lane_id=lane_id,
        expected_law_bundle_hash=expected_law_bundle_hash,
    )
    out_path = (job_dir / "training_admission_receipt.json").resolve()
    text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    write_text_worm(path=out_path, text=text, label="training_admission_receipt.json")
    if str(receipt.get("decision")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: training admission denied")
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_15 master valve: deterministic training admission gate (fail-closed).")
    ap.add_argument("--job", required=True, help="Path to jobspec JSON (schema-bound).")
    ap.add_argument("--job-dir", required=True, help="Job directory (writes training_admission_receipt.json WORM).")
    ap.add_argument("--lane-id", default="FL3_FACTORY", help="Lane identifier recorded in the receipt.")
    ap.add_argument("--expected-law-bundle-hash", default=None, help="If set, gate fails closed if LAW_BUNDLE hash differs.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    _ = ensure_training_admission_receipt(
        repo_root=repo_root,
        job_path=Path(args.job),
        job_dir=Path(args.job_dir),
        lane_id=str(args.lane_id),
        expected_law_bundle_hash=str(args.expected_law_bundle_hash) if args.expected_law_bundle_hash else None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
