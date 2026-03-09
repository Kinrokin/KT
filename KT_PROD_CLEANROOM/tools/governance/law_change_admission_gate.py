from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.governance.lane_policy import repo_clean_gate_for_current_lane
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


_SCHEMA_ID = "kt.law_change_admission_receipt.v1"
_SCHEMA_FILE = "fl3/kt.law_change_admission_receipt.v1.json"
_SCHEMA_VERSION_HASH = schema_version_hash(_SCHEMA_FILE)

_CHANGE_RECEIPT_SCHEMA_ID = "kt.law_bundle_change_receipt.v1"

_RC_DENIED = "LAW_CHANGE_ADMISSION_DENIED"
_RC_CONFIG_INVALID = "LAW_CHANGE_ADMISSION_CONFIG_INVALID"
_RC_COOLDOWN = "LAW_CHANGE_ADMISSION_COOLDOWN_ACTIVE"
_RC_TIME_CONTRACT_VIOLATION = "TIME_CONTRACT_VIOLATION"
_RC_LAW_BUNDLE_HASH_MISMATCH = "LAW_BUNDLE_HASH_MISMATCH"


def _allowed_reason_codes(*, taxonomy: Dict[str, Any]) -> Set[str]:
    mappings = taxonomy.get("mappings") if isinstance(taxonomy.get("mappings"), list) else []
    out: Set[str] = set()
    for m in mappings:
        if isinstance(m, dict):
            rc = m.get("reason_code")
            if isinstance(rc, str) and rc.strip():
                out.add(rc.strip())
    return out


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _parse_utc_z(ts: str) -> datetime:
    s = str(ts).strip()
    if not s.endswith("Z"):
        raise ValueError("timestamp must end with Z")
    # Accept both ...:SSZ and ...:SS.sssZ by normalizing.
    if "." in s:
        # Trim fractional seconds to microseconds precision for Python.
        head, tail = s[:-1].split(".", 1)
        frac = "".join(ch for ch in tail if ch.isdigit())[:6].ljust(6, "0")
        s_norm = f"{head}.{frac}Z"
        return datetime.strptime(s_norm, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _latest_law_amendment_created_at(*, audits_dir: Path) -> Optional[datetime]:
    """
    Returns the max created_at across LAW_AMENDMENT_FL3_*.json that are schema-valid.
    """
    best: Optional[datetime] = None
    for p in sorted(audits_dir.glob("LAW_AMENDMENT_FL3_*.json")):
        try:
            obj = _read_json_dict(p, name="law_amendment")
            validate_schema_bound_object(obj)
            created = _parse_utc_z(str(obj.get("created_at", "")).strip())
        except Exception:
            continue
        if best is None or created > best:
            best = created
    return best


def _load_time_contract(*, repo_root: Path, relpath: str = "KT_PROD_CLEANROOM/AUDITS/FL4_TIME_CONTRACT.json") -> None:
    p = (repo_root / relpath).resolve()
    obj = _read_json_dict(p, name="time_contract")
    validate_schema_bound_object(obj)


def build_law_change_admission_receipt(
    *,
    repo_root: Path,
    requested_bundle_hash: str,
    law_bundle_change_receipt_path: Path,
    cooldown_seconds: int,
    law_bundle_sha_rel: str = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
    failure_taxonomy_rel: str = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
) -> Dict[str, Any]:
    """
    EPIC_16 valve: law-change admission receipt (anti-churn).

    Determinism: decision time is evidence-anchored to the provided law_bundle_change_receipt.created_at,
    not wall-clock time. This makes reruns reproducible given the same inputs.
    """
    reasons: List[str] = []
    notes: Optional[str] = None

    # Determinism/time contract invariant.
    try:
        _load_time_contract(repo_root=repo_root)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_TIME_CONTRACT_VIOLATION)

    taxonomy = load_failure_taxonomy(repo_root=repo_root, relpath=failure_taxonomy_rel)
    allowed_rc = _allowed_reason_codes(taxonomy=taxonomy)

    # Structural invariant: canonical lane must prove a clean repo; local test lanes do not.
    ok, _err = repo_clean_gate_for_current_lane(repo_root)
    if not ok:
        reasons.append(_RC_DENIED)

    # Current bundle hash pin.
    law_sha_path = (repo_root / law_bundle_sha_rel).resolve()
    try:
        current_hash = law_sha_path.read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        current_hash = ""
    if len(current_hash) != 64 or any(c not in "0123456789abcdef" for c in current_hash.lower()):
        reasons.append(_RC_CONFIG_INVALID)
    if str(requested_bundle_hash).strip() != str(current_hash).strip():
        reasons.append(_RC_LAW_BUNDLE_HASH_MISMATCH)

    # Law bundle change receipt must exist and bind to requested hash.
    law_bundle_change_receipt_path = law_bundle_change_receipt_path.resolve()
    if not law_bundle_change_receipt_path.exists():
        reasons.append(_RC_CONFIG_INVALID)
        change_receipt = {}
        change_created_at = None
        change_ref = law_bundle_change_receipt_path.as_posix()
        change_sha = "0" * 64
    else:
        change_receipt = _read_json_dict(law_bundle_change_receipt_path, name="law_bundle_change_receipt")
        try:
            validate_schema_bound_object(change_receipt)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CONFIG_INVALID)
        if str(change_receipt.get("schema_id", "")).strip() != _CHANGE_RECEIPT_SCHEMA_ID:
            reasons.append(_RC_CONFIG_INVALID)
        if str(change_receipt.get("new_bundle_hash", "")).strip() != str(requested_bundle_hash).strip():
            reasons.append(_RC_CONFIG_INVALID)
        try:
            change_created_at = _parse_utc_z(str(change_receipt.get("created_at", "")).strip())
        except Exception:
            reasons.append(_RC_CONFIG_INVALID)
            change_created_at = None
        try:
            change_ref = str(law_bundle_change_receipt_path.relative_to(repo_root).as_posix())
        except Exception:
            change_ref = law_bundle_change_receipt_path.as_posix()
        change_sha = sha256_file_canonical(law_bundle_change_receipt_path)

    if not isinstance(cooldown_seconds, int) or cooldown_seconds < 0:
        reasons.append(_RC_CONFIG_INVALID)

    # Evidence-anchored cooldown: compare change_receipt.created_at to latest law amendment created_at.
    if cooldown_seconds > 0 and change_created_at is not None:
        audits_dir = (repo_root / "KT_PROD_CLEANROOM" / "AUDITS").resolve()
        latest_amend = _latest_law_amendment_created_at(audits_dir=audits_dir)
        if latest_amend is not None:
            age = (change_created_at - latest_amend).total_seconds()
            if age < float(cooldown_seconds):
                reasons.append(_RC_COOLDOWN)
                notes = (notes + ";" if notes else "") + f"cooldown_age_seconds={age:.3f}"

    reasons = sorted(set(reasons))
    decision = "PASS" if not reasons else "FAIL_CLOSED"

    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        decision = "FAIL_CLOSED"
        reasons = sorted(set([_RC_CONFIG_INVALID]))
        notes = "closed_reason_codes_violation"

    created_at = (
        str(change_receipt.get("created_at", "")).strip()
        if isinstance(change_receipt, dict) and str(change_receipt.get("created_at", "")).strip()
        else "1970-01-01T00:00:00Z"
    )

    receipt: Dict[str, Any] = {
        "schema_id": _SCHEMA_ID,
        "schema_version_hash": _SCHEMA_VERSION_HASH,
        "law_change_admission_receipt_id": "",
        "decision": decision,
        "reason_codes": reasons,
        "current_bundle_hash": str(current_hash),
        "requested_bundle_hash": str(requested_bundle_hash).strip(),
        "law_bundle_change_receipt_ref": change_ref,
        "law_bundle_change_receipt_sha256": change_sha,
        "cooldown_seconds": int(cooldown_seconds),
        "created_at": created_at,
    }
    if notes is not None:
        receipt["notes"] = notes
    receipt["law_change_admission_receipt_id"] = sha256_hex_of_obj(
        receipt, drop_keys={"created_at", "law_change_admission_receipt_id"}
    )
    validate_schema_bound_object(receipt)
    return receipt


def ensure_law_change_admission_receipt(
    *,
    repo_root: Path,
    requested_bundle_hash: str,
    law_bundle_change_receipt_path: Path,
    cooldown_seconds: int,
    out_path: Path,
) -> Dict[str, Any]:
    receipt = build_law_change_admission_receipt(
        repo_root=repo_root,
        requested_bundle_hash=requested_bundle_hash,
        law_bundle_change_receipt_path=law_bundle_change_receipt_path,
        cooldown_seconds=cooldown_seconds,
    )
    text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    write_text_worm(path=out_path, text=text, label="law_change_admission_receipt.json")
    if str(receipt.get("decision")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: law change admission denied")
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_16 valve: law-change admission receipt (anti-churn; fail-closed).")
    ap.add_argument("--requested-bundle-hash", required=True, help="Bundle hash to admit (must equal current LAW_BUNDLE hash).")
    ap.add_argument("--law-bundle-change-receipt", required=True, help="Path to kt.law_bundle_change_receipt.v1 for requested hash (decision time anchor).")
    ap.add_argument("--cooldown-seconds", type=int, default=0, help="Minimum age since last LAW_AMENDMENT, measured at change_receipt.created_at.")
    ap.add_argument("--out", default=None, help="Output path. Default: KT_PROD_CLEANROOM/AUDITS/LAW_CHANGE_ADMISSION_RECEIPT_FL3_<id>.json")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    requested = str(args.requested_bundle_hash).strip()

    # Default out path derived from deterministic receipt id.
    receipt = build_law_change_admission_receipt(
        repo_root=repo_root,
        requested_bundle_hash=requested,
        law_bundle_change_receipt_path=Path(args.law_bundle_change_receipt),
        cooldown_seconds=int(args.cooldown_seconds),
    )
    receipt_id = str(receipt.get("law_change_admission_receipt_id", "")).strip() or "0" * 64

    if args.out:
        out_path = Path(args.out)
    else:
        audits_dir = repo_root / "KT_PROD_CLEANROOM" / "AUDITS"
        out_path = audits_dir / f"LAW_CHANGE_ADMISSION_RECEIPT_FL3_{receipt_id}.json"

    _ = ensure_law_change_admission_receipt(
        repo_root=repo_root,
        requested_bundle_hash=requested,
        law_bundle_change_receipt_path=Path(args.law_bundle_change_receipt),
        cooldown_seconds=int(args.cooldown_seconds),
        out_path=out_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
