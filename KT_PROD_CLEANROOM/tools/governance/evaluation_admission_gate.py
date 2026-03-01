from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.governance.suite_registry_utils import (
    find_suite_entry,
    load_suite_registry,
    suite_definition_hash_ok,
    verify_suite_authorization,
)
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import canonical_json, repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import write_text_worm


_SCHEMA_ID = "kt.evaluation_admission_receipt.v1"
_SCHEMA_FILE = "fl3/kt.evaluation_admission_receipt.v1.json"
_SCHEMA_VERSION_HASH = schema_version_hash(_SCHEMA_FILE)

_PLAN_SCHEMA_ID = "kt.tournament_plan.v1"
_PLAN_SCHEMA_FILE = "fl3/kt.tournament_plan.v1.json"
_PLAN_SCHEMA_VERSION_HASH = schema_version_hash(_PLAN_SCHEMA_FILE)

_CP_SCHEMA_ID = "kt.counterpressure_plan.v1"
_CP_SCHEMA_FILE = "fl3/kt.counterpressure_plan.v1.json"
_CP_SCHEMA_VERSION_HASH = schema_version_hash(_CP_SCHEMA_FILE)

_BH_SCHEMA_ID = "kt.break_hypothesis.v1"
_BH_SCHEMA_FILE = "fl3/kt.break_hypothesis.v1.json"
_BH_SCHEMA_VERSION_HASH = schema_version_hash(_BH_SCHEMA_FILE)

_RC_DENIED = "EVALUATION_ADMISSION_DENIED"
_RC_CONFIG_INVALID = "EVALUATION_ADMISSION_CONFIG_INVALID"
_RC_TIME_CONTRACT_VIOLATION = "TIME_CONTRACT_VIOLATION"
_RC_LAW_BUNDLE_HASH_MISMATCH = "LAW_BUNDLE_HASH_MISMATCH"

_RC_SUITE_REGISTRY_MISSING = "SUITE_REGISTRY_MISSING"
_RC_SUITE_UNAUTHORIZED = "SUITE_UNAUTHORIZED"
_RC_SUITE_ROOT_HASH_MISMATCH = "SUITE_ROOT_HASH_MISMATCH"
_RC_SUITE_AUTH_INSUFFICIENT = "SUITE_AUTH_ATTESTATION_INSUFFICIENT"

_RC_CP_MISSING = "COUNTERPRESSURE_PLAN_MISSING"
_RC_BH_MISSING = "BREAK_HYPOTHESIS_MISSING"


def _allowed_reason_codes(*, taxonomy: Dict[str, Any]) -> Set[str]:
    mappings = taxonomy.get("mappings") if isinstance(taxonomy.get("mappings"), list) else []
    out: Set[str] = set()
    for m in mappings:
        if isinstance(m, dict):
            rc = m.get("reason_code")
            if isinstance(rc, str) and rc.strip():
                out.add(rc.strip())
    return out


def _git_status_is_clean(repo_root: Path) -> Tuple[bool, str]:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(repo_root), text=True)
    except Exception as exc:  # noqa: BLE001
        return False, f"FAIL_CLOSED: unable to run git status: {exc}"
    if out.strip():
        return False, "FAIL_CLOSED: repo is not clean"
    return True, ""


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _sha256_obj(obj: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(obj))


def _load_time_contract(*, repo_root: Path, relpath: str = "KT_PROD_CLEANROOM/AUDITS/FL4_TIME_CONTRACT.json") -> None:
    p = (repo_root / relpath).resolve()
    obj = _read_json_dict(p, name="time_contract")
    validate_schema_bound_object(obj)


def build_evaluation_admission_receipt(
    *,
    repo_root: Path,
    plan_path: Path,
    lane_id: str,
    suite_registry_path: Path,
    counterpressure_plan_path: Path,
    break_hypothesis_path: Path,
    expected_law_bundle_hash: Optional[str] = None,
    law_bundle_sha_rel: str = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256",
    failure_taxonomy_rel: str = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
) -> Dict[str, Any]:
    """
    EPIC_16 evaluation admission valve (fail-closed).

    Determinism:
      - created_at uses deterministic factory timeutil (fixed epoch).
      - admission_receipt_id drops created_at.

    Notes:
      - This gate is designed to precede tournament/merge evaluation.
      - In canonical lane (KT_CANONICAL_LANE=1), suite registry authorization is verified via HMAC signoffs.
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

    # Structural invariant: clean repo.
    ok, _err = _git_status_is_clean(repo_root)
    if not ok:
        reasons.append(_RC_DENIED)

    # Law bundle pin.
    law_sha_path = (repo_root / law_bundle_sha_rel).resolve()
    try:
        law_bundle_hash = law_sha_path.read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        law_bundle_hash = ""
    if len(law_bundle_hash) != 64 or any(c not in "0123456789abcdef" for c in law_bundle_hash.lower()):
        reasons.append(_RC_CONFIG_INVALID)
    if expected_law_bundle_hash and law_bundle_hash and str(expected_law_bundle_hash) != law_bundle_hash:
        reasons.append(_RC_LAW_BUNDLE_HASH_MISMATCH)

    # Plan must exist and be schema-bound (tournament_plan v1 for EPIC_16 v1).
    plan_path = plan_path.resolve()
    try:
        plan = _read_json_dict(plan_path, name="evaluation_plan")
        validate_schema_bound_object(plan)
    except Exception:  # noqa: BLE001
        reasons.append(_RC_CONFIG_INVALID)
        plan = {}

    if (
        plan.get("schema_id") != _PLAN_SCHEMA_ID
        or plan.get("schema_version_hash") != _PLAN_SCHEMA_VERSION_HASH
    ):
        reasons.append(_RC_CONFIG_INVALID)

    base_model_id = str(plan.get("base_model_id", "")).strip()
    suite_id = str(plan.get("suite_id", "")).strip()
    suite_root_hash = str(plan.get("suite_root_hash", "")).strip()
    decode_policy_id = str(plan.get("decode_policy_id", "")).strip()
    decode_cfg_hash = str(plan.get("decode_cfg_hash", "")).strip()
    if not base_model_id or not suite_id or not suite_root_hash or not decode_policy_id or not decode_cfg_hash:
        reasons.append(_RC_CONFIG_INVALID)

    try:
        plan_ref = str(plan_path.relative_to(repo_root).as_posix())
    except Exception:
        plan_ref = plan_path.as_posix()

    plan_sha = _sha256_obj(plan) if isinstance(plan, dict) else sha256_text("null")

    # Suite registry must exist and contain an exact (suite_id, suite_root_hash) entry.
    suite_registry_ref: str
    suite_registry_sha: str
    suite_entry: Optional[Dict[str, Any]] = None
    if not suite_registry_path.exists():
        reasons.append(_RC_SUITE_REGISTRY_MISSING)
        suite_registry = {}
        suite_registry_ref = str(suite_registry_path.as_posix())
        suite_registry_sha = "0" * 64
    else:
        suite_registry = load_suite_registry(path=suite_registry_path)
        suite_entry = find_suite_entry(registry=suite_registry, suite_id=suite_id, suite_root_hash=suite_root_hash)
        try:
            suite_registry_ref = str(suite_registry_path.resolve().relative_to(repo_root).as_posix())
        except Exception:
            suite_registry_ref = suite_registry_path.resolve().as_posix()
        suite_registry_sha = _sha256_obj(suite_registry)
        if suite_entry is None:
            reasons.append(_RC_SUITE_UNAUTHORIZED)
        else:
            ok_hash, err = suite_definition_hash_ok(
                repo_root=repo_root,
                suite_definition_ref=str(suite_entry.get("suite_definition_ref", "")),
                suite_root_hash=suite_root_hash,
            )
            if not ok_hash:
                reasons.append(_RC_SUITE_ROOT_HASH_MISMATCH)
                notes = (notes + ";" if notes else "") + f"suite_definition_hash:{err}"

            ok_auth, err_auth = verify_suite_authorization(registry=suite_registry, suite_entry=suite_entry)
            if not ok_auth:
                reasons.append(_RC_SUITE_AUTH_INSUFFICIENT)
                notes = (notes + ";" if notes else "") + f"suite_auth:{err_auth}"

    # Counterpressure plan must exist and bind to optimization suite + decode cfg.
    cp_ref: str
    cp_sha: str
    if not counterpressure_plan_path.exists():
        reasons.append(_RC_CP_MISSING)
        cp = {}
        cp_ref = str(counterpressure_plan_path.as_posix())
        cp_sha = "0" * 64
    else:
        cp = _read_json_dict(counterpressure_plan_path.resolve(), name="counterpressure_plan")
        try:
            validate_schema_bound_object(cp)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CONFIG_INVALID)
        if cp.get("schema_id") != _CP_SCHEMA_ID or cp.get("schema_version_hash") != _CP_SCHEMA_VERSION_HASH:
            reasons.append(_RC_CONFIG_INVALID)
        if str(cp.get("base_model_id", "")).strip() != base_model_id:
            reasons.append(_RC_CONFIG_INVALID)
        if str(cp.get("optimization_suite_id", "")).strip() != suite_id:
            reasons.append(_RC_CONFIG_INVALID)
        if str(cp.get("optimization_suite_root_hash", "")).strip() != suite_root_hash:
            reasons.append(_RC_CONFIG_INVALID)
        if str(cp.get("decode_policy_id", "")).strip() != decode_policy_id:
            reasons.append(_RC_CONFIG_INVALID)
        if str(cp.get("decode_cfg_hash", "")).strip() != decode_cfg_hash:
            reasons.append(_RC_CONFIG_INVALID)

        try:
            cp_ref = str(counterpressure_plan_path.resolve().relative_to(repo_root).as_posix())
        except Exception:
            cp_ref = counterpressure_plan_path.resolve().as_posix()
        cp_sha = _sha256_obj(cp)

    # Break hypothesis must exist and bind to base model + suite id and the counterpressure plan.
    bh_ref: str
    bh_sha: str
    if not break_hypothesis_path.exists():
        reasons.append(_RC_BH_MISSING)
        bh = {}
        bh_ref = str(break_hypothesis_path.as_posix())
        bh_sha = "0" * 64
    else:
        bh = _read_json_dict(break_hypothesis_path.resolve(), name="break_hypothesis")
        try:
            validate_schema_bound_object(bh)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CONFIG_INVALID)
        if bh.get("schema_id") != _BH_SCHEMA_ID or bh.get("schema_version_hash") != _BH_SCHEMA_VERSION_HASH:
            reasons.append(_RC_CONFIG_INVALID)
        if str(bh.get("base_model_id", "")).strip() != base_model_id:
            reasons.append(_RC_CONFIG_INVALID)
        if str(bh.get("suite_id", "")).strip() != suite_id:
            reasons.append(_RC_CONFIG_INVALID)
        if cp and bh and str(cp.get("break_hypothesis_id", "")).strip() != str(bh.get("break_hypothesis_id", "")).strip():
            reasons.append(_RC_CONFIG_INVALID)

        try:
            bh_ref = str(break_hypothesis_path.resolve().relative_to(repo_root).as_posix())
        except Exception:
            bh_ref = break_hypothesis_path.resolve().as_posix()
        bh_sha = _sha256_obj(bh)

    # Finalize and close reason codes.
    reasons = sorted(set(reasons))
    decision = "PASS" if not reasons else "FAIL_CLOSED"
    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        decision = "FAIL_CLOSED"
        reasons = sorted(set([_RC_CONFIG_INVALID]))
        notes = "closed_reason_codes_violation"

    created_at = utc_now_z()
    failure_taxonomy_id = str(taxonomy.get("taxonomy_id", "")).strip()

    receipt: Dict[str, Any] = {
        "schema_id": _SCHEMA_ID,
        "schema_version_hash": _SCHEMA_VERSION_HASH,
        "admission_receipt_id": "",
        "lane_id": str(lane_id),
        "decision": decision,
        "reason_codes": reasons,
        "evaluation_plan_ref": plan_ref,
        "evaluation_plan_sha256": plan_sha,
        "base_model_id": base_model_id,
        "suite_id": suite_id,
        "suite_root_hash": suite_root_hash,
        "decode_policy_id": decode_policy_id,
        "decode_cfg_hash": decode_cfg_hash,
        "suite_registry_ref": suite_registry_ref,
        "suite_registry_sha256": suite_registry_sha,
        "counterpressure_plan_ref": cp_ref,
        "counterpressure_plan_sha256": cp_sha,
        "break_hypothesis_ref": bh_ref,
        "break_hypothesis_sha256": bh_sha,
        "law_bundle_hash": str(law_bundle_hash),
        "failure_taxonomy_id": failure_taxonomy_id,
        "created_at": created_at,
    }
    if notes is not None:
        receipt["notes"] = notes

    receipt["admission_receipt_id"] = sha256_hex_of_obj(receipt, drop_keys={"created_at", "admission_receipt_id"})
    validate_schema_bound_object(receipt)
    return receipt


def ensure_evaluation_admission_receipt(
    *,
    repo_root: Path,
    plan_path: Path,
    lane_id: str,
    suite_registry_path: Path,
    counterpressure_plan_path: Path,
    break_hypothesis_path: Path,
    out_path: Path,
    expected_law_bundle_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Writes the evaluation admission receipt WORM (byte-identical no-op allowed).

    If decision is FAIL_CLOSED, writes the receipt (evidence) then raises FL3ValidationError.
    """
    receipt = build_evaluation_admission_receipt(
        repo_root=repo_root,
        plan_path=plan_path,
        lane_id=lane_id,
        suite_registry_path=suite_registry_path,
        counterpressure_plan_path=counterpressure_plan_path,
        break_hypothesis_path=break_hypothesis_path,
        expected_law_bundle_hash=expected_law_bundle_hash,
    )
    text = json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    write_text_worm(path=out_path, text=text, label="evaluation_admission_receipt.json")
    if str(receipt.get("decision")) != "PASS":
        raise FL3ValidationError("FAIL_CLOSED: evaluation admission denied")
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_16 valve: deterministic evaluation admission (authorized suites + counter-pressure prerequisites).")
    ap.add_argument("--plan", required=True, help="Path to kt.tournament_plan.v1 JSON (schema-bound).")
    ap.add_argument("--lane-id", default="EVAL_LANE", help="Lane identifier recorded in the receipt.")
    ap.add_argument("--suite-registry", default="KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json", help="Path to suite registry JSON.")
    ap.add_argument("--counterpressure-plan", required=True, help="Path to kt.counterpressure_plan.v1 JSON.")
    ap.add_argument("--break-hypothesis", required=True, help="Path to kt.break_hypothesis.v1 JSON.")
    ap.add_argument("--expected-law-bundle-hash", default=None, help="If set, gate fails closed if LAW_BUNDLE hash differs.")
    ap.add_argument("--out", default=None, help="Output path. Default: <plan_dir>/evaluation_admission_receipt.json")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    plan_path = Path(args.plan)

    if args.out:
        out_path = Path(args.out)
    else:
        out_path = plan_path.resolve().parent / "evaluation_admission_receipt.json"

    _ = ensure_evaluation_admission_receipt(
        repo_root=repo_root,
        plan_path=plan_path,
        lane_id=str(args.lane_id),
        suite_registry_path=(repo_root / str(args.suite_registry)).resolve()
        if not Path(str(args.suite_registry)).is_absolute()
        else Path(str(args.suite_registry)).resolve(),
        counterpressure_plan_path=Path(args.counterpressure_plan),
        break_hypothesis_path=Path(args.break_hypothesis),
        out_path=out_path,
        expected_law_bundle_hash=str(args.expected_law_bundle_hash) if args.expected_law_bundle_hash else None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
