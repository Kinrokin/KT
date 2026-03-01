from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from schemas.schema_files import schema_version_hash
from tools.governance.failure_taxonomy_reporter import load_failure_taxonomy
from tools.governance.suite_registry_utils import (
    find_suite_entry,
    load_suite_registry,
    suite_definition_hash_ok,
    verify_suite_authorization,
)
from tools.verification.fl3_canonical import canonical_json, repo_root_from, sha256_text
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object


_BH_SCHEMA_ID = "kt.break_hypothesis.v1"
_BH_SCHEMA_FILE = "fl3/kt.break_hypothesis.v1.json"
_BH_SCHEMA_VERSION_HASH = schema_version_hash(_BH_SCHEMA_FILE)

_CP_SCHEMA_ID = "kt.counterpressure_plan.v1"
_CP_SCHEMA_FILE = "fl3/kt.counterpressure_plan.v1.json"
_CP_SCHEMA_VERSION_HASH = schema_version_hash(_CP_SCHEMA_FILE)

_FP_SCHEMA_ID = "kt.fragility_probe_result.v1"
_FP_SCHEMA_FILE = "fl3/kt.fragility_probe_result.v1.json"
_FP_SCHEMA_VERSION_HASH = schema_version_hash(_FP_SCHEMA_FILE)

_RC_CP_MISSING = "COUNTERPRESSURE_PLAN_MISSING"
_RC_BH_MISSING = "BREAK_HYPOTHESIS_MISSING"
_RC_FP_MISSING = "FRAGILITY_PROBE_MISSING"
_RC_CP_FAIL = "COUNTERPRESSURE_FAIL"
_RC_CP_BUDGET = "COUNTERPRESSURE_REGRESSION_BUDGET_EXCEEDED"

_RC_SUITE_UNAUTHORIZED = "SUITE_UNAUTHORIZED"
_RC_SUITE_ROOT_HASH_MISMATCH = "SUITE_ROOT_HASH_MISMATCH"
_RC_SUITE_AUTH_INSUFFICIENT = "SUITE_AUTH_ATTESTATION_INSUFFICIENT"


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


def _sha256_obj(obj: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(obj))


def check_counterpressure_evidence(
    *,
    repo_root: Path,
    expected_base_model_id: str,
    expected_suite_id: str,
    expected_suite_root_hash: str,
    expected_decode_policy_id: str,
    expected_decode_cfg_hash: str,
    entrant_adapter_root_hashes: Sequence[str],
    suite_registry_path: Optional[Path],
    break_hypothesis_path: Path,
    counterpressure_plan_path: Path,
    fragility_probe_result_path: Path,
    expected_break_hypothesis_sha256: Optional[str] = None,
    expected_counterpressure_plan_sha256: Optional[str] = None,
    failure_taxonomy_rel: str = "KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json",
) -> Tuple[bool, List[str], Optional[str]]:
    """
    EPIC_16 hard gate: counter-pressure evidence is mandatory and must PASS.

    This function is deterministic and side-effect-free. Callers write their own evidence artifacts WORM.
    """
    reasons: List[str] = []
    notes: Optional[str] = None

    taxonomy = load_failure_taxonomy(repo_root=repo_root, relpath=failure_taxonomy_rel)
    allowed_rc = _allowed_reason_codes(taxonomy=taxonomy)

    if not break_hypothesis_path.exists():
        reasons.append(_RC_BH_MISSING)
        bh: Dict[str, Any] = {}
    else:
        bh = _read_json_dict(break_hypothesis_path, name="break_hypothesis")
        try:
            validate_schema_bound_object(bh)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CP_FAIL)
        if bh.get("schema_id") != _BH_SCHEMA_ID or bh.get("schema_version_hash") != _BH_SCHEMA_VERSION_HASH:
            reasons.append(_RC_CP_FAIL)
        if str(bh.get("base_model_id", "")).strip() != str(expected_base_model_id).strip():
            reasons.append(_RC_CP_FAIL)
        if str(bh.get("suite_id", "")).strip() != str(expected_suite_id).strip():
            reasons.append(_RC_CP_FAIL)

        if expected_break_hypothesis_sha256 is not None:
            got = _sha256_obj(bh)
            if str(expected_break_hypothesis_sha256).strip() != got:
                reasons.append(_RC_CP_FAIL)
                notes = (notes + ";" if notes else "") + "break_hypothesis_sha256_mismatch"

    if not counterpressure_plan_path.exists():
        reasons.append(_RC_CP_MISSING)
        cp: Dict[str, Any] = {}
    else:
        cp = _read_json_dict(counterpressure_plan_path, name="counterpressure_plan")
        try:
            validate_schema_bound_object(cp)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CP_FAIL)
        if cp.get("schema_id") != _CP_SCHEMA_ID or cp.get("schema_version_hash") != _CP_SCHEMA_VERSION_HASH:
            reasons.append(_RC_CP_FAIL)
        if str(cp.get("base_model_id", "")).strip() != str(expected_base_model_id).strip():
            reasons.append(_RC_CP_FAIL)
        if str(cp.get("optimization_suite_id", "")).strip() != str(expected_suite_id).strip():
            reasons.append(_RC_CP_FAIL)
        if str(cp.get("optimization_suite_root_hash", "")).strip() != str(expected_suite_root_hash).strip():
            reasons.append(_RC_CP_FAIL)
        if str(cp.get("decode_policy_id", "")).strip() != str(expected_decode_policy_id).strip():
            reasons.append(_RC_CP_FAIL)
        if str(cp.get("decode_cfg_hash", "")).strip() != str(expected_decode_cfg_hash).strip():
            reasons.append(_RC_CP_FAIL)
        if bh and str(cp.get("break_hypothesis_id", "")).strip() != str(bh.get("break_hypothesis_id", "")).strip():
            reasons.append(_RC_CP_FAIL)

        if expected_counterpressure_plan_sha256 is not None:
            got = _sha256_obj(cp)
            if str(expected_counterpressure_plan_sha256).strip() != got:
                reasons.append(_RC_CP_FAIL)
                notes = (notes + ";" if notes else "") + "counterpressure_plan_sha256_mismatch"

    # Measurement independence for counter-pressure: adversarial suite must be authorized and hash-bound
    # if a suite registry is provided.
    if suite_registry_path is not None:
        try:
            if suite_registry_path.exists() and cp:
                registry = load_suite_registry(path=suite_registry_path)
                adv_id = str(cp.get("adversarial_suite_id", "")).strip()
                adv_root = str(cp.get("adversarial_suite_root_hash", "")).strip()
                entry = find_suite_entry(registry=registry, suite_id=adv_id, suite_root_hash=adv_root)
                if entry is None:
                    reasons.append(_RC_SUITE_UNAUTHORIZED)
                    notes = (notes + ";" if notes else "") + "adversarial_suite_not_authorized"
                else:
                    ok_hash, err = suite_definition_hash_ok(
                        repo_root=repo_root,
                        suite_definition_ref=str(entry.get("suite_definition_ref", "")),
                        suite_root_hash=adv_root,
                    )
                    if not ok_hash:
                        reasons.append(_RC_SUITE_ROOT_HASH_MISMATCH)
                        notes = (notes + ";" if notes else "") + f"adversarial_suite_definition_hash:{err}"
                    ok_auth, err_auth = verify_suite_authorization(registry=registry, suite_entry=entry)
                    if not ok_auth:
                        reasons.append(_RC_SUITE_AUTH_INSUFFICIENT)
                        notes = (notes + ";" if notes else "") + f"adversarial_suite_auth:{err_auth}"
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CP_FAIL)
            notes = (notes + ";" if notes else "") + "suite_registry_check_error"

    if not fragility_probe_result_path.exists():
        reasons.append(_RC_FP_MISSING)
        fp: Dict[str, Any] = {}
    else:
        fp = _read_json_dict(fragility_probe_result_path, name="fragility_probe_result")
        try:
            validate_schema_bound_object(fp)
        except Exception:  # noqa: BLE001
            reasons.append(_RC_CP_FAIL)
        if fp.get("schema_id") != _FP_SCHEMA_ID or fp.get("schema_version_hash") != _FP_SCHEMA_VERSION_HASH:
            reasons.append(_RC_CP_FAIL)
        if cp and str(fp.get("counterpressure_plan_id", "")).strip() != str(cp.get("counterpressure_plan_id", "")).strip():
            reasons.append(_RC_CP_FAIL)

        # Close fragility probe result reason codes against taxonomy.
        fp_rc = fp.get("reason_codes") if isinstance(fp.get("reason_codes"), list) else []
        fp_unknown = [r for r in fp_rc if isinstance(r, str) and r.strip() and r.strip() not in allowed_rc]
        if fp_unknown:
            reasons.append(_RC_CP_FAIL)
            notes = (notes + ";" if notes else "") + "fragility_reason_codes_not_closed"

        if str(fp.get("status", "")).strip() != "PASS":
            reasons.append(_RC_CP_FAIL)

        # Require probes for all declared families.
        required_fams: Set[str] = set()
        for src in (bh, cp):
            fams = src.get("required_probe_families") if isinstance(src, dict) else None
            if isinstance(fams, list):
                for f in fams:
                    if isinstance(f, str) and f.strip():
                        required_fams.add(f.strip())

        probes = fp.get("probes") if isinstance(fp.get("probes"), list) else []
        fam_status: Dict[str, List[str]] = {}
        fail_count = 0
        for p in probes:
            if not isinstance(p, dict):
                continue
            fam = str(p.get("family", "")).strip()
            st = str(p.get("status", "")).strip()
            if fam:
                fam_status.setdefault(fam, []).append(st)
            if st == "FAIL_CLOSED":
                fail_count += 1

        missing_fams = sorted([f for f in required_fams if f not in fam_status])
        if missing_fams:
            reasons.append(_RC_CP_FAIL)
            notes = (notes + ";" if notes else "") + "missing_probe_families"

        for fam in sorted(required_fams):
            sts = fam_status.get(fam, [])
            if not any(s == "PASS" for s in sts):
                reasons.append(_RC_CP_FAIL)
                notes = (notes + ";" if notes else "") + "required_probe_family_failed"
                break

        # Enforce regression budgets from break hypothesis.
        allowed_new_hard_failures = 0
        if isinstance(bh, dict):
            rb = bh.get("regression_budgets") if isinstance(bh.get("regression_budgets"), dict) else {}
            try:
                allowed_new_hard_failures = int(rb.get("new_hard_failures_allowed", 0))
            except Exception:
                allowed_new_hard_failures = 0
        if fail_count > allowed_new_hard_failures:
            reasons.append(_RC_CP_BUDGET)

        # Require probe evaluation coverage for all tournament entrants.
        expected_hashes = {str(h).strip() for h in entrant_adapter_root_hashes if str(h).strip()}
        evaluated = fp.get("evaluated_adapter_root_hashes") if isinstance(fp.get("evaluated_adapter_root_hashes"), list) else []
        got_hashes = {str(h).strip() for h in evaluated if isinstance(h, str) and h.strip()}
        missing_hashes = sorted(expected_hashes - got_hashes)
        if missing_hashes:
            reasons.append(_RC_CP_FAIL)
            notes = (notes + ";" if notes else "") + "missing_evaluated_adapters"

    reasons = sorted(set(reasons))
    unknown = [r for r in reasons if r not in allowed_rc]
    if unknown:
        reasons = [_RC_CP_FAIL]
        notes = "closed_reason_codes_violation"

    return (not reasons), reasons, notes


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_16 deterministic counter-pressure gate (requires fragility probe PASS).")
    ap.add_argument("--base-model-id", required=True)
    ap.add_argument("--suite-id", required=True)
    ap.add_argument("--suite-root-hash", required=True)
    ap.add_argument("--decode-policy-id", required=True)
    ap.add_argument("--decode-cfg-hash", required=True)
    ap.add_argument("--entrant-hashes", required=True, help="Comma-separated adapter_root_hash values evaluated.")
    ap.add_argument("--suite-registry", default=None, help="Optional path to suite registry (enforces adversarial suite authorization).")
    ap.add_argument("--break-hypothesis", required=True, help="Path to kt.break_hypothesis.v1 JSON.")
    ap.add_argument("--counterpressure-plan", required=True, help="Path to kt.counterpressure_plan.v1 JSON.")
    ap.add_argument("--fragility-probe-result", required=True, help="Path to kt.fragility_probe_result.v1 JSON.")
    args = ap.parse_args(list(argv) if argv is not None else None)

    repo_root = repo_root_from(Path(__file__))
    suite_registry_path = None
    if args.suite_registry:
        p = Path(str(args.suite_registry))
        suite_registry_path = (repo_root / str(args.suite_registry)).resolve() if not p.is_absolute() else p.resolve()

    ok, reasons, notes = check_counterpressure_evidence(
        repo_root=repo_root,
        expected_base_model_id=str(args.base_model_id),
        expected_suite_id=str(args.suite_id),
        expected_suite_root_hash=str(args.suite_root_hash),
        expected_decode_policy_id=str(args.decode_policy_id),
        expected_decode_cfg_hash=str(args.decode_cfg_hash),
        entrant_adapter_root_hashes=[h for h in str(args.entrant_hashes).split(",") if h.strip()],
        suite_registry_path=suite_registry_path,
        break_hypothesis_path=Path(args.break_hypothesis),
        counterpressure_plan_path=Path(args.counterpressure_plan),
        fragility_probe_result_path=Path(args.fragility_probe_result),
        expected_break_hypothesis_sha256=None,
        expected_counterpressure_plan_sha256=None,
    )
    if notes:
        print(f"NOTES={notes}")
    if not ok:
        print("FAIL_CLOSED reasons=" + ",".join(reasons))
        return 2
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

