from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from tools.training.fl3_factory.manifests import sha256_file as sha256_file_canonical
from tools.training.fl3_factory.timeutil import utc_now_z
from tools.verification.fl3_canonical import repo_root_from
from tools.verification.fl3_validators import FL3ValidationError, validate_schema_bound_object
from tools.verification.worm_write import enforce_all_or_none_exist, write_text_worm


_POLICY_SCHEMA_ID = "kt.router_policy.v1"
_SUITE_SCHEMA_ID = "kt.router_demo_suite.v1"
_RECEIPT_SCHEMA_ID = "kt.routing_receipt.v1"
_RUN_REPORT_SCHEMA_ID = "kt.router_run_report.v1"


def _read_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise FL3ValidationError(f"FAIL_CLOSED: unreadable JSON {name}: {path.as_posix()}") from exc
    if not isinstance(obj, dict):
        raise FL3ValidationError(f"FAIL_CLOSED: {name} must be a JSON object: {path.as_posix()}")
    return obj


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _assert_out_dir_under_exports_runs(*, repo_root: Path, out_dir: Path) -> Path:
    out_dir = out_dir.resolve()
    allowed_root = (repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs").resolve()
    try:
        out_dir.relative_to(allowed_root)
    except ValueError as exc:
        raise FL3ValidationError(f"FAIL_CLOSED: out_dir must be under {allowed_root.as_posix()}") from exc
    return out_dir


def _choose_route(*, policy: Dict[str, Any], input_text: str) -> Tuple[str, List[str], List[str], List[str]]:
    """
    Deterministic keyword-substring routing.

    Returns:
      (domain_tag, matched_keywords, selected_adapter_ids, required_adapter_ids)
    """
    routes = policy.get("routes") if isinstance(policy.get("routes"), list) else []
    default_adapters = policy.get("default_adapter_ids") if isinstance(policy.get("default_adapter_ids"), list) else []

    txt = str(input_text).lower()
    matches: List[Tuple[str, List[str], List[str], List[str]]] = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        dom = str(r.get("domain_tag", "")).strip()
        keywords = r.get("keywords") if isinstance(r.get("keywords"), list) else []
        adapter_ids = r.get("adapter_ids") if isinstance(r.get("adapter_ids"), list) else []
        required_ids = r.get("required_adapter_ids") if isinstance(r.get("required_adapter_ids"), list) else []
        kws = [str(k).strip() for k in keywords if isinstance(k, str) and str(k).strip()]
        hit = sorted({k for k in kws if k.lower() in txt})
        if hit:
            adapters = sorted({str(a).strip() for a in adapter_ids if isinstance(a, str) and str(a).strip()})
            required = sorted({str(a).strip() for a in required_ids if isinstance(a, str) and str(a).strip()})
            selected = sorted(set(adapters) | set(required))
            matches.append((dom, hit, selected, required))

    if matches:
        # Lexicographic-min domain_tag among matches.
        dom, hit, selected, required = sorted(matches, key=lambda t: t[0])[0]
        return dom, hit, selected, required

    selected = sorted({str(a).strip() for a in default_adapters if isinstance(a, str) and str(a).strip()})
    if not selected:
        raise FL3ValidationError("FAIL_CLOSED: router policy default_adapter_ids empty at runtime")
    return "default", [], selected, []


def run_router_hat_demo(
    *, policy_path: Path, suite_path: Path, run_id: str, out_dir: Path
) -> Dict[str, Any]:
    repo_root = repo_root_from(Path(__file__))

    policy = _read_json_dict(policy_path, name="router_policy")
    validate_schema_bound_object(policy)
    if str(policy.get("schema_id", "")).strip() != _POLICY_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: router_policy schema_id mismatch")

    suite = _read_json_dict(suite_path, name="router_demo_suite")
    validate_schema_bound_object(suite)
    if str(suite.get("schema_id", "")).strip() != _SUITE_SCHEMA_ID:
        raise FL3ValidationError("FAIL_CLOSED: router_demo_suite schema_id mismatch")

    run_id = str(run_id).strip()
    if not run_id:
        raise FL3ValidationError("FAIL_CLOSED: run_id must be non-empty")

    policy_id = str(policy.get("router_policy_id", "")).strip()
    suite_id = str(suite.get("router_demo_suite_id", "")).strip()

    cases = suite.get("cases") if isinstance(suite.get("cases"), list) else []
    if not cases:
        raise FL3ValidationError("FAIL_CLOSED: suite has no cases")

    # Build receipts in-memory first to avoid partial WORM writes on failure.
    created_at = utc_now_z()
    from schemas.schema_files import schema_version_hash  # type: ignore

    receipts: List[Dict[str, Any]] = []
    for c in cases:
        if not isinstance(c, dict):
            continue
        case_id = str(c.get("case_id", "")).strip()
        input_text = str(c.get("input_text", "")).strip()
        exp_dom = str(c.get("expected_domain_tag", "")).strip()
        exp_adapters = c.get("expected_adapter_ids") if isinstance(c.get("expected_adapter_ids"), list) else []
        exp_set = sorted({str(a).strip() for a in exp_adapters if isinstance(a, str) and str(a).strip()})
        if not case_id or not input_text or not exp_dom or not exp_set:
            raise FL3ValidationError("FAIL_CLOSED: malformed case (missing required fields)")

        dom, hit, selected, required = _choose_route(policy=policy, input_text=input_text)
        if dom != exp_dom:
            raise FL3ValidationError(
                f"FAIL_CLOSED: domain mismatch case_id={case_id} expected={exp_dom!r} got={dom!r}"
            )
        if selected != exp_set:
            raise FL3ValidationError(
                f"FAIL_CLOSED: selected adapters mismatch case_id={case_id} expected={exp_set} got={selected}"
            )

        receipt: Dict[str, Any] = {
            "schema_id": _RECEIPT_SCHEMA_ID,
            "schema_version_hash": schema_version_hash("fl3/kt.routing_receipt.v1.json"),
            "routing_receipt_id": "",
            "run_id": run_id,
            "router_policy_id": policy_id,
            "router_demo_suite_id": suite_id,
            "case_id": case_id,
            "input_sha256": _sha256_text(input_text),
            "domain_tag": dom,
            "matched_keywords": hit,
            "selected_adapter_ids": selected,
            "required_adapter_ids": required,
            "created_at": created_at,
            "notes": None,
        }
        receipt["routing_receipt_id"] = sha256_hex_of_obj(
            receipt, drop_keys={"created_at", "routing_receipt_id"}
        )
        validate_schema_bound_object(receipt)
        receipts.append(receipt)

    out_dir = _assert_out_dir_under_exports_runs(repo_root=repo_root, out_dir=out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    expected_paths = [out_dir / f"routing_receipt_{r['case_id']}.json" for r in receipts]
    run_report_path = out_dir / "router_run_report.json"
    enforce_all_or_none_exist([run_report_path, *expected_paths], label="router_hat_demo")

    for r in sorted(receipts, key=lambda d: str(d.get("case_id", ""))):
        p = out_dir / f"routing_receipt_{r['case_id']}.json"
        write_text_worm(
            path=p,
            text=json.dumps(r, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            label=p.name,
        )

    # Build run report after receipts are written (so sha256 references are real).
    case_receipts: List[Dict[str, str]] = []
    for r in sorted(receipts, key=lambda d: str(d.get("case_id", ""))):
        case_id = str(r.get("case_id", "")).strip()
        p = (out_dir / f"routing_receipt_{case_id}.json").resolve()
        try:
            rel = p.relative_to(repo_root).as_posix()
        except Exception:  # noqa: BLE001
            rel = p.as_posix()
        case_receipts.append(
            {
                "case_id": case_id,
                "receipt_path": rel,
                "receipt_sha256": sha256_file_canonical(p),
            }
        )

    run_report: Dict[str, Any] = {
        "schema_id": _RUN_REPORT_SCHEMA_ID,
        "schema_version_hash": schema_version_hash("fl3/kt.router_run_report.v1.json"),
        "router_run_report_id": "",
        "run_id": run_id,
        "router_policy_id": policy_id,
        "router_demo_suite_id": suite_id,
        "status": "PASS",
        "case_receipts": case_receipts,
        "created_at": created_at,
        "notes": None,
    }
    run_report["router_run_report_id"] = sha256_hex_of_obj(
        run_report, drop_keys={"created_at", "router_run_report_id"}
    )
    validate_schema_bound_object(run_report)

    write_text_worm(
        path=run_report_path,
        text=json.dumps(run_report, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        label="router_run_report.json",
    )
    return run_report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="EPIC_19 router hat demo (deterministic routing receipts; schema-bound; WORM outputs).")
    ap.add_argument("--policy", required=True, help="Path to kt.router_policy.v1 JSON.")
    ap.add_argument("--suite", required=True, help="Path to kt.router_demo_suite.v1 JSON.")
    ap.add_argument("--run-id", required=True, help="Run identifier for this router demo.")
    ap.add_argument("--out-dir", required=True, help="Output directory (WORM writes routing_receipt_*.json + router_run_report.json).")
    args = ap.parse_args(list(argv) if argv is not None else None)

    _ = run_router_hat_demo(
        policy_path=Path(args.policy),
        suite_path=Path(args.suite),
        run_id=str(args.run_id),
        out_dir=Path(args.out_dir),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FL3ValidationError as exc:
        raise SystemExit(f"FAIL_CLOSED: {exc}") from exc
