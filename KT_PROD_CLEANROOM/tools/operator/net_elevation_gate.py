from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return 0
    return int(value)


def evaluate_net_elevation(spec: Mapping[str, Any]) -> Dict[str, Any]:
    positive_raw = spec.get("positive_factors", {})
    negative_raw = spec.get("negative_factors", {})
    policy_raw = spec.get("policy", {})

    positive_factors = {str(key): max(0, _int(value)) for key, value in dict(positive_raw).items()}
    negative_factors = {str(key): max(0, _int(value)) for key, value in dict(negative_raw).items()}
    policy = {str(key): value for key, value in dict(policy_raw).items()}

    runtime_loc_delta = max(0, _int(spec.get("runtime_loc_delta", 0)))
    test_loc_delta = max(0, _int(spec.get("test_loc_delta", 0)))
    governance_json_loc_delta = max(0, _int(spec.get("governance_json_loc_delta", 0)))
    authoritative_surface_delta = max(0, _int(spec.get("authoritative_surface_delta", 0)))
    max_new_authoritative_surfaces = max(0, _int(policy.get("max_new_authoritative_surfaces", 3)))
    allow_zero_net = bool(policy.get("allow_zero_net", True))

    positive_total = sum(positive_factors.values())
    negative_total = sum(negative_factors.values())
    runtime_substance_total = runtime_loc_delta + test_loc_delta
    net_elevation_score = positive_total - negative_total

    checks = [
        {
            "check_id": "positive_outweighs_negative",
            "pass": net_elevation_score >= 0 if allow_zero_net else net_elevation_score > 0,
            "detail": {"positive_total": positive_total, "negative_total": negative_total},
        },
        {
            "check_id": "authoritative_surface_budget_respected",
            "pass": authoritative_surface_delta <= max_new_authoritative_surfaces,
            "detail": {
                "authoritative_surface_delta": authoritative_surface_delta,
                "max_new_authoritative_surfaces": max_new_authoritative_surfaces,
            },
        },
        {
            "check_id": "runtime_or_test_substance_not_outrun_by_governance_json",
            "pass": runtime_substance_total >= governance_json_loc_delta,
            "detail": {
                "runtime_substance_total": runtime_substance_total,
                "governance_json_loc_delta": governance_json_loc_delta,
            },
        },
        {
            "check_id": "claim_inflation_guard",
            "pass": negative_factors.get("claim_inflation", 0) == 0,
            "detail": {"claim_inflation": negative_factors.get("claim_inflation", 0)},
        },
    ]

    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.operator.net_elevation_gate.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "net_elevation_score": net_elevation_score,
        "positive_factors": positive_factors,
        "negative_factors": negative_factors,
        "runtime_loc_delta": runtime_loc_delta,
        "test_loc_delta": test_loc_delta,
        "governance_json_loc_delta": governance_json_loc_delta,
        "authoritative_surface_delta": authoritative_surface_delta,
        "policy": {
            "max_new_authoritative_surfaces": max_new_authoritative_surfaces,
            "allow_zero_net": allow_zero_net,
        },
        "checks": checks,
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate KT net elevation from a bounded scoring spec.")
    parser.add_argument("--input", required=True, help="Path to the scoring spec JSON.")
    parser.add_argument("--output", default="", help="Optional output receipt path.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    input_path = Path(str(args.input)).expanduser()
    if not input_path.is_absolute():
        input_path = (root / input_path).resolve()
    output_path = Path(str(args.output)).expanduser() if str(args.output).strip() else Path()
    if output_path and not output_path.is_absolute():
        output_path = (root / output_path).resolve()

    payload = load_json(input_path)
    result = evaluate_net_elevation(payload)
    if output_path:
        write_json_stable(output_path, result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
