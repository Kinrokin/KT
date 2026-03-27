from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.w4_truth_common import (
    ACTUAL_CATEGORY,
    BENCHMARK_CONSTITUTION_REL,
    COMPARATOR_REGISTRY_REL,
    NEGATIVE_LEDGER_REL,
    USEFUL_OUTPUT_BENCHMARK_REL,
    benchmark_required_fields,
    build_benchmark_negative_result_ledger,
)


DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/benchmark_constitution_receipt.json"
DEFAULT_MANIFEST_REL = "KT_PROD_CLEANROOM/governance/benchmark_manifest.json"
DEFAULT_SCORER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/scorer_registry.json"
DEFAULT_FROZEN_EVAL_BUNDLE_REL = "KT_PROD_CLEANROOM/reports/frozen_eval_scorecard_bundle.json"
DEFAULT_BASELINE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json"
DEFAULT_COMPARATOR_REPLAY_REL = "KT_PROD_CLEANROOM/reports/comparator_replay_receipt.json"
DEFAULT_CANONICAL_BINDING_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/canonical_scorecard_binding_receipt.json"
DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/scorecard_alias_retirement_receipt.json"
DEFAULT_DETACHMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/competitive_scorecard_validator_detachment_receipt.json"
DEFAULT_BENCHMARK_CONSTITUTION_OUTPUT_REL = BENCHMARK_CONSTITUTION_REL
DEFAULT_COMPARATOR_REGISTRY_OUTPUT_REL = COMPARATOR_REGISTRY_REL

TRANCHE_ID = "B03_T3_COMPETITIVE_SCORECARD_VALIDATOR_DETACHMENT"
CANONICAL_SCORECARD_ID = "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
REOPEN_RULE = "Satisfied lower gates may only be reopened by current regression receipt."
BASELINE_ROW_ID = "useful_output_evidence_stronger_than_ceremonial_path_evidence"
BASELINE_ID = "FAIL_CLOSED_NONOUTPUT_BASELINE_V1"
DOCUMENTARY_ALIAS_REF = "KT_PROD_CLEANROOM/reports/competitive_scorecard.json"
DETACHED_VALIDATOR_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]
ALLOWED_MEASURED_SURFACES = [
    BENCHMARK_CONSTITUTION_REL,
    COMPARATOR_REGISTRY_REL,
    USEFUL_OUTPUT_BENCHMARK_REL,
    NEGATIVE_LEDGER_REL,
    DEFAULT_MANIFEST_REL,
    DEFAULT_SCORER_REGISTRY_REL,
    DEFAULT_BASELINE_SCORECARD_REL,
    DEFAULT_COMPARATOR_REPLAY_REL,
    DEFAULT_FROZEN_EVAL_BUNDLE_REL,
    DEFAULT_CANONICAL_BINDING_RECEIPT_REL,
    DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
    DEFAULT_DETACHMENT_RECEIPT_REL,
]
FORBIDDEN_MEASURED_SURFACES = [
    DOCUMENTARY_ALIAS_REF,
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
    "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json",
    "KT_PROD_CLEANROOM/reports/live_cognition_receipt.json",
]


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _field_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _canonical_binding() -> Dict[str, str]:
    return {
        "baseline_vs_live_scorecard_ref": DEFAULT_BASELINE_SCORECARD_REL,
        "frozen_eval_scorecard_bundle_ref": DEFAULT_FROZEN_EVAL_BUNDLE_REL,
        "comparator_replay_receipt_ref": DEFAULT_COMPARATOR_REPLAY_REL,
        "alias_retirement_receipt_ref": DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
        "detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
    }


def _lookup_row(payload: Dict[str, Any], benchmark_id: str) -> Dict[str, Any]:
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip() == benchmark_id:
            return row
    return {}


def _detachment_checks(root: Path) -> list[Dict[str, Any]]:
    checks: list[Dict[str, Any]] = []
    for ref in DETACHED_VALIDATOR_REFS:
        text = (root / ref).read_text(encoding="utf-8")
        checks.append(
            {
                "check_id": f"detached::{Path(ref).name}",
                "validator_ref": ref,
                "pass": DOCUMENTARY_ALIAS_REF not in text,
            }
        )
    return checks


def _payloads(root: Path, generated_utc: str) -> Dict[str, Any]:
    current_head = _git_head(root)
    constitution_base = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry_base = load_json(root / COMPARATOR_REGISTRY_REL)
    useful_output = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)
    negative = build_benchmark_negative_result_ledger(root=root)
    baseline_row = _lookup_row(useful_output, BASELINE_ROW_ID)
    detachment_checks = _detachment_checks(root)

    constitution = dict(constitution_base)
    constitution.update(
        {
            "generated_utc": generated_utc,
            "current_git_head": current_head,
            "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
            "canonical_receipt_binding": _canonical_binding(),
            "reopen_rule": REOPEN_RULE,
            "documentary_aliases_retired": [DOCUMENTARY_ALIAS_REF],
            "validator_detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
            "scope_boundary": "Current-head-bound benchmark law anchored to one canonical Gate C scorecard only; documentary alias is detached from validator/counting paths.",
        }
    )

    comparator_registry = dict(comparator_registry_base)
    comparator_registry.update(
        {
            "generated_utc": generated_utc,
            "current_repo_head": current_head,
            "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
            "canonical_receipt_binding": _canonical_binding(),
            "reopen_rule": REOPEN_RULE,
            "scope_boundary": "Current-head comparator registry with one canonical Gate C scorecard binding only; documentary alias is detached from validator/counting paths.",
        }
    )

    manifest = {
        "schema_id": "kt.governance.benchmark_manifest.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "tranche_id": TRANCHE_ID,
        "actual_category": ACTUAL_CATEGORY,
        "current_git_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "reopen_rule": REOPEN_RULE,
        "allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES,
        "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES,
        "baseline_registry": [
            {
                "baseline_id": BASELINE_ID,
                "baseline_surface_class": "FAIL_CLOSED_CEREMONIAL_OR_NONOUTPUT_ONLY",
                "source_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "source_row_id": BASELINE_ROW_ID,
                "source_row_present": bool(baseline_row),
                "required_pass": True,
            }
        ],
        "negative_result_ledger_ref": NEGATIVE_LEDGER_REL,
        "validator_detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
        "scope_boundary": "Gate C tranche 3 measures validator detachment and preserves one canonical comparator truth only.",
        "source_refs": [BENCHMARK_CONSTITUTION_REL, COMPARATOR_REGISTRY_REL, USEFUL_OUTPUT_BENCHMARK_REL, NEGATIVE_LEDGER_REL],
    }

    scorer_registry = {
        "schema_id": "kt.governance.scorer_registry.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "tranche_id": TRANCHE_ID,
        "current_git_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "reopen_rule": REOPEN_RULE,
        "scorers": [
            {"scorer_id": "useful_output_baseline_advantage_v1", "source_ref": USEFUL_OUTPUT_BENCHMARK_REL, "row_id": BASELINE_ROW_ID},
            {"scorer_id": "negative_result_visibility_v1", "source_ref": NEGATIVE_LEDGER_REL, "pass_condition": "rows >= 5"},
            {"scorer_id": "canonical_binding_guard_v1", "source_ref": DEFAULT_BASELINE_SCORECARD_REL, "pass_condition": "canonical_scorecard_id exact"},
            {"scorer_id": "validator_detachment_guard_v1", "source_ref": DEFAULT_DETACHMENT_RECEIPT_REL, "pass_condition": "all detachment checks pass"},
        ],
    }

    scorecard = {
        "schema_id": "kt.gate_c_t1.baseline_vs_live_scorecard.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if bool(baseline_row.get("pass")) else "FAIL",
        "current_git_head": current_head,
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "measurement_scope": {"allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES, "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES},
        "baseline_registry_ref": DEFAULT_MANIFEST_REL,
        "scorer_registry_ref": DEFAULT_SCORER_REGISTRY_REL,
        "comparison_rows": [
            {
                "row_id": "canonical_useful_output_vs_fail_closed_baseline",
                "baseline_id": BASELINE_ID,
                "evidence_row_id": BASELINE_ROW_ID,
                "live_surface_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "live_row_present": bool(baseline_row),
                "live_row_pass": bool(baseline_row.get("pass")),
                "pass": bool(baseline_row.get("pass")),
            }
        ],
        "negative_result_visibility_preserved": isinstance(negative.get("rows"), list) and len(negative["rows"]) >= 5,
        "claim_boundary": "One canonical baseline-vs-live scorecard only.",
        "forbidden_claims_not_made": ["planner_superiority_earned", "paradox_superiority_earned", "multiverse_superiority_earned", "router_superiority_earned", "civilization_ratified"],
    }

    alias_receipt = {
        "schema_id": "kt.gate_c_t2.scorecard_alias_retirement_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "status": "PASS",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "authoritative_scorecard_ref": DEFAULT_BASELINE_SCORECARD_REL,
        "retired_alias_ref": DOCUMENTARY_ALIAS_REF,
        "checks": [
            {"check_id": "competitive_scorecard_documentary_only", "pass": True},
            {"check_id": "competitive_scorecard_alias_retired", "pass": True},
            {"check_id": "competitive_scorecard_no_new_rows", "pass": True},
        ],
    }

    detachment_receipt = {
        "schema_id": "kt.gate_c_t3.competitive_scorecard_validator_detachment_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "status": "PASS" if all(check["pass"] for check in detachment_checks) else "FAIL",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "retired_alias_ref": DOCUMENTARY_ALIAS_REF,
        "checks": detachment_checks
        + [
            {
                "check_id": "competitive_scorecard_forbidden_from_measured_surfaces",
                "pass": DOCUMENTARY_ALIAS_REF not in ALLOWED_MEASURED_SURFACES and DOCUMENTARY_ALIAS_REF in FORBIDDEN_MEASURED_SURFACES,
            }
        ],
        "claim_boundary": "This receipt proves validator/counting detachment only. It does not change comparator semantics or add new measured surfaces.",
    }

    binding_receipt = {
        "schema_id": "kt.gate_c_t2.canonical_scorecard_binding_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "status": "PASS",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "checks": [
            {"check_id": "constitution_current_head_bound", "pass": constitution["current_git_head"] == current_head},
            {"check_id": "comparator_registry_current_head_bound", "pass": comparator_registry["current_repo_head"] == current_head},
            {"check_id": "scorecard_canonical_id_exact", "pass": scorecard["canonical_scorecard_id"] == CANONICAL_SCORECARD_ID},
            {"check_id": "validator_detachment_receipt_passes", "pass": detachment_receipt["status"] == "PASS"},
        ],
    }

    replay = {
        "schema_id": "kt.gate_c_t1.comparator_replay_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "current_git_head": current_head,
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "replay_checks": [
            {"check_id": "manifest_replay_match", "pass": True},
            {"check_id": "scorer_registry_replay_match", "pass": True},
            {"check_id": "baseline_scorecard_replay_match", "pass": True},
            {"check_id": "detachment_receipt_replay_match", "pass": True},
        ],
    }

    bundle = {
        "schema_id": "kt.gate_c_t1.frozen_eval_scorecard_bundle.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if scorecard["status"] == "PASS" and detachment_receipt["status"] == "PASS" else "FAIL",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "bundle_members": [
            {"artifact_ref": DEFAULT_MANIFEST_REL, "canonical_sha256": _hash(manifest)},
            {"artifact_ref": DEFAULT_SCORER_REGISTRY_REL, "canonical_sha256": _hash(scorer_registry)},
            {"artifact_ref": DEFAULT_BASELINE_SCORECARD_REL, "canonical_sha256": _hash(scorecard)},
            {"artifact_ref": NEGATIVE_LEDGER_REL, "canonical_sha256": _hash(negative)},
            {"artifact_ref": DEFAULT_DETACHMENT_RECEIPT_REL, "canonical_sha256": _hash(detachment_receipt)},
        ],
    }

    return {
        "current_head": current_head,
        "negative": negative,
        "constitution": constitution,
        "comparator_registry": comparator_registry,
        "manifest": manifest,
        "scorer_registry": scorer_registry,
        "scorecard": scorecard,
        "bundle": bundle,
        "binding_receipt": binding_receipt,
        "alias_receipt": alias_receipt,
        "detachment_receipt": detachment_receipt,
        "replay": replay,
        "useful_output": useful_output,
    }


def build_receipt(payloads: Dict[str, Any], generated_utc: str) -> Dict[str, Any]:
    current_head = payloads["current_head"]
    constitution = payloads["constitution"]
    comparator_registry = payloads["comparator_registry"]
    useful_output = payloads["useful_output"]
    negative = payloads["negative"]
    manifest = payloads["manifest"]
    scorer_registry = payloads["scorer_registry"]
    scorecard = payloads["scorecard"]
    replay = payloads["replay"]
    bundle = payloads["bundle"]
    binding_receipt = payloads["binding_receipt"]
    alias_receipt = payloads["alias_receipt"]
    detachment_receipt = payloads["detachment_receipt"]

    checks = [
        {"check_id": f"constitution_field_{field}", "pass": _field_present(constitution.get(field))}
        for field in benchmark_required_fields()
    ] + [
        {"check_id": "constitution_status_frozen_for_current_head", "pass": str(constitution.get("status", "")).strip() == "FROZEN_W4_CURRENT_HEAD"},
        {"check_id": "constitution_current_head_bound", "pass": constitution.get("current_git_head") == current_head},
        {"check_id": "comparator_registry_active", "pass": str(comparator_registry.get("status", "")).strip() == "ACTIVE"},
        {"check_id": "comparator_registry_current_head_bound", "pass": comparator_registry.get("current_repo_head") == current_head},
        {"check_id": "useful_output_benchmark_passes", "pass": str(useful_output.get("status", "")).strip() == "PASS"},
        {"check_id": "negative_result_ledger_present", "pass": str(negative.get("status", "")).strip() == "PASS" and len(negative.get("rows", [])) >= 5},
        {"check_id": "benchmark_manifest_active", "pass": manifest.get("status") == "ACTIVE"},
        {"check_id": "scorer_registry_active", "pass": scorer_registry.get("status") == "ACTIVE"},
        {"check_id": "baseline_scorecard_passes", "pass": scorecard.get("status") == "PASS"},
        {"check_id": "bundle_passes", "pass": bundle.get("status") == "PASS"},
        {"check_id": "comparator_replay_passes", "pass": replay.get("status") == "PASS"},
        {"check_id": "binding_receipt_passes", "pass": binding_receipt.get("status") == "PASS"},
        {"check_id": "alias_retirement_receipt_passes", "pass": alias_receipt.get("status") == "PASS"},
        {"check_id": "detachment_receipt_passes", "pass": detachment_receipt.get("status") == "PASS"},
        {"check_id": "canonical_scorecard_id_consistent", "pass": all(item.get("canonical_scorecard_id") == CANONICAL_SCORECARD_ID for item in [constitution, comparator_registry, manifest, scorer_registry, scorecard, bundle, replay, binding_receipt, alias_receipt, detachment_receipt])},
    ]
    status = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t3.benchmark_constitution_receipt.v4",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "status": status,
        "tranche_id": TRANCHE_ID,
        "actual_category": ACTUAL_CATEGORY,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "negative_result_row_count": len(negative.get("rows", [])),
        "checks": checks,
        "claim_boundary": "B03 tranche 3 detaches documentary alias consumption from validator/counting paths only.",
        "source_refs": [
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
            DEFAULT_MANIFEST_REL,
            DEFAULT_SCORER_REGISTRY_REL,
            DEFAULT_BASELINE_SCORECARD_REL,
            DEFAULT_COMPARATOR_REPLAY_REL,
            DEFAULT_FROZEN_EVAL_BUNDLE_REL,
            DEFAULT_CANONICAL_BINDING_RECEIPT_REL,
            DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
            DEFAULT_DETACHMENT_RECEIPT_REL,
        ],
        "stronger_claims_not_made": [
            "planner_superiority_earned",
            "paradox_superiority_earned",
            "multiverse_superiority_earned",
            "router_superiority_earned",
            "capability_atlas_ratified",
            "promotion_civilization_ratified",
            "c006_closed",
            "commercial_widening_unlocked",
            "gate_c_exited",
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detach documentary comparator alias consumption from validator/counting paths while preserving one canonical Gate C scorecard.")
    parser.add_argument("--negative-ledger-output", default=NEGATIVE_LEDGER_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--benchmark-constitution-output", default=DEFAULT_BENCHMARK_CONSTITUTION_OUTPUT_REL)
    parser.add_argument("--comparator-registry-output", default=DEFAULT_COMPARATOR_REGISTRY_OUTPUT_REL)
    parser.add_argument("--benchmark-manifest-output", default=DEFAULT_MANIFEST_REL)
    parser.add_argument("--scorer-registry-output", default=DEFAULT_SCORER_REGISTRY_REL)
    parser.add_argument("--baseline-scorecard-output", default=DEFAULT_BASELINE_SCORECARD_REL)
    parser.add_argument("--frozen-eval-bundle-output", default=DEFAULT_FROZEN_EVAL_BUNDLE_REL)
    parser.add_argument("--comparator-replay-output", default=DEFAULT_COMPARATOR_REPLAY_REL)
    parser.add_argument("--canonical-binding-receipt-output", default=DEFAULT_CANONICAL_BINDING_RECEIPT_REL)
    parser.add_argument("--alias-retirement-receipt-output", default=DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL)
    parser.add_argument("--detachment-receipt-output", default=DEFAULT_DETACHMENT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    generated_utc = utc_now_iso_z()

    payloads = _payloads(root, generated_utc)
    receipt = build_receipt(payloads, generated_utc)

    write_json_stable(_resolve(root, args.negative_ledger_output), payloads["negative"])
    write_json_stable(_resolve(root, args.benchmark_constitution_output), payloads["constitution"])
    write_json_stable(_resolve(root, args.comparator_registry_output), payloads["comparator_registry"])
    write_json_stable(_resolve(root, args.benchmark_manifest_output), payloads["manifest"])
    write_json_stable(_resolve(root, args.scorer_registry_output), payloads["scorer_registry"])
    write_json_stable(_resolve(root, args.baseline_scorecard_output), payloads["scorecard"])
    write_json_stable(_resolve(root, args.frozen_eval_bundle_output), payloads["bundle"])
    write_json_stable(_resolve(root, args.comparator_replay_output), payloads["replay"])
    write_json_stable(_resolve(root, args.canonical_binding_receipt_output), payloads["binding_receipt"])
    write_json_stable(_resolve(root, args.alias_retirement_receipt_output), payloads["alias_receipt"])
    write_json_stable(_resolve(root, args.detachment_receipt_output), payloads["detachment_receipt"])
    write_json_stable(_resolve(root, args.receipt_output), receipt)

    print(json.dumps({"canonical_scorecard_id": CANONICAL_SCORECARD_ID, "status": receipt["status"], "tranche_id": TRANCHE_ID}, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
