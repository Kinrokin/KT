from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import load_json, repo_root, write_json_stable
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

TRANCHE_ID = "B03_T1_FROZEN_COMPARATOR_CONSTITUTION"
CANONICAL_SCORECARD_ID = "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
REOPEN_RULE = "Satisfied lower gates may only be reopened by current regression receipt."
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
]
FORBIDDEN_MEASURED_SURFACES = [
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
    "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json",
    "KT_PROD_CLEANROOM/reports/live_cognition_receipt.json",
]
BASELINE_ROW_ID = "useful_output_evidence_stronger_than_ceremonial_path_evidence"
BASELINE_ID = "FAIL_CLOSED_NONOUTPUT_BASELINE_V1"


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _field_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _payload_hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _lookup_row(payload: Dict[str, Any], benchmark_id: str) -> Dict[str, Any]:
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip() == benchmark_id:
            return row
    return {}


def _canonical_binding() -> Dict[str, str]:
    return {
        "baseline_vs_live_scorecard_ref": DEFAULT_BASELINE_SCORECARD_REL,
        "frozen_eval_scorecard_bundle_ref": DEFAULT_FROZEN_EVAL_BUNDLE_REL,
        "comparator_replay_receipt_ref": DEFAULT_COMPARATOR_REPLAY_REL,
    }


def build_benchmark_manifest(
    *,
    root: Path,
    generated_utc: str,
    negative_ledger: Dict[str, Any],
) -> Dict[str, Any]:
    constitution = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry = load_json(root / COMPARATOR_REGISTRY_REL)
    useful_output_benchmark = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)
    baseline_row = _lookup_row(useful_output_benchmark, BASELINE_ROW_ID)
    current_head = _git_head(root)
    negative_rows = negative_ledger.get("rows", [])
    return {
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
                "required_pass": True,
                "source_row_present": bool(baseline_row),
            }
        ],
        "freeze_mode": "CANONICAL_BASELINE_VS_LIVE_ONLY",
        "negative_result_ledger_ref": NEGATIVE_LEDGER_REL,
        "source_refs": [
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
        ],
        "scope_boundary": (
            "Gate C tranche 1 measures only frozen comparator constitution surfaces. It does not score cognition, "
            "paradox, temporal, multiverse, router, or any broader capability organ."
        ),
        "supporting_statuses": {
            "constitution_status": str(constitution.get("status", "")).strip(),
            "comparator_registry_status": str(comparator_registry.get("status", "")).strip(),
            "negative_result_row_count": len(negative_rows) if isinstance(negative_rows, list) else 0,
        },
    }


def build_scorer_registry(*, root: Path, generated_utc: str) -> Dict[str, Any]:
    current_head = _git_head(root)
    return {
        "schema_id": "kt.governance.scorer_registry.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "tranche_id": TRANCHE_ID,
        "current_git_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "reopen_rule": REOPEN_RULE,
        "scorers": [
            {
                "scorer_id": "useful_output_baseline_advantage_v1",
                "kind": "BOOLEAN_ROW_PASS",
                "source_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "row_id": BASELINE_ROW_ID,
                "pass_condition": "row.pass == true",
                "scope_class": "COMPARATOR_CONSTITUTION_ONLY",
            },
            {
                "scorer_id": "negative_result_visibility_v1",
                "kind": "MIN_ROW_COUNT",
                "source_ref": NEGATIVE_LEDGER_REL,
                "pass_condition": "rows >= 5",
                "scope_class": "COMPARATOR_CONSTITUTION_ONLY",
            },
            {
                "scorer_id": "historical_contamination_guard_v1",
                "kind": "BOOLEAN_FIELD",
                "source_ref": BENCHMARK_CONSTITUTION_REL,
                "field_path": "contamination_policy.historical_uplift_forbidden",
                "pass_condition": "value == true",
                "scope_class": "COMPARATOR_CONSTITUTION_ONLY",
            },
            {
                "scorer_id": "canonical_binding_guard_v1",
                "kind": "REF_EQUALITY",
                "source_ref": DEFAULT_BASELINE_SCORECARD_REL,
                "pass_condition": "canonical_scorecard_id and canonical_receipt_binding are exact",
                "scope_class": "COMPARATOR_CONSTITUTION_ONLY",
            },
        ],
        "scope_boundary": "This scorer registry is comparator-law only and cannot be reused to narrate broader capability surfaces.",
    }


def build_baseline_vs_live_scorecard(
    *,
    root: Path,
    generated_utc: str,
    manifest: Dict[str, Any],
    scorer_registry: Dict[str, Any],
    negative_ledger: Dict[str, Any],
) -> Dict[str, Any]:
    constitution = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry = load_json(root / COMPARATOR_REGISTRY_REL)
    useful_output_benchmark = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)
    row = _lookup_row(useful_output_benchmark, BASELINE_ROW_ID)
    negative_rows = negative_ledger.get("rows", [])
    contamination_safe = bool((constitution.get("contamination_policy") or {}).get("historical_uplift_forbidden"))
    row_pass = bool(row.get("pass"))
    registry_active = _status_is(comparator_registry.get("status"), "ACTIVE")
    negative_ok = isinstance(negative_rows, list) and len(negative_rows) >= 5
    status = "PASS" if all([row_pass, contamination_safe, registry_active, negative_ok]) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t1.baseline_vs_live_scorecard.v1",
        "generated_utc": generated_utc,
        "status": status,
        "current_git_head": _git_head(root),
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "measurement_scope": {
            "allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES,
            "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES,
        },
        "baseline_registry_ref": DEFAULT_MANIFEST_REL,
        "scorer_registry_ref": DEFAULT_SCORER_REGISTRY_REL,
        "comparison_rows": [
            {
                "row_id": "canonical_useful_output_vs_fail_closed_baseline",
                "baseline_id": BASELINE_ID,
                "baseline_surface_class": "FAIL_CLOSED_CEREMONIAL_OR_NONOUTPUT_ONLY",
                "live_surface_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "evidence_row_id": BASELINE_ROW_ID,
                "live_row_present": bool(row),
                "live_row_pass": row_pass,
                "pass": row_pass,
            }
        ],
        "contamination_safe": contamination_safe,
        "negative_result_visibility_preserved": negative_ok,
        "comparator_registry_status": str(comparator_registry.get("status", "")).strip(),
        "claim_boundary": (
            "This is the one canonical baseline-vs-live scorecard for Gate C tranche 1. It only proves that the bounded "
            "useful-output live lane remains stronger than the fail-closed nonoutput baseline under frozen comparator law."
        ),
        "forbidden_claims_not_made": [
            "planner_superiority_earned",
            "paradox_superiority_earned",
            "multiverse_superiority_earned",
            "router_superiority_earned",
            "civilization_ratified",
        ],
        "source_refs": [
            DEFAULT_MANIFEST_REL,
            DEFAULT_SCORER_REGISTRY_REL,
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
        ],
        "supporting_refs": {
            "manifest_status": str(manifest.get("status", "")).strip(),
            "scorer_registry_status": str(scorer_registry.get("status", "")).strip(),
        },
    }


def build_frozen_eval_scorecard_bundle(
    *,
    generated_utc: str,
    manifest: Dict[str, Any],
    scorer_registry: Dict[str, Any],
    baseline_scorecard: Dict[str, Any],
    negative_ledger: Dict[str, Any],
) -> Dict[str, Any]:
    manifest_hash = _payload_hash(manifest)
    scorer_registry_hash = _payload_hash(scorer_registry)
    scorecard_hash = _payload_hash(baseline_scorecard)
    negative_hash = _payload_hash(negative_ledger)
    status = (
        "PASS"
        if str(manifest.get("status", "")).strip() == "ACTIVE"
        and str(scorer_registry.get("status", "")).strip() == "ACTIVE"
        and str(baseline_scorecard.get("status", "")).strip() == "PASS"
        else "FAIL"
    )
    return {
        "schema_id": "kt.gate_c_t1.frozen_eval_scorecard_bundle.v1",
        "generated_utc": generated_utc,
        "status": status,
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "bundle_members": [
            {"artifact_ref": DEFAULT_MANIFEST_REL, "canonical_sha256": manifest_hash, "role": "benchmark_manifest"},
            {"artifact_ref": DEFAULT_SCORER_REGISTRY_REL, "canonical_sha256": scorer_registry_hash, "role": "scorer_registry"},
            {"artifact_ref": DEFAULT_BASELINE_SCORECARD_REL, "canonical_sha256": scorecard_hash, "role": "canonical_scorecard"},
            {"artifact_ref": NEGATIVE_LEDGER_REL, "canonical_sha256": negative_hash, "role": "negative_result_ledger"},
        ],
        "measurement_scope": {
            "allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES,
            "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES,
        },
        "claim_boundary": "This bundle freezes comparator-law surfaces only. It does not certify broader cognition or routing capability.",
    }


def build_comparator_replay_receipt(
    *,
    root: Path,
    generated_utc: str,
    negative_ledger: Dict[str, Any],
    manifest: Dict[str, Any],
    scorer_registry: Dict[str, Any],
    baseline_scorecard: Dict[str, Any],
    bundle: Dict[str, Any],
) -> Dict[str, Any]:
    manifest_replay = build_benchmark_manifest(root=root, generated_utc=generated_utc, negative_ledger=negative_ledger)
    scorer_registry_replay = build_scorer_registry(root=root, generated_utc=generated_utc)
    scorecard_replay = build_baseline_vs_live_scorecard(
        root=root,
        generated_utc=generated_utc,
        manifest=manifest_replay,
        scorer_registry=scorer_registry_replay,
        negative_ledger=negative_ledger,
    )
    bundle_replay = build_frozen_eval_scorecard_bundle(
        generated_utc=generated_utc,
        manifest=manifest_replay,
        scorer_registry=scorer_registry_replay,
        baseline_scorecard=scorecard_replay,
        negative_ledger=negative_ledger,
    )
    manifest_match = _payload_hash(manifest) == _payload_hash(manifest_replay)
    scorer_registry_match = _payload_hash(scorer_registry) == _payload_hash(scorer_registry_replay)
    scorecard_match = _payload_hash(baseline_scorecard) == _payload_hash(scorecard_replay)
    bundle_match = _payload_hash(bundle) == _payload_hash(bundle_replay)
    status = "PASS" if all([manifest_match, scorer_registry_match, scorecard_match, bundle_match]) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t1.comparator_replay_receipt.v1",
        "generated_utc": generated_utc,
        "status": status,
        "current_git_head": _git_head(root),
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "replay_checks": [
            {"check_id": "manifest_replay_match", "pass": manifest_match},
            {"check_id": "scorer_registry_replay_match", "pass": scorer_registry_match},
            {"check_id": "baseline_scorecard_replay_match", "pass": scorecard_match},
            {"check_id": "bundle_replay_match", "pass": bundle_match},
        ],
        "claim_boundary": "Replay receipt proves deterministic reconstruction of the comparator constitution bundle only.",
    }


def build_receipt(
    *,
    root: Path,
    generated_utc: str,
    negative_ledger: Dict[str, Any],
    manifest: Dict[str, Any],
    scorer_registry: Dict[str, Any],
    baseline_scorecard: Dict[str, Any],
    comparator_replay: Dict[str, Any],
    bundle: Dict[str, Any],
) -> Dict[str, Any]:
    constitution = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry = load_json(root / COMPARATOR_REGISTRY_REL)
    useful_output_benchmark = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)
    field_checks = [
        {
            "check_id": f"constitution_field_{field}",
            "pass": _field_present(constitution.get(field)),
        }
        for field in benchmark_required_fields()
    ]
    negative_rows = negative_ledger.get("rows", [])
    negative_row_count = len(negative_rows) if isinstance(negative_rows, list) else 0
    scorecard_binding = baseline_scorecard.get("canonical_receipt_binding") or {}
    checks = field_checks + [
        {
            "check_id": "constitution_status_frozen_for_current_head",
            "pass": str(constitution.get("status", "")).strip() == "FROZEN_W4_CURRENT_HEAD",
        },
        {
            "check_id": "constitution_category_matches_actual_category",
            "pass": str(constitution.get("actual_category", "")).strip() == ACTUAL_CATEGORY,
        },
        {
            "check_id": "comparator_registry_active",
            "pass": _status_is(comparator_registry.get("status"), "ACTIVE"),
        },
        {
            "check_id": "useful_output_benchmark_passes",
            "pass": _status_is(useful_output_benchmark.get("status"), "PASS"),
        },
        {
            "check_id": "negative_result_ledger_present",
            "pass": _status_is(negative_ledger.get("status"), "PASS") and negative_row_count >= 5,
        },
        {
            "check_id": "benchmark_manifest_active",
            "pass": str(manifest.get("status", "")).strip() == "ACTIVE",
        },
        {
            "check_id": "scorer_registry_active",
            "pass": str(scorer_registry.get("status", "")).strip() == "ACTIVE",
        },
        {
            "check_id": "baseline_scorecard_passes",
            "pass": str(baseline_scorecard.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "comparator_replay_passes",
            "pass": str(comparator_replay.get("status", "")).strip() == "PASS",
        },
        {
            "check_id": "canonical_scorecard_id_consistent",
            "pass": all(
                str(item.get("canonical_scorecard_id", "")).strip() == CANONICAL_SCORECARD_ID
                for item in (manifest, scorer_registry, baseline_scorecard, comparator_replay, bundle)
            ),
        },
        {
            "check_id": "canonical_receipt_binding_consistent",
            "pass": scorecard_binding == _canonical_binding() and bundle.get("canonical_receipt_binding") == _canonical_binding(),
        },
        {
            "check_id": "measurement_scope_limited",
            "pass": baseline_scorecard.get("measurement_scope", {}).get("forbidden_measured_surfaces") == FORBIDDEN_MEASURED_SURFACES,
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t1.benchmark_constitution_receipt.v2",
        "generated_utc": generated_utc,
        "current_git_head": _git_head(root),
        "status": status,
        "tranche_id": TRANCHE_ID,
        "actual_category": ACTUAL_CATEGORY,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "negative_result_row_count": negative_row_count,
        "checks": checks,
        "claim_boundary": (
            "B03 tranche 1 freezes comparator constitution and one canonical baseline-vs-live scorecard only. "
            "It does not unlock planner, paradox, temporal, multiverse, router, civilization, externality, or product widening."
        ),
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
        ],
        "stronger_claims_not_made": [
            "planner_superiority_earned",
            "paradox_superiority_earned",
            "multiverse_superiority_earned",
            "router_superiority_earned",
            "capability_atlas_ratifed",
            "promotion_civilization_ratified",
            "c006_closed",
            "commercial_widening_unlocked",
        ],
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the frozen comparator constitution and emit one canonical baseline-vs-live scorecard.")
    parser.add_argument("--negative-ledger-output", default=NEGATIVE_LEDGER_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--benchmark-manifest-output", default=DEFAULT_MANIFEST_REL)
    parser.add_argument("--scorer-registry-output", default=DEFAULT_SCORER_REGISTRY_REL)
    parser.add_argument("--baseline-scorecard-output", default=DEFAULT_BASELINE_SCORECARD_REL)
    parser.add_argument("--frozen-eval-bundle-output", default=DEFAULT_FROZEN_EVAL_BUNDLE_REL)
    parser.add_argument("--comparator-replay-output", default=DEFAULT_COMPARATOR_REPLAY_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    root = repo_root()
    generated_utc = subprocess.check_output(
        ["python", "-c", "from tools.operator.titanium_common import utc_now_iso_z; print(utc_now_iso_z())"],
        cwd=str(root / "KT_PROD_CLEANROOM"),
        text=True,
    ).strip()

    negative_ledger = build_benchmark_negative_result_ledger(root=root)
    manifest = build_benchmark_manifest(root=root, generated_utc=generated_utc, negative_ledger=negative_ledger)
    scorer_registry = build_scorer_registry(root=root, generated_utc=generated_utc)
    baseline_scorecard = build_baseline_vs_live_scorecard(
        root=root,
        generated_utc=generated_utc,
        manifest=manifest,
        scorer_registry=scorer_registry,
        negative_ledger=negative_ledger,
    )
    bundle = build_frozen_eval_scorecard_bundle(
        generated_utc=generated_utc,
        manifest=manifest,
        scorer_registry=scorer_registry,
        baseline_scorecard=baseline_scorecard,
        negative_ledger=negative_ledger,
    )
    comparator_replay = build_comparator_replay_receipt(
        root=root,
        generated_utc=generated_utc,
        negative_ledger=negative_ledger,
        manifest=manifest,
        scorer_registry=scorer_registry,
        baseline_scorecard=baseline_scorecard,
        bundle=bundle,
    )
    receipt = build_receipt(
        root=root,
        generated_utc=generated_utc,
        negative_ledger=negative_ledger,
        manifest=manifest,
        scorer_registry=scorer_registry,
        baseline_scorecard=baseline_scorecard,
        comparator_replay=comparator_replay,
        bundle=bundle,
    )

    write_json_stable(_resolve(root, args.negative_ledger_output), negative_ledger)
    write_json_stable(_resolve(root, args.benchmark_manifest_output), manifest)
    write_json_stable(_resolve(root, args.scorer_registry_output), scorer_registry)
    write_json_stable(_resolve(root, args.baseline_scorecard_output), baseline_scorecard)
    write_json_stable(_resolve(root, args.frozen_eval_bundle_output), bundle)
    write_json_stable(_resolve(root, args.comparator_replay_output), comparator_replay)
    write_json_stable(_resolve(root, args.receipt_output), receipt)

    summary = {
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "status": receipt["status"],
        "tranche_id": TRANCHE_ID,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
