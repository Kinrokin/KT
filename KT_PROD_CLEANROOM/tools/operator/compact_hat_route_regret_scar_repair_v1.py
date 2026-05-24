from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as taxonomy
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_V1"
TARGET_OUTCOME = "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_READY__EXPANDED_DETACHED_BENCH_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_EXPANDED_EXTERNAL_MARKET_BENCHMARK_AND_DETACHED_VERIFIER_PACKET"
COMPUTE_PACKET_NAME = "kt13_expand_repair_v1.zip"
KNOWN_EVIDENCE_HEAD = "4de572be825acb0e7551174575e225b74d6cf523"
SOURCE_PACKET_SHA256 = "ed0dae10e8c3f6be08dd30afa0e2003eaffd4f4b91ff42e29693410a53a22e4d"
HF_FINAL_ADAPTER_STORE = "Kinrokin/kt13-full-e2e-final-only-20260524-174447"

BLOCKED_CLAIMS = dict(taxonomy.BLOCKED_CLAIMS)
CANONICAL_LOBES = [lobe_id for lobe_id, _, _ in taxonomy.CANONICAL_LOBES]

ARTIFACTS: dict[str, str] = {
    "inspection_receipt": "KT_PROD_CLEANROOM/reports/kt_compact_hat_route_regret_scar_repair_inspection_receipt.json",
    "kt_hat_mode_contract": "configs/kt_hat_mode_contract.json",
    "kt_hat_mode_schema": "runtime/kt_hat_mode_contract.schema.json",
    "kt_hat_compact_policy": "runtime/kt_hat_compact_policy.json",
    "kt_hat_bench_policy": "runtime/kt_hat_bench_policy.json",
    "kt_hat_operator_policy": "runtime/kt_hat_operator_policy.json",
    "kt_hat_high_risk_policy": "runtime/kt_hat_high_risk_policy.json",
    "kt_hat_math_policy": "runtime/kt_hat_math_policy.json",
    "kt_hat_audit_policy": "runtime/kt_hat_audit_policy.json",
    "formal_math_base": "configs/formal_math_repair/base.yaml",
    "formal_math_datasets": "configs/formal_math_repair/datasets.yaml",
    "formal_math_tranche_config": "training/formal_math_repair_tranche_config.json",
    "numeric_answer_schema": "training/numeric_answer_extraction_schema.json",
    "route_regret_matrix_schema": "router/route_regret_matrix.schema.json",
    "route_regret_scorecard_schema": "router/route_regret_scorecard.schema.json",
    "scar_cluster_schema": "adaptive/scar_cluster_receipt.schema.json",
    "delta_corpus_schema": "adaptive/delta_corpus_manifest.schema.json",
    "delta_distinct_hash_schema": "adaptive/delta_adapter_distinct_hash_receipt.schema.json",
    "benchmark_external_50": "configs/benchmark_external_50.yaml",
    "expanded_benchmark_config": "benchmarks/expanded_detached_benchmark_config.json",
    "verified_work_schema": "benchmarks/verified_work_per_token_scorecard.schema.json",
    "benchmark_leakage_schema": "benchmarks/benchmark_leakage_scan.schema.json",
    "evaluator_integrity_schema": "benchmarks/evaluator_integrity_receipt.schema.json",
    "repair_readiness_receipt": "KT_PROD_CLEANROOM/reports/kt_compact_hat_route_regret_scar_repair_receipt.json",
    "artifact_registry": "registry/artifact_authority_registry.json",
    "artifact_delta": "registry/artifact_authority_registry_compact_hat_route_regret_scar_repair_delta_receipt.json",
    "packet_dir": "packets/kt13_expand_repair_v1",
    "packet_manifest": "packets/kt13_expand_repair_v1/PACKET_MANIFEST.json",
    "packet_readme": "packets/kt13_expand_repair_v1/README_RUNBOOK.md",
    "packet_bootstrap": "packets/kt13_expand_repair_v1/KAGGLE_BOOTSTRAP_CELL.py",
    "packet_runner": "packets/kt13_expand_repair_v1/KT13_EXPAND_REPAIR_V1_RUNNER.py",
    "packet_hash_manifest": "packets/kt13_expand_repair_v1/SHA256_MANIFEST.json",
    "packet_zip": f"packets/{COMPUTE_PACKET_NAME}",
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _git_branch(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _write_text_stable(path: Path, text: str) -> bool:
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def normalize_math_answer(text: object) -> str | None:
    raw = "" if text is None else str(text)
    if not raw.strip():
        return None
    patterns = [
        r"\\boxed\{([^{}]+)\}",
        r"####\s*([-+]?\d[\d,]*(?:\.\d+)?(?:/\d[\d,]*)?)",
        r"(?:final answer|answer|therefore|so)\s*(?:is|=|:)?\s*([-+]?\d[\d,]*(?:\.\d+)?(?:/\d[\d,]*)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, flags=re.IGNORECASE)
        if match:
            return _canonical_number(match.group(1))
    candidates = re.findall(r"[-+]?\d[\d,]*(?:\.\d+)?(?:/\d[\d,]*)?", raw)
    return _canonical_number(candidates[-1]) if candidates else None


def _canonical_number(value: str) -> str | None:
    cleaned = value.strip().replace(",", "")
    if not cleaned:
        return None
    if "/" in cleaned:
        left, right = cleaned.split("/", 1)
        try:
            denom = float(right)
            if denom == 0:
                return None
            return _trim_float(float(left) / denom)
        except ValueError:
            return None
    try:
        return _trim_float(float(cleaned))
    except ValueError:
        return None


def _trim_float(value: float) -> str:
    if math.isclose(value, round(value), rel_tol=0, abs_tol=1e-12):
        return str(int(round(value)))
    return f"{value:.12g}"


def score_math_answers(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    scored = []
    correct = 0
    for row in rows:
        expected = normalize_math_answer(row.get("expected"))
        actual = normalize_math_answer(row.get("actual"))
        is_correct = expected is not None and actual is not None and expected == actual
        correct += int(is_correct)
        scored.append(
            {
                "sample_id": row.get("sample_id"),
                "expected_normalized": expected,
                "actual_normalized": actual,
                "correct": is_correct,
            }
        )
    return {
        "sample_count": len(scored),
        "correct_count": correct,
        "accuracy": correct / len(scored) if scored else 0.0,
        "scored_rows": scored,
    }


def build_route_regret_matrix(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    matrix = []
    total_regret = 0.0
    overroute_count = 0
    for row in rows:
        route_scores = row.get("route_scores", {})
        if not isinstance(route_scores, Mapping) or not route_scores:
            raise ValueError("route_scores required for route regret")
        selected_route = str(row.get("selected_route"))
        if selected_route not in route_scores:
            raise ValueError(f"selected_route missing from route_scores: {selected_route}")
        best_route = max(route_scores, key=lambda key: float(route_scores[key]))
        selected_score = float(route_scores[selected_route])
        best_score = float(route_scores[best_route])
        regret = max(0.0, best_score - selected_score)
        token_count = max(1.0, float(row.get("token_count", 1)))
        verified_work = max(0.0, selected_score)
        routed_to_heavy = bool(row.get("routed_to_heavy", selected_route not in {"base", "compact"}))
        baseline_score = float(route_scores.get("base", selected_score))
        overroute = routed_to_heavy and selected_score <= baseline_score
        overroute_count += int(overroute)
        total_regret += regret
        matrix.append(
            {
                "sample_id": row.get("sample_id"),
                "selected_route": selected_route,
                "best_route": best_route,
                "selected_score": selected_score,
                "best_score": best_score,
                "route_regret": regret,
                "token_count": token_count,
                "verified_work": verified_work,
                "verified_work_per_token": verified_work / token_count,
                "overroute": overroute,
            }
        )
    return {
        "schema_id": "kt.router.route_regret_matrix.v1",
        "sample_count": len(matrix),
        "mean_route_regret": total_regret / len(matrix) if matrix else 0.0,
        "overroute_rate": overroute_count / len(matrix) if matrix else 0.0,
        "rows": matrix,
    }


def verify_delta_distinctness(
    *,
    failure_rows: Sequence[Mapping[str, Any]],
    delta_rows: Sequence[Mapping[str, Any]],
    parent_adapter_hash: str,
    delta_adapter_hash: str,
) -> dict[str, Any]:
    def clean_id(value: object) -> str:
        return "" if value is None else str(value).strip()

    missing_failure_id_rows = [index for index, row in enumerate(failure_rows) if not clean_id(row.get("failure_id"))]
    missing_delta_source_id_rows = [index for index, row in enumerate(delta_rows) if not clean_id(row.get("source_failure_id"))]
    failure_ids = {clean_id(row.get("failure_id")) for row in failure_rows if clean_id(row.get("failure_id"))}
    mapped_ids = {clean_id(row.get("source_failure_id")) for row in delta_rows if clean_id(row.get("source_failure_id"))}
    unmapped = sorted(mapped_ids - failure_ids)
    missing = sorted(failure_ids - mapped_ids)
    distinct = bool(parent_adapter_hash) and bool(delta_adapter_hash) and parent_adapter_hash != delta_adapter_hash
    identifiers_complete = not missing_failure_id_rows and not missing_delta_source_id_rows
    return {
        "schema_id": "kt.adaptive.delta_adapter_distinct_hash_receipt.v1",
        "failure_count": len(failure_ids),
        "delta_example_count": len(delta_rows),
        "missing_failure_id_rows": missing_failure_id_rows,
        "missing_delta_source_id_rows": missing_delta_source_id_rows,
        "identifiers_complete": identifiers_complete,
        "parent_adapter_hash": parent_adapter_hash,
        "delta_adapter_hash": delta_adapter_hash,
        "delta_adapter_hash_distinct": distinct,
        "all_delta_examples_map_to_observed_failures": not unmapped,
        "observed_failures_without_delta_examples": missing,
        "unmapped_delta_failure_ids": unmapped,
        "scar_learning_claim_allowed": distinct and identifiers_complete and not unmapped and not missing,
    }


def _json_schema(schema_id: str, required: Sequence[str], properties: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        "type": "object",
        "required": list(required),
        "properties": dict(properties),
        "additionalProperties": True,
    }


def _kt_hat_mode_contract() -> dict[str, Any]:
    return {
        "schema_id": "kt.runtime.kt_hat_mode_contract.v1",
        "artifact_id": "KT_HAT_MODE_CONTRACT",
        "authority": "INTERNAL_SHADOW_RUNTIME_POLICY_ONLY",
        "mode_order": ["compact", "bench", "operator", "high_risk", "math", "audit"],
        "claim_ceiling_preserved": True,
        "modes": {
            "compact": {
                "purpose": "minimal routing and claim-boundary wrapper for low-token execution",
                "max_overhead_tokens": 160,
                "answer_style": "direct",
                "requires_claim_footer": False,
                "allows_internal_trace": False,
            },
            "bench": {
                "purpose": "benchmark execution with answer extraction and no narrative expansion",
                "max_overhead_tokens": 96,
                "answer_style": "answer_only",
                "requires_numeric_answer_extraction": True,
                "allows_internal_trace": False,
            },
            "operator": {
                "purpose": "bounded operator workflow guidance with receipts",
                "max_overhead_tokens": 320,
                "answer_style": "concise_steps",
                "allows_internal_trace": False,
            },
            "high_risk": {
                "purpose": "tighten refusal, evidence, and escalation behavior on sensitive surfaces",
                "max_overhead_tokens": 420,
                "answer_style": "bounded_with_refusal_if_needed",
                "requires_escalation_check": True,
                "allows_internal_trace": False,
            },
            "math": {
                "purpose": "formal math repair and final answer extraction",
                "max_overhead_tokens": 240,
                "answer_style": "short_derivation_plus_final_answer",
                "requires_numeric_answer_extraction": True,
                "allows_internal_trace": False,
            },
            "audit": {
                "purpose": "receipt and claim-boundary audit",
                "max_overhead_tokens": 512,
                "answer_style": "evidence_table",
                "requires_receipt_references": True,
                "allows_internal_trace": False,
            },
        },
        **BLOCKED_CLAIMS,
    }


def _mode_policy(mode: str, max_tokens: int, answer_style: str, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema_id": f"kt.runtime.kt_hat_{mode}_policy.v1",
        "mode": mode,
        "max_overhead_tokens": max_tokens,
        "answer_style": answer_style,
        "token_budget_enforced": True,
        "claim_ceiling_preserved": True,
        "production_authority": False,
        "external_claim_authority": False,
        **(dict(extra or {})),
        **BLOCKED_CLAIMS,
    }


def _payloads(current_head: str) -> dict[str, Any | str]:
    lobe_targets = ["formal_proof_reasoning_lobe", "learning_delta_lobe", "audit_reasoning_lobe"]
    return {
        ARTIFACTS["kt_hat_mode_contract"]: _kt_hat_mode_contract(),
        ARTIFACTS["kt_hat_mode_schema"]: _json_schema(
            "kt.runtime.kt_hat_mode_contract.schema.v1",
            ["schema_id", "modes", "claim_ceiling_preserved"],
            {
                "schema_id": {"const": "kt.runtime.kt_hat_mode_contract.v1"},
                "claim_ceiling_preserved": {"const": True},
                "modes": {"type": "object"},
            },
        ),
        ARTIFACTS["kt_hat_compact_policy"]: _mode_policy("compact", 160, "direct"),
        ARTIFACTS["kt_hat_bench_policy"]: _mode_policy(
            "bench",
            96,
            "answer_only",
            {
                "numeric_answer_extraction_required": True,
                "benchmark_narrative_suppressed": True,
                "route_regret_logging_required": True,
            },
        ),
        ARTIFACTS["kt_hat_operator_policy"]: _mode_policy("operator", 320, "concise_steps", {"receipt_prompting_required": True}),
        ARTIFACTS["kt_hat_high_risk_policy"]: _mode_policy(
            "high_risk",
            420,
            "bounded_with_refusal_if_needed",
            {"tightened_claim_ceiling": True, "escalation_check_required": True},
        ),
        ARTIFACTS["kt_hat_math_policy"]: _mode_policy(
            "math",
            240,
            "short_derivation_plus_final_answer",
            {"numeric_answer_extraction_required": True, "final_answer_marker_required": True},
        ),
        ARTIFACTS["kt_hat_audit_policy"]: _mode_policy("audit", 512, "evidence_table", {"receipt_references_required": True}),
        ARTIFACTS["formal_math_base"]: """schema_id: kt.training.formal_math_repair.base.v1
authority: INTERNAL_SHADOW_REPAIR_CONFIG_ONLY
mode: formal_math_repair
target_lobes:
  - formal_proof_reasoning_lobe
  - learning_delta_lobe
  - audit_reasoning_lobe
forbidden_claims:
  external_audit_complete: false
  seven_b_amplification_proven: false
  router_superiority_claim_authorized: false
numeric_answer_extraction_required: true
no_regression_required: true
claim_ceiling_preserved: true
""",
        ARTIFACTS["formal_math_datasets"]: """schema_id: kt.training.formal_math_repair.datasets.v1
authority: INTERNAL_SHADOW_DATASET_PLAN_ONLY
datasets:
  - dataset_id: gsm8k
    split: test_or_validation
    sample_count: 50
    use: detached_benchmark_and_repair_diagnostics
  - dataset_id: math_final_answer_synthetic_smoke
    split: generated_from_observed_failures_only
    sample_count: bounded_by_failure_ledger
    use: answer_extraction_regression
leakage_scan_required: true
dataset_provenance_required: true
claim_ceiling_preserved: true
""",
        ARTIFACTS["formal_math_tranche_config"]: {
            "schema_id": "kt.training.formal_math_repair_tranche_config.v1",
            "artifact_id": "KT_FORMAL_MATH_REPAIR_TRANCHE_CONFIG",
            "authority": "INTERNAL_SHADOW_REPAIR_CONFIG_ONLY",
            "current_head": current_head,
            "target_lobe_ids": lobe_targets,
            "canonical_lobe_subset": True,
            "numeric_answer_extraction_required": True,
            "no_regression_required": True,
            "training_authorizes_claims": False,
            "claim_ceiling_preserved": True,
            **BLOCKED_CLAIMS,
        },
        ARTIFACTS["numeric_answer_schema"]: _json_schema(
            "kt.training.numeric_answer_extraction.schema.v1",
            ["sample_id", "raw_answer", "normalized_answer"],
            {
                "sample_id": {"type": "string"},
                "raw_answer": {"type": "string"},
                "normalized_answer": {"type": ["string", "null"]},
                "extraction_method": {"enum": ["boxed", "hash_answer", "final_answer_phrase", "last_number"]},
            },
        ),
        ARTIFACTS["route_regret_matrix_schema"]: _json_schema(
            "kt.router.route_regret_matrix.schema.v1",
            ["schema_id", "rows"],
            {
                "schema_id": {"const": "kt.router.route_regret_matrix.v1"},
                "rows": {"type": "array"},
                "mean_route_regret": {"type": "number"},
                "overroute_rate": {"type": "number"},
            },
        ),
        ARTIFACTS["route_regret_scorecard_schema"]: _json_schema(
            "kt.router.route_regret_scorecard.schema.v1",
            ["schema_id", "route_regret_pass", "router_optimizes_verified_work_not_label_fit"],
            {
                "schema_id": {"const": "kt.router.route_regret_scorecard.v1"},
                "route_regret_pass": {"type": "boolean"},
                "router_optimizes_verified_work_not_label_fit": {"const": True},
            },
        ),
        ARTIFACTS["scar_cluster_schema"]: _json_schema(
            "kt.adaptive.scar_cluster_receipt.schema.v1",
            ["schema_id", "scar_clusters", "source_failure_ledger"],
            {"schema_id": {"const": "kt.adaptive.scar_cluster_receipt.v1"}, "scar_clusters": {"type": "array"}},
        ),
        ARTIFACTS["delta_corpus_schema"]: _json_schema(
            "kt.adaptive.delta_corpus_manifest.schema.v1",
            ["schema_id", "delta_examples", "all_examples_map_to_failures"],
            {"schema_id": {"const": "kt.adaptive.delta_corpus_manifest.v1"}, "all_examples_map_to_failures": {"const": True}},
        ),
        ARTIFACTS["delta_distinct_hash_schema"]: _json_schema(
            "kt.adaptive.delta_adapter_distinct_hash_receipt.schema.v1",
            ["schema_id", "parent_adapter_hash", "delta_adapter_hash", "delta_adapter_hash_distinct"],
            {"schema_id": {"const": "kt.adaptive.delta_adapter_distinct_hash_receipt.v1"}, "delta_adapter_hash_distinct": {"const": True}},
        ),
        ARTIFACTS["benchmark_external_50"]: """schema_id: kt.benchmark.external_50.config.v1
authority: INTERNAL_DETACHED_BENCHMARK_PACKET_ONLY
sample_count_per_dataset: 50
datasets:
  - GSM8K
  - ARC-Challenge
  - HellaSwag
  - TruthfulQA-MC
kt_native_audit_slice: resource_safe_only
route_regret_required: true
verified_work_per_token_required: true
benchmark_leakage_scan_required: true
evaluator_integrity_receipt_required: true
claim_ceiling_preserved: true
""",
        ARTIFACTS["expanded_benchmark_config"]: {
            "schema_id": "kt.benchmark.expanded_detached_benchmark_config.v1",
            "artifact_id": "KT_EXPANDED_DETACHED_BENCHMARK_CONFIG",
            "authority": "INTERNAL_DETACHED_BENCHMARK_PACKET_ONLY",
            "current_head": current_head,
            "sample_count_per_dataset": 50,
            "datasets": ["GSM8K", "ARC-Challenge", "HellaSwag", "TruthfulQA-MC"],
            "kt_native_audit_slice": "resource_safe_only",
            "route_regret_required": True,
            "verified_work_per_token_required": True,
            "benchmark_leakage_scan_required": True,
            "evaluator_integrity_receipt_required": True,
            "claim_ceiling_preserved": True,
            **BLOCKED_CLAIMS,
        },
        ARTIFACTS["verified_work_schema"]: _json_schema(
            "kt.benchmark.verified_work_per_token_scorecard.schema.v1",
            ["schema_id", "verified_work", "token_count", "verified_work_per_token"],
            {"schema_id": {"const": "kt.benchmark.verified_work_per_token_scorecard.v1"}, "verified_work_per_token": {"type": "number"}},
        ),
        ARTIFACTS["benchmark_leakage_schema"]: _json_schema(
            "kt.benchmark.leakage_scan.schema.v1",
            ["schema_id", "leakage_scan_pass", "leakage_findings"],
            {"schema_id": {"const": "kt.benchmark.leakage_scan.v1"}, "leakage_scan_pass": {"type": "boolean"}},
        ),
        ARTIFACTS["evaluator_integrity_schema"]: _json_schema(
            "kt.benchmark.evaluator_integrity_receipt.schema.v1",
            ["schema_id", "evaluator_integrity_pass", "detached_verifier_mode"],
            {"schema_id": {"const": "kt.benchmark.evaluator_integrity_receipt.v1"}, "detached_verifier_mode": {"const": True}},
        ),
    }


def _repair_receipt(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.compact_hat_route_regret_scar_repair.receipt.v1",
        "artifact_id": "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "selected_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "kt_hat_modes_defined": ["compact", "bench", "operator", "high_risk", "math", "audit"],
        "formal_math_repair_configured": True,
        "numeric_answer_extraction_configured": True,
        "route_regret_contract_configured": True,
        "scar_delta_distinctness_law_configured": True,
        "verified_work_per_token_configured": True,
        "expanded_benchmark_packet_ready": True,
        "compute_packet_path": ARTIFACTS["packet_zip"],
        "claim_ceiling_preserved": True,
        "blockers": [],
        **BLOCKED_CLAIMS,
    }


def _inspection_receipt(current_head: str, compute_packet_sha256: str | None) -> dict[str, Any]:
    return {
        "schema_id": "kt.compact_hat_route_regret_scar_repair.inspection_receipt.v1",
        "artifact_id": "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_INSPECTION_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "packet_known_evidence_head": KNOWN_EVIDENCE_HEAD,
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "compute_packet_path": ARTIFACTS["packet_zip"],
        "compute_packet_sha256": compute_packet_sha256,
        "head_matches_packet_evidence_head": current_head == KNOWN_EVIDENCE_HEAD,
        "hf_final_adapter_store": HF_FINAL_ADAPTER_STORE,
        "repo_first": True,
        "kaggle_first": False,
        "claim_ceiling_preserved": True,
        "blockers": [],
        **BLOCKED_CLAIMS,
    }


def _packet_runner_text(current_head: str) -> str:
    return r'''from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PACKET_BUILD_HEAD = "__PACKET_BUILD_HEAD__"
KNOWN_EVIDENCE_HEAD = "__KNOWN_EVIDENCE_HEAD__"
REQUESTED_HEAD_ENV = os.environ.get("KT_REQUESTED_HEAD")
HF_FINAL_ADAPTER_STORE = os.environ.get("KT_HF_ADAPTER_STORE", "__HF_FINAL_ADAPTER_STORE__")
OUT_DIR = Path(os.environ.get("KT_OUT_DIR", "/kaggle/working/kt13_expand_repair_v1_outputs"))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(name: str, obj: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / name).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return os.environ.get("KT_ACTUAL_HEAD", "UNKNOWN")


def requested_head(actual_head: str, actual_head_known: bool) -> tuple[str, str]:
    if REQUESTED_HEAD_ENV:
        return REQUESTED_HEAD_ENV, "KT_REQUESTED_HEAD_ENV"
    if actual_head_known:
        return actual_head, "ACTUAL_GIT_HEAD_DEFAULT"
    return PACKET_BUILD_HEAD, "PACKET_BUILD_HEAD_FALLBACK"


def is_ancestor(ancestor: str, descendant: str) -> bool | None:
    if not ancestor or not descendant or descendant == "UNKNOWN":
        return None
    try:
        proc = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return None
    return proc.returncode == 0


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    actual_head = git_head()
    actual_head_known = actual_head not in {"", "UNKNOWN"}
    requested, requested_source = requested_head(actual_head, actual_head_known)
    head_match = actual_head_known and actual_head == requested
    packet_build_head_is_ancestor = is_ancestor(PACKET_BUILD_HEAD, actual_head)
    write_json(
        "head_binding_receipt.json",
        {
            "schema_id": "kt.kaggle.head_binding_receipt.v1",
            "generated_utc": utc_now(),
            "requested_head": requested,
            "requested_head_source": requested_source,
            "actual_head": actual_head,
            "actual_head_known": actual_head_known,
            "packet_build_head": PACKET_BUILD_HEAD,
            "known_evidence_head": KNOWN_EVIDENCE_HEAD,
            "packet_build_head_is_ancestor_of_actual": packet_build_head_is_ancestor,
            "head_match": head_match,
            "fail_closed_if_mismatch": True,
            "assessment_only_if_unknown": False,
        },
    )
    if not head_match:
        blocker_id = "HEAD_UNKNOWN" if not actual_head_known else "HEAD_MISMATCH"
        write_json(
            "blocker_ledger.json",
            {
                "schema_id": "kt.kaggle.blocker_ledger.v1",
                "blockers": [{"blocker_id": blocker_id, "requested_head": requested, "actual_head": actual_head}],
                "next_lawful_move": "REPLAY_PACKET_ON_CURRENT_HEAD_BEFORE_BENCHMARK",
            },
        )
        return 2

    write_json(
        "run_manifest.json",
        {
            "schema_id": "kt.kaggle.kt13_expand_repair.run_manifest.v1",
            "generated_utc": utc_now(),
            "run_mode": "RUN_EXPANDED_EXTERNAL_MARKET_BENCHMARK_AND_DETACHED_VERIFIER_PACKET",
            "hf_final_adapter_store": HF_FINAL_ADAPTER_STORE,
            "claim_ceiling_preserved": True,
            "commercial_claim_authorized": False,
            "external_audit_complete": False,
            "s_tier_claim_authorized": False,
            "seven_b_amplification_proven": False,
        },
    )
    write_json(
        "evaluator_integrity_receipt.json",
        {
            "schema_id": "kt.benchmark.evaluator_integrity_receipt.v1",
            "evaluator_integrity_status": "PENDING_EXECUTION",
            "evaluator_integrity_pass": False,
            "detached_verifier_mode": True,
            "claim_authority": "NONE_PENDING_ACTUAL_EVALUATION",
        },
    )
    write_json(
        "benchmark_leakage_scan.json",
        {
            "schema_id": "kt.benchmark.leakage_scan.v1",
            "leakage_scan_status": "PENDING_EXECUTION",
            "leakage_scan_pass": False,
            "leakage_findings": [],
            "claim_authority": "NONE_PENDING_ACTUAL_SCAN",
        },
    )
    write_json("route_regret_matrix.json", {"schema_id": "kt.router.route_regret_matrix.v1", "sample_count": 0, "rows": [], "note": "populate during benchmark execution"})
    write_json("verified_work_per_token_scorecard.json", {"schema_id": "kt.benchmark.verified_work_per_token_scorecard.v1", "verified_work": 0, "token_count": 0, "verified_work_per_token": 0})
    write_json(
        "assessment_summary.json",
        {
            "schema_id": "kt.kaggle.kt13_expand_repair.assessment_summary.v1",
            "outcome": "KT_13_EXPANDED_DETACHED_BENCHMARK_PACKET_STARTED__AWAITING_MODEL_EXECUTION_RESULTS",
            "next_lawful_move": "RUN_TARGETED_REPAIR_RETRAIN_FOR_MATH_HAT_ROUTE_REGRET_SCAR_DELTA_AFTER_RESULTS",
        },
    )
    print(f"KT expand/repair packet initialized at {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''.replace("__PACKET_BUILD_HEAD__", current_head).replace("__KNOWN_EVIDENCE_HEAD__", KNOWN_EVIDENCE_HEAD).replace("__HF_FINAL_ADAPTER_STORE__", HF_FINAL_ADAPTER_STORE)


def _packet_bootstrap_text() -> str:
    return f'''# KT13 expand/repair one-cell Kaggle bootstrap.
# Upload this zip as a Kaggle dataset or place it in /kaggle/input, then run this single cell.
import hashlib
import os
import zipfile
from pathlib import Path

os.environ.setdefault("KT_HF_ADAPTER_STORE", "{HF_FINAL_ADAPTER_STORE}")
os.environ.setdefault("KT_OUT_DIR", "/kaggle/working/kt13_expand_repair_v1_outputs")

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_extract(zf, target):
    root = target.resolve()
    for member in zf.infolist():
        dest = (root / member.filename).resolve()
        if root != dest and root not in dest.parents:
            raise RuntimeError(f"Unsafe zip member path: {{member.filename}}")
    zf.extractall(root)

explicit = os.environ.get("KT_PACKET_ZIP_PATH")
if explicit:
    candidates = [Path(explicit)]
else:
    preferred = Path("/kaggle/input/kt13-expand-repair-v1/{COMPUTE_PACKET_NAME}")
    if preferred.exists():
        candidates = [preferred]
    else:
        candidates = list(Path("/kaggle/input").glob("*/{COMPUTE_PACKET_NAME}")) + list(Path("/kaggle/working").glob("{COMPUTE_PACKET_NAME}"))

existing = [candidate for candidate in candidates if candidate.exists()]
if len(existing) > 1:
    raise RuntimeError(f"Multiple candidate packets found; set KT_PACKET_ZIP_PATH explicitly: {{[str(p) for p in existing]}}")
packet_zip = existing[0] if existing else None
if packet_zip is None:
    raise FileNotFoundError("Could not find {COMPUTE_PACKET_NAME} in /kaggle/input or /kaggle/working")

expected_sha = os.environ.get("KT_PACKET_SHA256")
if expected_sha and _sha256(packet_zip).lower() != expected_sha.lower():
    raise RuntimeError("KT packet sha256 mismatch; refusing to extract or execute")

work = Path("/kaggle/working/kt13_expand_repair_v1_packet")
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet_zip, "r") as zf:
    _safe_extract(zf, work)

runner = work / "KT13_EXPAND_REPAIR_V1_RUNNER.py"
if not runner.exists():
    matches = list(work.rglob("KT13_EXPAND_REPAIR_V1_RUNNER.py"))
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one runner, found {{len(matches)}}")
    runner = matches[0]

namespace = {{"__name__": "__kt_runner__"}}
exec(compile(runner.read_text(encoding="utf-8"), str(runner), "exec"), namespace)
exit_code = int(namespace["main"]())
if exit_code != 0:
    raise RuntimeError(f"KT runner failed with exit code {{exit_code}}")
'''


def _packet_manifest(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.packet.kt13_expand_repair_v1.manifest.v1",
        "packet_id": "kt13_expand_repair_v1",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "known_evidence_head": KNOWN_EVIDENCE_HEAD,
        "head_binding_required": True,
        "runtime_requested_head_default": "ACTUAL_GIT_HEAD",
        "packet_build_head_recorded": True,
        "hf_final_adapter_store": HF_FINAL_ADAPTER_STORE,
        "run_mode": NEXT_LAWFUL_MOVE,
        "one_cell_kaggle_compatible": True,
        "claim_ceiling_preserved": True,
        "contains": [
            "KT13_EXPAND_REPAIR_V1_RUNNER.py",
            "KAGGLE_BOOTSTRAP_CELL.py",
            "README_RUNBOOK.md",
            "PACKET_MANIFEST.json",
            "SHA256_MANIFEST.json",
        ],
        **BLOCKED_CLAIMS,
    }


def _packet_readme(current_head: str) -> str:
    return f"""# kt13_expand_repair_v1

Repo-side authority: `{PROGRAM_ID}`.

Current head bound by packet build: `{current_head}`.

Known evidence head from final adapter verification packet: `{KNOWN_EVIDENCE_HEAD}`.

Runtime requested-head default: actual checked-out git head. Set `KT_REQUESTED_HEAD` only when intentionally pinning a specific commit. The runner also records this packet build head and whether it is an ancestor of the actual run head.

HF adapter store: `{HF_FINAL_ADAPTER_STORE}`.

This packet is one-cell Kaggle compatible. It is for expanded detached benchmark and repair-signal collection only. It does not claim commercial launch, external audit completion, S-tier, beyond-SOTA, category leadership, frontier parity, 7B amplification, router superiority, multi-lobe superiority, or production readiness.

## Use

Upload `{COMPUTE_PACKET_NAME}` to Kaggle, paste `KAGGLE_BOOTSTRAP_CELL.py` into one cell, and run. The runner emits receipts into `/kaggle/working/kt13_expand_repair_v1_outputs`.

If `requested_head != actual_head`, the runner fails closed and emits `blocker_ledger.json`.
"""


def _write_packet(root: Path, current_head: str) -> list[str]:
    changed: list[str] = []
    packet_files: dict[str, str] = {
        ARTIFACTS["packet_runner"]: _packet_runner_text(current_head),
        ARTIFACTS["packet_bootstrap"]: _packet_bootstrap_text(),
        ARTIFACTS["packet_readme"]: _packet_readme(current_head),
    }
    for raw, text in packet_files.items():
        if _write_text_stable(root / raw, text):
            changed.append(raw)

    manifest = _packet_manifest(current_head)
    if write_json_stable(root / ARTIFACTS["packet_manifest"], manifest):
        changed.append(ARTIFACTS["packet_manifest"])

    hash_manifest = {
        "schema_id": "kt.packet.sha256_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "files": [],
    }
    for raw in [ARTIFACTS["packet_runner"], ARTIFACTS["packet_bootstrap"], ARTIFACTS["packet_readme"], ARTIFACTS["packet_manifest"]]:
        path = root / raw
        hash_manifest["files"].append({"path": Path(raw).name, "sha256": file_sha256(path)})
    if write_json_stable(root / ARTIFACTS["packet_hash_manifest"], hash_manifest):
        changed.append(ARTIFACTS["packet_hash_manifest"])

    zip_path = root / ARTIFACTS["packet_zip"]
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    before = zip_path.read_bytes() if zip_path.exists() else None
    packet_dir = root / ARTIFACTS["packet_dir"]
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(packet_dir.iterdir()):
            if path.is_file():
                zf.write(path, arcname=path.name)
    after = zip_path.read_bytes()
    if before != after:
        changed.append(ARTIFACTS["packet_zip"])
    return changed


def _registry_entry(root: Path, artifact_id: str, raw: str, role: str, *, controls_execution: bool) -> dict[str, Any]:
    path = root / raw
    return {
        "artifact_id": artifact_id,
        "path": raw,
        "role": role,
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "validation_status": "PASS",
        "controls_execution": controls_execution,
        "claim_authority": "INTERNAL_SHADOW",
        "sha256": file_sha256(path) if path.is_file() else None,
        "supersedes": [],
        "superseded_by": None,
        "notes": "Compact KT-hat, route-regret, scar/delta repair readiness artifact; no claim expansion or production authority.",
    }


def _update_registry(root: Path, current_head: str) -> dict[str, Any]:
    registry = load_json(root / ARTIFACTS["artifact_registry"])
    new_ids = {
        "KT_HAT_MODE_CONTRACT",
        "KT_FORMAL_MATH_REPAIR_TRANCHE_CONFIG",
        "KT_ROUTE_REGRET_MATRIX_SCHEMA",
        "KT_DELTA_ADAPTER_DISTINCT_HASH_SCHEMA",
        "KT_EXPANDED_DETACHED_BENCHMARK_CONFIG",
        "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_RECEIPT",
        "KT13_EXPAND_REPAIR_PACKET",
    }
    artifacts = [item for item in registry.get("artifacts", []) if item.get("artifact_id") not in new_ids]
    artifacts.extend(
        [
            _registry_entry(root, "KT_HAT_MODE_CONTRACT", ARTIFACTS["kt_hat_mode_contract"], "kt_hat_mode_contract", controls_execution=True),
            _registry_entry(root, "KT_FORMAL_MATH_REPAIR_TRANCHE_CONFIG", ARTIFACTS["formal_math_tranche_config"], "formal_math_repair_config", controls_execution=True),
            _registry_entry(root, "KT_ROUTE_REGRET_MATRIX_SCHEMA", ARTIFACTS["route_regret_matrix_schema"], "route_regret_contract", controls_execution=True),
            _registry_entry(root, "KT_DELTA_ADAPTER_DISTINCT_HASH_SCHEMA", ARTIFACTS["delta_distinct_hash_schema"], "scar_delta_distinctness_law", controls_execution=True),
            _registry_entry(root, "KT_EXPANDED_DETACHED_BENCHMARK_CONFIG", ARTIFACTS["expanded_benchmark_config"], "expanded_detached_benchmark_contract", controls_execution=True),
            _registry_entry(root, "KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_RECEIPT", ARTIFACTS["repair_readiness_receipt"], "repair_readiness_receipt", controls_execution=True),
            _registry_entry(root, "KT13_EXPAND_REPAIR_PACKET", ARTIFACTS["packet_zip"], "expanded_benchmark_compute_packet", controls_execution=False),
        ]
    )
    registry["current_head"] = current_head
    registry["generated_utc"] = utc_now_iso_z()
    registry["artifacts"] = artifacts
    return registry


def _artifact_delta(current_head: str) -> dict[str, Any]:
    added = [
        ARTIFACTS["kt_hat_mode_contract"],
        ARTIFACTS["kt_hat_mode_schema"],
        ARTIFACTS["kt_hat_compact_policy"],
        ARTIFACTS["kt_hat_bench_policy"],
        ARTIFACTS["kt_hat_operator_policy"],
        ARTIFACTS["kt_hat_high_risk_policy"],
        ARTIFACTS["kt_hat_math_policy"],
        ARTIFACTS["kt_hat_audit_policy"],
        ARTIFACTS["formal_math_base"],
        ARTIFACTS["formal_math_datasets"],
        ARTIFACTS["formal_math_tranche_config"],
        ARTIFACTS["numeric_answer_schema"],
        ARTIFACTS["route_regret_matrix_schema"],
        ARTIFACTS["route_regret_scorecard_schema"],
        ARTIFACTS["scar_cluster_schema"],
        ARTIFACTS["delta_corpus_schema"],
        ARTIFACTS["delta_distinct_hash_schema"],
        ARTIFACTS["benchmark_external_50"],
        ARTIFACTS["expanded_benchmark_config"],
        ARTIFACTS["verified_work_schema"],
        ARTIFACTS["benchmark_leakage_schema"],
        ARTIFACTS["evaluator_integrity_schema"],
        ARTIFACTS["repair_readiness_receipt"],
        ARTIFACTS["inspection_receipt"],
        ARTIFACTS["packet_manifest"],
        ARTIFACTS["packet_readme"],
        ARTIFACTS["packet_bootstrap"],
        ARTIFACTS["packet_runner"],
        ARTIFACTS["packet_hash_manifest"],
        ARTIFACTS["packet_zip"],
    ]
    return {
        "schema_id": "kt.artifact_authority_registry.compact_hat_route_regret_scar_repair_delta_receipt.v1",
        "artifact_id": "KT_ARTIFACT_AUTHORITY_REGISTRY_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_DELTA_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "artifacts_added": added,
        "artifacts_modified": [ARTIFACTS["artifact_registry"], ARTIFACTS["artifact_delta"]],
        "artifacts_superseded": [],
        "new_authority_added": "INTERNAL_SHADOW_PREP_ONLY_NO_CLAIM_EXPANSION",
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        **BLOCKED_CLAIMS,
    }


def _write_payload(root: Path, raw: str, payload: Any | str) -> bool:
    if isinstance(payload, str):
        return _write_text_stable(root / raw, payload)
    return write_json_stable(root / raw, payload)


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = output_root or repo_root()
    current_head = _git_head(root)
    changed: list[str] = []

    for raw, payload in _payloads(current_head).items():
        if _write_payload(root, raw, payload):
            changed.append(raw)

    repair_receipt = _repair_receipt(current_head)
    if write_json_stable(root / ARTIFACTS["repair_readiness_receipt"], repair_receipt):
        changed.append(ARTIFACTS["repair_readiness_receipt"])

    changed.extend(_write_packet(root, current_head))
    packet_sha = file_sha256(root / ARTIFACTS["packet_zip"]) if (root / ARTIFACTS["packet_zip"]).is_file() else None
    if write_json_stable(root / ARTIFACTS["inspection_receipt"], _inspection_receipt(current_head, packet_sha)):
        changed.append(ARTIFACTS["inspection_receipt"])

    registry = _update_registry(root, current_head)
    if write_json_stable(root / ARTIFACTS["artifact_registry"], registry):
        changed.append(ARTIFACTS["artifact_registry"])

    delta = _artifact_delta(current_head)
    if write_json_stable(root / ARTIFACTS["artifact_delta"], delta):
        changed.append(ARTIFACTS["artifact_delta"])

    return {
        "current_head": current_head,
        "branch": _git_branch(root),
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "changed_outputs": changed,
        "expanded_benchmark_packet_path": ARTIFACTS["packet_zip"],
        "claim_ceiling": "unchanged",
        "blockers": [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Author compact KT-hat, route-regret, scar/delta repair readiness packet.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(summary["outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
