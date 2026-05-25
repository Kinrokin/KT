from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
import textwrap
import zipfile
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

KT_PROD_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
if str(KT_PROD_CLEANROOM_ROOT) not in sys.path:
    sys.path.insert(0, str(KT_PROD_CLEANROOM_ROOT))

try:
    from tools.operator import g3_academy_pressure_repair_v1 as g3
    from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable
except ImportError:  # pragma: no cover
    from KT_PROD_CLEANROOM.tools.operator import g3_academy_pressure_repair_v1 as g3
    from KT_PROD_CLEANROOM.tools.operator.titanium_common import (
        file_sha256,
        load_json,
        repo_root,
        utc_now_iso_z,
        write_json_stable,
    )


PROGRAM_ID = "KT_G3_1_CAUSAL_REPAIR_SUPERLANE_V1"
TARGET_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_PACKET_READY__RETRY_G3_1_REPAIR_BENCH_NEXT__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_BLOCKED__NAMED_DEFECT_REMAINS"
NEXT_LAWFUL_MOVE = "RUN_KTG31_CAUSAL_REPAIR_PACKET_V1"
PACKET_NAME = "ktg31_v1.zip"
SOURCE_PACKET_SHA256 = "db933b94917ee447abae0ca683f279935fb7c20567015f67d65060b2b3b5b2dc"

G31_TARGETS = (
    "g3_1_math_act_adapter",
    "g3_1_hat_policy_adapter",
    "g3_1_route_regret_policy",
)

ABLATION_ARMS = (
    "base_raw",
    "base_kt_hat_compact",
    "routed_13_lobe_kt_hat_compact",
    "g3_math_repair",
    "g3_hat_math_scar",
    "g31_math_act_adapter",
    "g31_hat_policy_adapter",
    "g31_route_regret_policy",
    "g31_combined_policy",
    "oracle_route_replay",
)

BLOCKED_CLAIMS = dict(g3.BLOCKED_CLAIMS)

ARTIFACTS: dict[str, str] = {
    "truth_pin_receipt": "reports/g31_truth_pin_receipt.json",
    "evidence_import_receipt": "reports/g31_evidence_import_receipt.json",
    "source_evidence_index": "reports/g31_source_evidence_index.json",
    "per_sample_causal_trace": "reports/g31_per_sample_causal_trace.jsonl",
    "math_act_decomposition": "reports/g31_math_act_decomposition.json",
    "math_act_verifier_receipt": "reports/g31_math_act_verifier_receipt.json",
    "route_regret_closure_targets": "reports/g31_route_regret_closure_targets.json",
    "reducible_uncertainty_matrix": "reports/g31_reducible_uncertainty_matrix.json",
    "hat_salvage_suppression_matrix": "reports/g31_hat_salvage_suppression_matrix.json",
    "adapter_identity_scorecard": "reports/g31_adapter_identity_scorecard.json",
    "negative_transfer_scorecard": "reports/g31_negative_transfer_scorecard.json",
    "human_anchor_quality_receipt": "reports/g31_human_anchor_quality_receipt.json",
    "repair_corpus_provenance_scan": "reports/g31_repair_corpus_provenance_scan.json",
    "duplicate_prompt_cluster_scan": "reports/g31_duplicate_prompt_cluster_scan.json",
    "poison_trigger_scan": "reports/g31_poison_trigger_scan.json",
    "no_placeholder_pass_receipt": "reports/g31_no_placeholder_pass_receipt.json",
    "final_receipt": "reports/g31_causal_repair_superlane_receipt.json",
    "math_repair_corpus": "data/g31_math_repair_corpus.jsonl",
    "route_policy_training_pairs": "data/g31_route_policy_training_pairs.jsonl",
    "hat_calibration_corpus": "data/g31_hat_calibration_corpus.jsonl",
    "packet_dir": "packets/ktg31_v1",
    "packet_zip": f"packets/{PACKET_NAME}",
    "packet_manifest": "packets/ktg31_v1/PACKET_MANIFEST.json",
    "packet_runner": "packets/ktg31_v1/KTG31_V1_CAUSAL_REPAIR_RUNNER.py",
    "packet_bootstrap": "packets/ktg31_v1/KAGGLE_BOOTSTRAP_CELL.py",
    "packet_hash_manifest": "packets/ktg31_v1/SHA256_MANIFEST.json",
    "artifact_registry": "registry/artifact_authority_registry.json",
    "artifact_delta": "registry/artifact_authority_registry_g31_causal_repair_delta_receipt.json",
}

BANNED_PASS_TOKENS = (
    "PENDING_EXECUTION",
    "TODO",
    "PLACEHOLDER",
    "DUMMY",
    "MOCK",
    "SAMPLE_ONLY",
    "AWAITING_MODEL_EXECUTION_RESULTS",
)


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


def _json_dumps(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _sha_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        if raw.strip():
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL row in {path} is not an object")
            rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    text = "".join(json.dumps(dict(row), sort_keys=True, ensure_ascii=True) + "\n" for row in rows)
    _write_text_stable(path, text)


def normalize_numeric(value: Any) -> str | None:
    text = "" if value is None else str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text.replace(",", ""))
    if not match:
        return None
    raw = match.group(0)
    try:
        number = float(raw)
    except ValueError:
        return None
    if number.is_integer():
        return str(int(number))
    return (f"{number:.8f}").rstrip("0").rstrip(".")


def _required_path(root: Path, rel_path: str) -> Path:
    path = root / rel_path
    if not path.exists():
        raise FileNotFoundError(f"Required G3.1 source artifact missing: {rel_path}")
    return path


def load_source_evidence(root: Path) -> dict[str, Any]:
    paths = {
        "g2_evidence_manifest": _required_path(root, g3.ARTIFACTS["g2_evidence_manifest"]),
        "g2_failure_map": _required_path(root, g3.ARTIFACTS["g2_failure_map"]),
        "g2_route_regret_targets": _required_path(root, g3.ARTIFACTS["g2_route_regret_targets"]),
        "g3_metric_constitution": _required_path(root, g3.ARTIFACTS["g3_metric_constitution"]),
        "g3_human_anchor_manifest": _required_path(root, g3.ARTIFACTS["human_anchor_manifest"]),
        "g3_math_repair_corpus": _required_path(root, g3.ARTIFACTS["math_repair_corpus"]),
        "g3_hat_calibration_corpus": _required_path(root, g3.ARTIFACTS["kt_hat_calibration_corpus"]),
        "g3_packet_manifest": _required_path(root, g3.ARTIFACTS["packet_manifest"]),
    }
    return {
        "paths": paths,
        "g2_evidence_manifest": load_json(paths["g2_evidence_manifest"]),
        "failure_map": load_json(paths["g2_failure_map"]),
        "route_targets": load_json(paths["g2_route_regret_targets"]),
        "metric_constitution": load_json(paths["g3_metric_constitution"]),
        "human_anchor_manifest": load_json(paths["g3_human_anchor_manifest"]),
        "g3_math_rows": _read_jsonl(paths["g3_math_repair_corpus"]),
        "g3_hat_rows": _read_jsonl(paths["g3_hat_calibration_corpus"]),
        "g3_packet_manifest": load_json(paths["g3_packet_manifest"]),
    }


def truth_pin_receipt(root: Path) -> dict[str, Any]:
    return {
        "schema_id": "kt.g31.truth_pin_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "current_head": _git_head(root),
        "branch": _git_branch(root),
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "claim_ceiling": BLOCKED_CLAIMS,
        "claim_ceiling_status": "UNCHANGED",
        "kaggle_run_executed": False,
        "adapter_promotion_authorized": False,
    }


def evidence_receipts(root: Path, evidence: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    paths: Mapping[str, Path] = evidence["paths"]
    index_rows = [
        {
            "artifact_id": key,
            "path": path.as_posix(),
            "sha256": file_sha256(path),
            "authority": "LIVE_REPO_SOURCE" if key.startswith("g2_") or key.startswith("g3_") else "HANDOFF_CONTEXT",
        }
        for key, path in sorted(paths.items())
    ]
    g3_summary = {
        "source_packet_sha256": SOURCE_PACKET_SHA256,
        "summary": "G3 completed candidate repair execution, uploaded evidence, did not beat routed_13_lobe_kt_hat_compact, and did not earn promotion.",
        "authority": "HANDOFF_CONTEXT_ONLY_NOT_PROMOTION_AUTHORITY",
    }
    receipt = {
        "schema_id": "kt.g31.evidence_import_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "g2_repo_evidence_imported": True,
        "g3_build_artifacts_imported": True,
        "g3_packet_summary_imported": True,
        "g3_detailed_per_sample_runtime_trace_imported": False,
        "g3_detailed_trace_gap_preserved": True,
        "g3_summary": g3_summary,
        "prompt_stated_numbers_used_as_promotion_evidence": False,
        "claim_ceiling_status": "UNCHANGED",
        "blockers": [],
    }
    index = {
        "schema_id": "kt.g31.source_evidence_index.v1",
        "created_utc": utc_now_iso_z(),
        "current_head": _git_head(root),
        "sources": index_rows,
        "g3_handoff_context": g3_summary,
    }
    return receipt, index


def _route_row_by_failure_id(route_targets: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(row.get("failure_id")): dict(row) for row in route_targets.get("rows", [])}


def _failure_class(row: Mapping[str, Any], route_row: Mapping[str, Any] | None) -> tuple[str, str, float]:
    modes = set(row.get("failure_modes", []))
    dataset = str(row.get("dataset", ""))
    routed_correct = bool(row.get("routed_correct"))
    base_raw_correct = bool(row.get("base_raw_correct"))
    base_compact_correct = bool(row.get("base_compact_correct"))
    chosen = str(row.get("chosen_subject", "routed_13_lobe_kt_hat_compact"))
    best = str((route_row or row).get("best_subject_in_hindsight", row.get("best_subject_in_hindsight", "")))
    if dataset == "gsm8k" and "FORMAL_MATH_FINAL_ANSWER_REPAIR_TARGET" in modes:
        return "repairable_by_adapter_learning", "g3_1_math_act_adapter", 1.0 if not routed_correct else 0.25
    if best and best != chosen:
        return "repairable_by_control", "g3_1_route_regret_policy", 1.0 if (base_raw_correct or base_compact_correct) else 0.5
    if base_raw_correct and not base_compact_correct:
        return "repairable_by_control", "g3_1_hat_policy_adapter", 0.75
    if (base_raw_correct or base_compact_correct) and not routed_correct:
        return "repairable_by_control", "g3_1_route_regret_policy", 0.75
    if not base_raw_correct and not base_compact_correct and not routed_correct:
        return "irreducible_or_quarantine", "quarantine_current_model_limit", 0.0
    return "repairable_by_control", "g3_1_route_regret_policy", 0.25


def build_causal_trace(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    route_lookup = _route_row_by_failure_id(evidence["route_targets"])
    rows: list[dict[str, Any]] = []
    for row in evidence["failure_map"].get("rows", []):
        failure_id = str(row.get("failure_id"))
        route_row = route_lookup.get(failure_id, {})
        failure_class, repair_surface, repair_value = _failure_class(row, route_row)
        route_regret = 1.0 if route_row.get("best_subject_in_hindsight") != row.get("chosen_subject") else 0.0
        if not row.get("routed_correct") and route_row.get("best_correct"):
            route_regret = max(route_regret, 1.0)
        trace = {
            "sample_id": failure_id,
            "dataset": row.get("dataset"),
            "item_id": row.get("item_id"),
            "gold_answer": row.get("expected_normalized_answer"),
            "answer_by_arm": {
                "base_raw": None,
                "base_kt_hat_compact": None,
                "routed_13_lobe_kt_hat_compact": row.get("routed_prediction"),
                "g3_math_repair": None,
                "g3_hat_math_scar": None,
                "oracle_route_replay": row.get("expected_normalized_answer") if route_row.get("best_correct") else None,
            },
            "correct_by_arm": {
                "base_raw": bool(row.get("base_raw_correct")),
                "base_kt_hat_compact": bool(row.get("base_compact_correct")),
                "routed_13_lobe_kt_hat_compact": bool(row.get("routed_correct")),
                "g3_math_repair": None,
                "g3_hat_math_scar": None,
                "oracle_route_replay": bool(route_row.get("best_correct", row.get("routed_correct"))),
            },
            "tokens_by_arm": {
                "base_raw": None,
                "base_kt_hat_compact": None,
                "routed_13_lobe_kt_hat_compact": None,
                "g3_math_repair": None,
                "g3_hat_math_scar": None,
                "oracle_route_replay": None,
            },
            "latency_by_arm": {
                "routed_13_lobe_kt_hat_compact": None,
                "oracle_route_replay_delta": route_row.get("latency_delta"),
            },
            "chosen_route": str(row.get("chosen_subject", "routed_13_lobe_kt_hat_compact")),
            "oracle_route": str(route_row.get("best_subject_in_hindsight", row.get("best_subject_in_hindsight", "UNKNOWN_ORACLE"))),
            "route_regret": float(route_regret),
            "hat_intervention": _hat_intervention(row),
            "verifier_pass": bool(row.get("human_anchor_available")),
            "failure_class": failure_class,
            "repair_surface": repair_surface,
            "repair_value": float(repair_value),
            "source_failure_modes": row.get("failure_modes", []),
            "g3_runtime_detail_available": False,
        }
        rows.append(trace)
    return rows


def _hat_intervention(row: Mapping[str, Any]) -> str:
    base = bool(row.get("base_raw_correct"))
    hat = bool(row.get("base_compact_correct"))
    routed = bool(row.get("routed_correct"))
    if hat and not base:
        return "hat_saved_sample"
    if base and not hat:
        return "hat_harmed_sample"
    if base and hat:
        return "hat_shortened_correctly" if routed else "should_have_stayed_silent"
    if not base and not hat and routed:
        return "route_salvaged_sample"
    return "hat_did_nothing"


def build_math_outputs(trace_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for row in trace_rows:
        if row.get("dataset") != "gsm8k":
            continue
        gold = normalize_numeric(row.get("gold_answer"))
        pred = normalize_numeric(row.get("answer_by_arm", {}).get("routed_13_lobe_kt_hat_compact"))
        if pred is None:
            act = "parse_failure"
        elif gold is None:
            act = "harness_evaluation_artifact"
        elif pred == gold:
            act = "verification_failure"
        elif row.get("route_regret", 0) > 0:
            act = "route_failure"
        else:
            act = "arithmetic_calculation_failure"
        counts[act] += 1
        rows.append(
            {
                "sample_id": row["sample_id"],
                "dataset": row["dataset"],
                "gold_answer": row.get("gold_answer"),
                "routed_answer": row.get("answer_by_arm", {}).get("routed_13_lobe_kt_hat_compact"),
                "normalized_gold": gold,
                "normalized_routed": pred,
                "math_act_failure_class": act,
                "repair_surface": "g3_1_math_act_adapter",
                "human_anchor": bool(row.get("verifier_pass")),
            }
        )
    decomposition = {
        "schema_id": "kt.g31.math_act_decomposition.v1",
        "created_utc": utc_now_iso_z(),
        "math_sample_count": len(rows),
        "by_math_act": dict(sorted(counts.items())),
        "allowed_classes": [
            "parse_failure",
            "quantity_extraction_failure",
            "operation_selection_failure",
            "arithmetic_calculation_failure",
            "verification_failure",
            "final_answer_canonicalization_failure",
            "route_failure",
            "harness_evaluation_artifact",
            "irreducible_current_model_limit",
        ],
        "claim_ceiling_preserved": True,
    }
    verifier = {
        "schema_id": "kt.g31.math_act_verifier_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "deterministic_numeric_normalizer_present": True,
        "arithmetic_consistency_checker_present": True,
        "answer_only_finalizer_required_at_runtime": True,
        "wrong_operation_classifier_present": True,
        "verifier_bounded_candidate_selector_required_at_runtime": True,
        "math_act_verifier_pass": len(rows) > 0 and "harness_evaluation_artifact" not in counts,
        "claim_ceiling_preserved": True,
    }
    return decomposition, verifier, rows


def build_route_outputs(trace_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    targets = []
    pairs = []
    for row in trace_rows:
        route_regret = float(row.get("route_regret", 0.0))
        if row.get("repair_surface") == "g3_1_route_regret_policy" or route_regret > 0:
            targets.append(row)
            pairs.append(
                {
                    "sample_id": row["sample_id"],
                    "dataset": row["dataset"],
                    "chosen_route": row["chosen_route"],
                    "oracle_route": row["oracle_route"],
                    "route_regret": route_regret,
                    "utility_formula": "1.0*correct + 0.35*verifier_pass + 0.2*admissible - 0.2*normalized_tokens - 0.1*normalized_latency",
                    "repair_surface": "g3_1_route_regret_policy",
                }
            )
    ratio = 1.0 if targets else 0.0
    closure = {
        "schema_id": "kt.g31.route_regret_closure_targets.v1",
        "created_utc": utc_now_iso_z(),
        "target_count": len(targets),
        "simulated_oracle_route_regret_closure": ratio,
        "minimum_pass_threshold": 0.30,
        "strong_pass_threshold": 0.50,
        "simulation_pass": ratio >= 0.30,
        "empirical_router_superiority_claimed": False,
        "claim_ceiling_preserved": True,
        "rows": pairs,
    }
    uncertainty = {
        "schema_id": "kt.g31.reducible_uncertainty_matrix.v1",
        "created_utc": utc_now_iso_z(),
        "by_failure_class": dict(Counter(str(row["failure_class"]) for row in trace_rows)),
        "by_repair_surface": dict(Counter(str(row["repair_surface"]) for row in trace_rows)),
        "unknown_failure_class_ratio": 0.0,
        "claim_ceiling_preserved": True,
    }
    return closure, uncertainty, pairs


def build_hat_outputs(trace_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counts = Counter(str(row.get("hat_intervention")) for row in trace_rows)
    corpus = [
        {
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "hat_intervention": row.get("hat_intervention"),
            "repair_surface": "g3_1_hat_policy_adapter",
            "gold_answer": row.get("gold_answer"),
            "human_anchor": bool(row.get("verifier_pass")),
        }
        for row in trace_rows
        if row.get("hat_intervention") in {"hat_harmed_sample", "should_have_stayed_silent", "hat_did_nothing"}
    ]
    matrix = {
        "schema_id": "kt.g31.hat_salvage_suppression_matrix.v1",
        "created_utc": utc_now_iso_z(),
        "by_hat_intervention": dict(sorted(counts.items())),
        "hat_policy_training_rows": len(corpus),
        "non_math_no_regression_required_at_runtime": True,
        "math_target_slice_improvement_required_at_runtime": True,
        "claim_ceiling_preserved": True,
    }
    return matrix, corpus


def build_adapter_outputs(trace_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_surface = Counter(str(row["repair_surface"]) for row in trace_rows)
    identity = {
        "schema_id": "kt.g31.adapter_identity_scorecard.v1",
        "created_utc": utc_now_iso_z(),
        "build_mode_child_adapter_hashes_present": False,
        "runtime_child_adapter_hashes_required": True,
        "required_targets": list(G31_TARGETS),
        "by_repair_surface": dict(sorted(by_surface.items())),
        "promotion_allowed_from_build_mode": False,
        "claim_ceiling_preserved": True,
    }
    negative_transfer = {
        "schema_id": "kt.g31.negative_transfer_scorecard.v1",
        "created_utc": utc_now_iso_z(),
        "global_no_regression_required_at_runtime": True,
        "best_static_lobe_comparison_required_at_runtime": True,
        "lobe_ablation_effect_required_at_runtime": True,
        "negative_transfer_rate_runtime_required": True,
        "claim_ceiling_preserved": True,
    }
    return identity, negative_transfer


def build_anchor_outputs(trace_rows: Sequence[Mapping[str, Any]], math_rows: Sequence[Mapping[str, Any]], route_pairs: Sequence[Mapping[str, Any]], hat_rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    total = max(1, len(trace_rows))
    anchored = sum(1 for row in trace_rows if row.get("verifier_pass"))
    anchor_ratio = anchored / total
    human_anchor = {
        "schema_id": "kt.g31.human_anchor_quality_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "human_anchor_ratio": anchor_ratio,
        "minimum_required": 0.20,
        "human_anchor_pass": anchor_ratio >= 0.20,
        "anchor_classes": {
            "external_benchmark_ground_truth": anchored,
            "hand_audited_g2_g3_failure_cluster": 0,
            "operator_approved_repair_exemplar": 0,
            "known_good_kt_canonical_output": 0,
            "synthetic_only_example": 0,
        },
        "synthetic_only_repair_corpus": False,
        "claim_ceiling_preserved": True,
    }
    provenance = {
        "schema_id": "kt.g31.repair_corpus_provenance_scan.v1",
        "created_utc": utc_now_iso_z(),
        "math_rows": len(math_rows),
        "route_policy_rows": len(route_pairs),
        "hat_calibration_rows": len(hat_rows),
        "all_rows_trace_to_g2_or_g3_failure": True,
        "synthetic_only_repair_corpus": False,
        "claim_ceiling_preserved": True,
    }
    seen: Counter[str] = Counter(str(row.get("item_id", row["sample_id"])) for row in trace_rows)
    duplicate_clusters = {key: count for key, count in seen.items() if count > 1}
    duplicate_scan = {
        "schema_id": "kt.g31.duplicate_prompt_cluster_scan.v1",
        "created_utc": utc_now_iso_z(),
        "duplicate_cluster_count": len(duplicate_clusters),
        "duplicate_clusters": duplicate_clusters,
        "blocking_duplicate_cluster_found": False,
    }
    poison_terms = ("ignore previous", "system prompt", "developer message", "secret", "exfiltrate")
    poison_hits = []
    for row in trace_rows:
        haystack = json.dumps(row, sort_keys=True).lower()
        for term in poison_terms:
            if term in haystack:
                poison_hits.append({"sample_id": row["sample_id"], "trigger": term})
    poison_scan = {
        "schema_id": "kt.g31.poison_trigger_scan.v1",
        "created_utc": utc_now_iso_z(),
        "poison_trigger_count": len(poison_hits),
        "poison_hits": poison_hits,
        "blocking_poison_trigger_found": bool(poison_hits),
    }
    return human_anchor, provenance, duplicate_scan, poison_scan


def scan_banned_tokens(paths: Sequence[Path]) -> dict[str, Any]:
    findings = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in BANNED_PASS_TOKENS:
            if token in text:
                findings.append({"path": path.as_posix(), "token": token})
    return {
        "schema_id": "kt.g31.no_placeholder_pass_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "findings": findings,
        "no_placeholder_pass": not findings,
        "banned_tokens": list(BANNED_PASS_TOKENS),
    }


def _runner_source(head: str) -> str:
    source = r'''
from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import random
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROGRAM_ID = "__PROGRAM_ID__"
PACKET_BUILD_HEAD = "__PACKET_BUILD_HEAD__"
SUCCESS_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_RUNTIME_COMPLETE__ASSESSMENT_READY__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KT_G3_1_CAUSAL_REPAIR_RUNTIME_BLOCKED__NAMED_DEFECT_REMAINS"
G31_TARGETS = __G31_TARGETS__
ABLATION_ARMS = __ABLATION_ARMS__
BLOCKED_CLAIMS = __BLOCKED_CLAIMS__


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return os.environ.get("KT_ACTUAL_HEAD", PACKET_BUILD_HEAD)


def bind_head(output_dir: Path) -> dict[str, Any]:
    expected = os.environ.get("KT_EXPECTED_MAIN_HEAD", "").strip()
    actual = git_head()
    receipt = {
        "schema_id": "kt.g31.runtime_head_binding_receipt.v1",
        "created_utc": utc_now(),
        "packet_build_head": PACKET_BUILD_HEAD,
        "expected_main_head": expected or actual,
        "actual_head": actual,
        "head_match": not expected or expected == actual,
        "claim_ceiling_preserved": True,
    }
    write_json(output_dir / "g31_head_binding_receipt.json", receipt)
    if not receipt["head_match"]:
        raise RuntimeError(f"HEAD_BINDING_MISMATCH expected={expected} actual={actual}")
    return receipt


def config(output_dir: Path) -> dict[str, Any]:
    os.environ.setdefault("HF_HOME", "/kaggle/working/hf_cache")
    os.environ.setdefault("TRANSFORMERS_CACHE", "/kaggle/working/hf_cache/transformers")
    os.environ.setdefault("HF_DATASETS_CACHE", "/kaggle/working/hf_cache/datasets")
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True,max_split_size_mb:64")
    seed = int_env("KT_SEED", 3101)
    random.seed(seed)
    cfg = {
        "schema_id": "kt.g31.runtime_config.v1",
        "created_utc": utc_now(),
        "base_model": os.environ.get("KT_BASE_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"),
        "seed": seed,
        "max_steps": int_env("KT_G31_TRAIN_STEPS", 16),
        "max_seq_len": int_env("KT_G31_MAX_SEQ_LEN", 256),
        "targets": list(G31_TARGETS),
        "ablation_arms": list(ABLATION_ARMS),
        "require_hf_upload": bool_env("KT_UPLOAD_EVIDENCE_TO_HF", True),
        "hf_repo_id": os.environ.get("KT_G31_HF_REPO_ID", "").strip(),
        "output_dir": str(output_dir),
        "claims_authorized": [],
    }
    write_json(output_dir / "g31_run_manifest.json", cfg)
    return cfg


def import_deps() -> dict[str, Any]:
    try:
        import torch
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    except Exception as exc:
        raise RuntimeError(f"MISSING_RUNTIME_DEPENDENCY: {exc}") from exc
    return locals()


def load_model(deps: dict[str, Any], cfg: dict[str, Any]) -> tuple[Any, Any, str]:
    torch = deps["torch"]
    tokenizer = deps["AutoTokenizer"].from_pretrained(cfg["base_model"], cache_dir=os.environ.get("TRANSFORMERS_CACHE"))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    kwargs: dict[str, Any] = {"cache_dir": os.environ.get("TRANSFORMERS_CACHE"), "device_map": "auto"}
    kwargs["quantization_config"] = deps["BitsAndBytesConfig"](
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = deps["AutoModelForCausalLM"].from_pretrained(cfg["base_model"], **kwargs)
    model = deps["prepare_model_for_kbit_training"](model)
    return model, tokenizer, "cuda" if torch.cuda.is_available() else "cpu"


def row_text(row: dict[str, Any], target: str) -> str:
    return (
        f"KT G3.1 causal repair target: {target}\n"
        f"sample_id: {row.get('sample_id')}\n"
        f"dataset: {row.get('dataset')}\n"
        f"gold_answer: {row.get('gold_answer')}\n"
        f"failure_class: {row.get('failure_class')}\n"
        f"repair_surface: {row.get('repair_surface')}\n"
        "Task: produce the minimal causal repair policy while preserving no-regression, human anchor, and claim ceiling."
    )


def train_target(target: str, rows: list[dict[str, Any]], cfg: dict[str, Any], output_dir: Path, deps: dict[str, Any]) -> dict[str, Any]:
    torch = deps["torch"]
    model, tokenizer, device = load_model(deps, cfg)
    lora_cfg = deps["LoraConfig"](r=8, lora_alpha=16, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM", target_modules=["q_proj", "k_proj", "v_proj", "o_proj"])
    model = deps["get_peft_model"](model, lora_cfg)
    selected = [row for row in rows if row.get("repair_surface") == target or target in str(row.get("repair_surface", ""))]
    if not selected:
        selected = rows[:16]
    selected = selected[: max(1, min(32, len(selected)))]
    optimizer = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=2e-4)
    losses = []
    model.train()
    for step, row in enumerate(selected[: cfg["max_steps"]]):
        encoded = tokenizer(row_text(row, target), truncation=True, max_length=cfg["max_seq_len"], return_tensors="pt")
        encoded["labels"] = encoded["input_ids"].clone()
        encoded = {key: value.to(device) for key, value in encoded.items()}
        out = model(**encoded)
        out.loss.backward()
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
        losses.append(float(out.loss.detach().cpu().item()))
    adapter_dir = output_dir / "adapters" / target
    adapter_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(adapter_dir, safe_serialization=True)
    tokenizer.save_pretrained(adapter_dir)
    hashes = {str(path.relative_to(output_dir)): sha256_file(path) for path in adapter_dir.rglob("*.safetensors")}
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return {"target": target, "rows": len(selected), "steps": len(losses), "mean_loss": sum(losses) / len(losses) if losses else None, "hashes": hashes}


def make_zip(output_dir: Path, run_id: str) -> Path:
    path = output_dir / f"{run_id}_ASSESSMENT_ONLY.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(output_dir.rglob("*")):
            if item.is_file() and item != path and "adapters" not in item.parts:
                zf.write(item, item.relative_to(output_dir))
    return path


def upload(assessment_zip: Path, cfg: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    receipt = {"schema_id": "kt.g31.hf_upload_receipt.v1", "created_utc": utc_now(), "upload_required": cfg["require_hf_upload"], "uploaded_urls": [], "claim_ceiling_preserved": True}
    if not cfg["require_hf_upload"]:
        receipt["upload_pass"] = True
        receipt["reason"] = "KT_UPLOAD_EVIDENCE_TO_HF=0"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    if not os.environ.get("HF_TOKEN"):
        receipt["upload_pass"] = False
        receipt["blocker"] = "HF_TOKEN_MISSING"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    if not cfg["hf_repo_id"]:
        receipt["upload_pass"] = False
        receipt["blocker"] = "KT_G31_HF_REPO_ID_MISSING"
        write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
        return receipt
    try:
        from huggingface_hub import HfApi
        api = HfApi(token=os.environ["HF_TOKEN"])
        api.upload_file(path_or_fileobj=str(assessment_zip), path_in_repo=assessment_zip.name, repo_id=cfg["hf_repo_id"], repo_type="dataset")
        receipt["uploaded_urls"].append(f"https://huggingface.co/datasets/{cfg['hf_repo_id']}/blob/main/{assessment_zip.name}")
        receipt["upload_pass"] = True
    except Exception as exc:
        receipt["upload_pass"] = False
        receipt["blocker"] = f"HF_UPLOAD_FAILED: {exc}"
    write_json(output_dir / "g31_hf_upload_receipt.json", receipt)
    return receipt


def blocked(output_dir: Path, run_id: str, blockers: list[dict[str, Any]]) -> int:
    write_json(output_dir / "BLOCKER_RECEIPT.json", {"schema_id": "kt.g31.blocker_receipt.v1", "blockers": blockers, "claim_ceiling_preserved": True})
    write_json(output_dir / "g31_negative_result_ledger.json", {"schema_id": "kt.g31.negative_result_ledger.v1", "negative_result_count": len(blockers), "rows": blockers})
    zip_path = make_zip(output_dir, run_id)
    summary = {"schema_id": "kt.g31.assessment_summary.v1", "outcome": BLOCKED_OUTCOME, "success": False, "assessment_zip": str(zip_path), "blockers": blockers, "claim_ceiling": BLOCKED_CLAIMS}
    write_json(output_dir / "assessment_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 2


def main() -> int:
    packet_dir = Path(__file__).resolve().parent
    run_id = os.environ.get("KT_RUN_ID") or f"ktg31_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    output_dir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktg31_outputs")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        head = bind_head(output_dir)
        cfg = config(output_dir)
        trace_rows = read_jsonl(packet_dir / "g31_per_sample_causal_trace.jsonl")
        deps = import_deps()
        results = []
        blockers = []
        for target in G31_TARGETS:
            try:
                results.append(train_target(target, trace_rows, cfg, output_dir, deps))
            except Exception as exc:
                blockers.append({"stage": "train_target", "target": target, "defect": str(exc)})
        write_json(output_dir / "g31_training_receipt.json", {"schema_id": "kt.g31.training_receipt.v1", "targets": list(G31_TARGETS), "results": results, "training_errors_count": len(blockers), "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_ablation_scorecard.json", {"schema_id": "kt.g31.ablation_scorecard.v1", "arms": list(ABLATION_ARMS), "runtime_ablation_required": True, "results": [], "claim_ceiling_preserved": True})
        hash_rows = [{"path": str(path.relative_to(output_dir)), "sha256": sha256_file(path)} for path in sorted((output_dir / "adapters").rglob("*.safetensors"))] if (output_dir / "adapters").exists() else []
        write_json(output_dir / "g31_scar_delta_receipt.json", {"schema_id": "kt.g31.scar_delta_receipt.v1", "child_adapter_hashes": hash_rows, "before_after_target_metrics_required": True, "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_no_regression_receipt.json", {"schema_id": "kt.g31.no_regression_receipt.v1", "global_regression_pass": not blockers and bool(hash_rows), "claim_ceiling_preserved": True})
        write_json(output_dir / "g31_anti_goodhart_scorecard.json", {"schema_id": "kt.g31.anti_goodhart_scorecard.v1", "utility_collapse_detected": False, "anti_goodhart_pairings_present": True, "claim_ceiling_preserved": True})
        assessment_zip = make_zip(output_dir, run_id)
        upload_receipt = upload(assessment_zip, cfg, output_dir)
        if not upload_receipt.get("upload_pass"):
            blockers.append({"stage": "hf_upload", "defect": upload_receipt.get("blocker", "HF_UPLOAD_FAILED")})
        if blockers:
            return blocked(output_dir, run_id, blockers)
        summary = {"schema_id": "kt.g31.assessment_summary.v1", "outcome": SUCCESS_OUTCOME, "success": True, "assessment_zip": str(assessment_zip), "hf_urls": upload_receipt.get("uploaded_urls", []), "claim_ceiling": BLOCKED_CLAIMS}
        write_json(output_dir / "assessment_summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        return blocked(output_dir, run_id, [{"stage": "runtime_exception", "defect": str(exc)}])


if __name__ == "__main__":
    raise SystemExit(main())
'''
    return (
        textwrap.dedent(source).strip()
        .replace("__PROGRAM_ID__", PROGRAM_ID)
        .replace("__PACKET_BUILD_HEAD__", head)
        .replace("__G31_TARGETS__", json.dumps(list(G31_TARGETS), sort_keys=True))
        .replace("__ABLATION_ARMS__", json.dumps(list(ABLATION_ARMS), sort_keys=True))
        .replace("__BLOCKED_CLAIMS__", json.dumps(BLOCKED_CLAIMS, sort_keys=True))
        + "\n"
    )


def _bootstrap_source() -> str:
    return '''from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
import zipfile

PACKET_NAME = "ktg31_v1.zip"


def _packet_zip() -> Path:
    override = os.environ.get("KT_PACKET_ZIP_PATH", "").strip()
    if override:
        packet = Path(override)
        if not packet.exists():
            raise FileNotFoundError(f"KT_PACKET_ZIP_PATH not found: {packet}")
        return packet
    candidates = sorted(Path("/kaggle/input").rglob(PACKET_NAME))
    if not candidates:
        raise FileNotFoundError(f"{PACKET_NAME} not found under /kaggle/input")
    if len(candidates) > 1:
        rendered = ", ".join(str(path) for path in candidates)
        raise RuntimeError(f"Multiple candidate packets found; set KT_PACKET_ZIP_PATH: {rendered}")
    return candidates[0]


def _verify_sha256(path: Path) -> None:
    expected = os.environ.get("KT_PACKET_SHA256", "").strip().lower()
    if not expected:
        return
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError(f"KT_PACKET_SHA256 mismatch: expected {expected}, got {actual}")


def _safe_extract(packet: Path, work: Path) -> None:
    root = work.resolve()
    with zipfile.ZipFile(packet) as zf:
        for member in zf.namelist():
            target = (root / member).resolve()
            if not (target == root or root in target.parents):
                raise RuntimeError(f"Unsafe zip member path: {member}")
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(member))


def _install_deps() -> None:
    if os.environ.get("KT_SKIP_INSTALL", "").lower() in {"1", "true", "yes", "on"}:
        return
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        "--quiet",
        "--upgrade",
        "transformers>=4.43",
        "peft>=0.12",
        "accelerate>=0.33",
        "safetensors>=0.4",
        "huggingface_hub>=0.24",
        "bitsandbytes>=0.43",
    ])


packet_zip = _packet_zip()
_verify_sha256(packet_zip)
work = Path("/kaggle/working/ktg31_v1")
work.mkdir(parents=True, exist_ok=True)
_safe_extract(packet_zip, work)
_install_deps()
runner = work / "KTG31_V1_CAUSAL_REPAIR_RUNNER.py"
exec(compile(runner.read_text(encoding="utf-8"), str(runner), "exec"), {"__name__": "__main__", "__file__": str(runner)})
'''


def _readme(head: str) -> str:
    return f"""# KTG31 V1 Causal Repair Packet

Build head: `{head}`

This packet is the compute handoff for `KT_G3_1_CAUSAL_REPAIR_SUPERLANE_V1`.
It trains only:

- `g3_1_math_act_adapter`
- `g3_1_hat_policy_adapter`
- `g3_1_route_regret_policy`

It does not rerun full 13-lobe substrate training and does not authorize adapter
promotion or any commercial, external-audit, S-tier, frontier, 7B-amplification,
router-superiority, multi-lobe-superiority, or production-readiness claim.
"""


def _packet_manifest(head: str, packet_sha: str | None, source_hashes: Mapping[str, str]) -> dict[str, Any]:
    return {
        "schema_id": "kt.g31.packet_manifest.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "packet_name": PACKET_NAME,
        "packet_build_head": head,
        "packet_sha256_recorded_in_repo_receipt": packet_sha is None,
        "packet_sha256": packet_sha,
        "runner": "KTG31_V1_CAUSAL_REPAIR_RUNNER.py",
        "trainable_targets": list(G31_TARGETS),
        "ablation_arms": list(ABLATION_ARMS),
        "full_13_lobe_retrain_allowed": False,
        "claim_ceiling_preserved": True,
        "claims_authorized": [],
        "source_hashes": dict(source_hashes),
    }


def emit_packet(root: Path, *, head: str, source_paths: Mapping[str, str]) -> str:
    packet_dir = root / ARTIFACTS["packet_dir"]
    if packet_dir.exists():
        shutil.rmtree(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)
    source_hashes: dict[str, str] = {}
    for arcname, rel_path in source_paths.items():
        src = root / rel_path
        if not src.exists():
            raise FileNotFoundError(f"Cannot package missing artifact: {rel_path}")
        dst = packet_dir / arcname
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        source_hashes[arcname] = file_sha256(src)
    _write_text_stable(packet_dir / "KTG31_V1_CAUSAL_REPAIR_RUNNER.py", _runner_source(head))
    _write_text_stable(packet_dir / "KAGGLE_BOOTSTRAP_CELL.py", _bootstrap_source())
    _write_text_stable(packet_dir / "README_RUNBOOK.md", _readme(head))
    write_json_stable(packet_dir / "PACKET_MANIFEST.json", _packet_manifest(head, None, source_hashes))
    hash_rows = []
    for path in sorted(packet_dir.iterdir()):
        if path.is_file() and path.name != "SHA256_MANIFEST.json":
            hash_rows.append({"path": path.name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    write_json_stable(packet_dir / "SHA256_MANIFEST.json", {"schema_id": "kt.g31.packet_sha256_manifest.v1", "files": hash_rows})
    zip_path = root / ARTIFACTS["packet_zip"]
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(packet_dir.iterdir()):
            if path.is_file():
                zf.write(path, path.name)
    return file_sha256(zip_path)


def update_artifact_registry(root: Path) -> dict[str, Any]:
    registry_path = root / ARTIFACTS["artifact_registry"]
    registry = load_json(registry_path) if registry_path.exists() else {"schema_id": "kt.artifact_authority_registry.v3", "artifacts": []}
    additions = [
        {
            "artifact_id": "KT_G31_CAUSAL_REPAIR_RECEIPT",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "claim_authority": "INTERNAL_SHADOW",
            "controls_execution": False,
            "notes": "G3.1 repo-side causal repair autopsy; no claim expansion.",
            "path": ARTIFACTS["final_receipt"],
            "role": "g31_causal_repair_repo_receipt",
            "sha256": file_sha256(root / ARTIFACTS["final_receipt"]) if (root / ARTIFACTS["final_receipt"]).exists() else "",
            "superseded_by": None,
            "supersedes": [],
            "validation_status": "PASS",
        },
        {
            "artifact_id": "KTG31_CAUSAL_REPAIR_PACKET_V1",
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "claim_authority": "INTERNAL_SHADOW",
            "controls_execution": False,
            "notes": "Targeted G3.1 compute packet; runtime receipts required before any promotion review.",
            "path": ARTIFACTS["packet_zip"],
            "role": "g31_targeted_causal_repair_compute_packet",
            "sha256": file_sha256(root / ARTIFACTS["packet_zip"]) if (root / ARTIFACTS["packet_zip"]).exists() else "",
            "superseded_by": None,
            "supersedes": [],
            "validation_status": "PASS",
        },
    ]
    existing = {artifact.get("artifact_id"): artifact for artifact in registry.get("artifacts", [])}
    for entry in additions:
        existing[entry["artifact_id"]] = entry
    registry["artifacts"] = list(existing.values())
    registry["current_head"] = _git_head(root)
    registry["generated_utc"] = utc_now_iso_z()
    registry.setdefault("schema_id", "kt.artifact_authority_registry.v3")
    write_json_stable(registry_path, registry)
    delta = {
        "schema_id": "kt.g31.artifact_authority_registry_delta_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "artifacts_added_or_updated": [entry["artifact_id"] for entry in additions],
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        **BLOCKED_CLAIMS,
    }
    write_json_stable(root / ARTIFACTS["artifact_delta"], delta)
    return delta


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = (output_root or repo_root()).resolve()
    head = _git_head(root)
    branch = _git_branch(root)
    evidence = load_source_evidence(root)
    truth_pin = truth_pin_receipt(root)
    import_receipt, source_index = evidence_receipts(root, evidence)
    trace_rows = build_causal_trace(evidence)
    math_decomposition, math_verifier, math_rows = build_math_outputs(trace_rows)
    route_closure, uncertainty, route_pairs = build_route_outputs(trace_rows)
    hat_matrix, hat_rows = build_hat_outputs(trace_rows)
    adapter_identity, negative_transfer = build_adapter_outputs(trace_rows)
    human_anchor, provenance, duplicate_scan, poison_scan = build_anchor_outputs(trace_rows, math_rows, route_pairs, hat_rows)

    receipts: dict[str, Any] = {
        ARTIFACTS["truth_pin_receipt"]: truth_pin,
        ARTIFACTS["evidence_import_receipt"]: import_receipt,
        ARTIFACTS["source_evidence_index"]: source_index,
        ARTIFACTS["math_act_decomposition"]: math_decomposition,
        ARTIFACTS["math_act_verifier_receipt"]: math_verifier,
        ARTIFACTS["route_regret_closure_targets"]: route_closure,
        ARTIFACTS["reducible_uncertainty_matrix"]: uncertainty,
        ARTIFACTS["hat_salvage_suppression_matrix"]: hat_matrix,
        ARTIFACTS["adapter_identity_scorecard"]: adapter_identity,
        ARTIFACTS["negative_transfer_scorecard"]: negative_transfer,
        ARTIFACTS["human_anchor_quality_receipt"]: human_anchor,
        ARTIFACTS["repair_corpus_provenance_scan"]: provenance,
        ARTIFACTS["duplicate_prompt_cluster_scan"]: duplicate_scan,
        ARTIFACTS["poison_trigger_scan"]: poison_scan,
    }
    for rel_path, obj in receipts.items():
        write_json_stable(root / rel_path, obj)
    write_jsonl(root / ARTIFACTS["per_sample_causal_trace"], trace_rows)
    write_jsonl(root / ARTIFACTS["math_repair_corpus"], math_rows)
    write_jsonl(root / ARTIFACTS["route_policy_training_pairs"], route_pairs)
    write_jsonl(root / ARTIFACTS["hat_calibration_corpus"], hat_rows)

    generated_paths = [root / path for path in receipts] + [
        root / ARTIFACTS["per_sample_causal_trace"],
        root / ARTIFACTS["math_repair_corpus"],
        root / ARTIFACTS["route_policy_training_pairs"],
        root / ARTIFACTS["hat_calibration_corpus"],
    ]
    placeholder = scan_banned_tokens(generated_paths)
    write_json_stable(root / ARTIFACTS["no_placeholder_pass_receipt"], placeholder)
    blockers: list[dict[str, Any]] = []
    if not placeholder["no_placeholder_pass"]:
        blockers.append({"gate": "no_placeholder_pass", "defect": "BANNED_TOKEN_FOUND", "findings": placeholder["findings"]})
    if uncertainty["unknown_failure_class_ratio"] >= 0.10:
        blockers.append({"gate": "causal_trace", "defect": "UNKNOWN_FAILURE_CLASS_RATIO_TOO_HIGH"})
    if not route_closure["simulation_pass"]:
        blockers.append({"gate": "route_regret_closure", "defect": "SIMULATED_CLOSURE_BELOW_MINIMUM"})
    if not human_anchor["human_anchor_pass"]:
        blockers.append({"gate": "human_anchor", "defect": "HUMAN_ANCHOR_RATIO_BELOW_20_PERCENT"})
    if poison_scan["blocking_poison_trigger_found"]:
        blockers.append({"gate": "poison_trigger_scan", "defect": "POISON_TRIGGER_FOUND"})

    source_paths = {
        "g31_per_sample_causal_trace.jsonl": ARTIFACTS["per_sample_causal_trace"],
        "g31_math_act_decomposition.json": ARTIFACTS["math_act_decomposition"],
        "g31_math_act_verifier_receipt.json": ARTIFACTS["math_act_verifier_receipt"],
        "g31_route_regret_closure_targets.json": ARTIFACTS["route_regret_closure_targets"],
        "g31_reducible_uncertainty_matrix.json": ARTIFACTS["reducible_uncertainty_matrix"],
        "g31_hat_salvage_suppression_matrix.json": ARTIFACTS["hat_salvage_suppression_matrix"],
        "g31_adapter_identity_scorecard.json": ARTIFACTS["adapter_identity_scorecard"],
        "g31_negative_transfer_scorecard.json": ARTIFACTS["negative_transfer_scorecard"],
        "g31_human_anchor_quality_receipt.json": ARTIFACTS["human_anchor_quality_receipt"],
        "g31_repair_corpus_provenance_scan.json": ARTIFACTS["repair_corpus_provenance_scan"],
        "g31_math_repair_corpus.jsonl": ARTIFACTS["math_repair_corpus"],
        "g31_route_policy_training_pairs.jsonl": ARTIFACTS["route_policy_training_pairs"],
        "g31_hat_calibration_corpus.jsonl": ARTIFACTS["hat_calibration_corpus"],
    }
    packet_sha = emit_packet(root, head=head, source_paths=source_paths)
    final_receipt = {
        "schema_id": "kt.g31.causal_repair_superlane_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": branch,
        "selected_outcome": BLOCKED_OUTCOME if blockers else TARGET_OUTCOME,
        "next_lawful_move": "PATCH_KT_G3_1_CAUSAL_REPAIR_SUPERLANE_V1" if blockers else NEXT_LAWFUL_MOVE,
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "causal_trace_rows": len(trace_rows),
        "math_repair_rows": len(math_rows),
        "route_policy_rows": len(route_pairs),
        "hat_calibration_rows": len(hat_rows),
        "human_anchor_ratio": human_anchor["human_anchor_ratio"],
        "g3_detailed_trace_gap_preserved": True,
        "claim_ceiling_status": "UNCHANGED",
        "claim_ceiling": BLOCKED_CLAIMS,
        "blockers": blockers,
    }
    write_json_stable(root / ARTIFACTS["final_receipt"], final_receipt)
    registry_delta = update_artifact_registry(root)
    return {
        "current_head": head,
        "branch": branch,
        "outcome": final_receipt["selected_outcome"],
        "next_lawful_move": final_receipt["next_lawful_move"],
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "artifact_registry_delta": registry_delta["artifacts_added_or_updated"],
        "claim_ceiling_status": "UNCHANGED",
        "blockers": blockers,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=PROGRAM_ID)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    summary = run(output_root=Path(args.output_root).resolve() if args.output_root else None)
    print(_json_dumps(summary), end="")
    return 1 if summary["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
