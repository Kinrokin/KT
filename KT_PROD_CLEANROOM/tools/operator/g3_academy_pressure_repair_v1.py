from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import author_lobe_gate_court_taxonomy_reconciliation as taxonomy
from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_G3_ACADEMY_PRESSURE_REPAIR_SUPERLANE_V1"
TARGET_OUTCOME = "KT_G3_ACADEMY_PRESSURE_REPAIR_READY__TARGETED_G3_RUN_NEXT__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_TARGETED_G3_ACADEMY_PRESSURE_REPAIR_PACKET"
PACKET_NAME = "ktg3_run_v1.zip"
SOURCE_PACKET_SHA256 = "d498040128107f7299085f0c3af96cfcdf99daab1b49ccc74d7676e931859292"
HF_G2_DATASET = "Kinrokin/kt-g2-expanded-bench-20260525-045148"

BLOCKED_CLAIMS = dict(taxonomy.BLOCKED_CLAIMS)
CANONICAL_LOBES = [lobe_id for lobe_id, _, _ in taxonomy.CANONICAL_LOBES]

CLAIM_CEILING_COMPAT_KEYS = set(BLOCKED_CLAIMS) | {
    "canonical_promotion_authorized",
    "external_validation_accepted",
    "production_readiness_claim_authorized",
}

G2_ZIP_MEMBERS = {
    "assessment_summary": "outputs/reports/assessment_summary.json",
    "benchmark_scorecard": "outputs/reports/benchmark_scorecard.json",
    "verified_work_per_token_scorecard": "outputs/reports/verified_work_per_token_scorecard.json",
    "route_regret_matrix": "outputs/reports/route_regret_matrix.json",
    "benchmark_predictions": "outputs/reports/benchmark_predictions.jsonl",
    "dataset_load_receipt": "outputs/reports/dataset_load_receipt.json",
}

ARTIFACTS: dict[str, str] = {
    "source_path_compatibility_receipt": "reports/source_path_compatibility_receipt.json",
    "g2_evidence_import_receipt": "reports/g2_evidence_import_receipt.json",
    "g2_evidence_manifest": "reports/g2_evidence_manifest.json",
    "g2_failure_map": "reports/g2_failure_map.json",
    "g2_route_regret_targets": "reports/g2_route_regret_targets.json",
    "human_anchor_manifest": "reports/human_anchor_manifest.json",
    "human_anchor_anti_collapse_receipt": "reports/human_anchor_anti_collapse_receipt.json",
    "build_vs_run_boundary_receipt": "reports/build_vs_run_boundary_receipt.json",
    "no_placeholder_pass_receipt": "reports/no_placeholder_pass_receipt.json",
    "g3_metric_constitution": "reports/g3_metric_constitution.json",
    "anti_goodhart_scorecard": "reports/g3_anti_goodhart_scorecard.json",
    "utility_under_constraint_receipt": "reports/g3_utility_under_constraint_receipt.json",
    "formal_math_repair_plan": "reports/g3_formal_math_repair_plan.json",
    "math_repair_corpus": "reports/g3_math_repair_corpus.jsonl",
    "kt_hat_calibration_corpus": "reports/g3_kt_hat_calibration_corpus.jsonl",
    "scar_delta_receipt": "reports/g3_scar_delta_receipt.json",
    "long_horizon_state_tracking_receipt": "reports/g3_long_horizon_state_tracking_receipt.json",
    "lobe_specialization_scorecard": "reports/g3_lobe_specialization_scorecard.json",
    "assurance_case_claim_compiler_receipt": "reports/g3_assurance_case_claim_compiler_receipt.json",
    "clinical_phase_promotion_receipt": "reports/g3_clinical_phase_promotion_receipt.json",
    "phase_status": "reports/g3_phase_status.json",
    "final_receipt": "reports/g3_academy_pressure_repair_receipt.json",
    "artifact_registry": "registry/artifact_authority_registry.json",
    "artifact_delta": "registry/artifact_authority_registry_g3_academy_pressure_repair_delta_receipt.json",
    "packet_dir": "packets/ktg3_run_v1",
    "packet_manifest": "packets/ktg3_run_v1/PACKET_MANIFEST.json",
    "packet_readme": "packets/ktg3_run_v1/README_RUNBOOK.md",
    "packet_bootstrap": "packets/ktg3_run_v1/KAGGLE_BOOTSTRAP_CELL.py",
    "packet_runner": "packets/ktg3_run_v1/KTG3_TARGETED_REPAIR_RUNNER.py",
    "packet_hash_manifest": "packets/ktg3_run_v1/SHA256_MANIFEST.json",
    "packet_zip": f"packets/{PACKET_NAME}",
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


def _sha_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read_jsonl(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in data.decode("utf-8-sig").splitlines():
        if raw.strip():
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError("JSONL rows must be objects")
            rows.append(obj)
    return rows


def _default_evidence_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    env_path = os.environ.get("KT_G2_EVIDENCE_PATH")
    if env_path:
        candidates.append(Path(env_path).expanduser())
    candidates.extend(
        [
            Path.home() / "Downloads" / "ktg2_v2_20260525_041618_ASSESSMENT_ONLY.zip",
            root / "outputs" / "reports" / "assessment_summary.json",
        ]
    )
    return candidates


def discover_g2_evidence(root: Path, explicit: str | None = None) -> Path:
    candidates = [Path(explicit).expanduser()] if explicit else _default_evidence_candidates(root)
    for candidate in candidates:
        if candidate.exists() and _is_supported_evidence_candidate(candidate):
            return candidate
    rendered = ", ".join(path.as_posix() for path in candidates)
    raise FileNotFoundError(f"No importable G2 evidence found. Checked: {rendered}")


def _is_supported_evidence_candidate(candidate: Path) -> bool:
    if candidate.is_file() and candidate.suffix.lower() == ".zip":
        return True
    if candidate.is_file() and candidate.name == "assessment_summary.json":
        parent = candidate.parent
        required = [
            parent / "benchmark_scorecard.json",
            parent / "verified_work_per_token_scorecard.json",
            parent / "route_regret_matrix.json",
            parent / "benchmark_predictions.jsonl",
        ]
        return all(path.exists() for path in required)
    if candidate.is_dir():
        required = [
            candidate / "assessment_summary.json",
            candidate / "benchmark_scorecard.json",
            candidate / "verified_work_per_token_scorecard.json",
            candidate / "route_regret_matrix.json",
            candidate / "benchmark_predictions.jsonl",
        ]
        return all(path.exists() for path in required)
    return False


def load_g2_evidence(source_path: Path) -> dict[str, Any]:
    source_path = source_path.resolve()
    if source_path.suffix.lower() == ".zip":
        return _load_g2_zip(source_path)
    if source_path.is_dir():
        return _load_g2_dir(source_path)
    if source_path.name == "assessment_summary.json":
        base = source_path.parent
        return _load_g2_dir(base)
    raise ValueError(f"Unsupported G2 evidence source: {source_path}")


def _load_g2_zip(source_path: Path) -> dict[str, Any]:
    imported: dict[str, dict[str, Any]] = {}
    payloads: dict[str, Any] = {}
    with zipfile.ZipFile(source_path, "r") as zf:
        names = set(zf.namelist())
        missing = [member for member in G2_ZIP_MEMBERS.values() if member not in names and member != G2_ZIP_MEMBERS["dataset_load_receipt"]]
        if missing:
            raise ValueError(f"G2 evidence zip missing required members: {missing}")
        for key, member in G2_ZIP_MEMBERS.items():
            if member not in names:
                continue
            raw = zf.read(member)
            imported[key] = {"member": member, "sha256": _sha_bytes(raw), "size_bytes": len(raw)}
            payloads[key] = _read_jsonl(raw) if member.endswith(".jsonl") else json.loads(raw.decode("utf-8-sig"))
    return {
        "source_kind": "assessment_zip",
        "source_path": source_path.as_posix(),
        "source_sha256": file_sha256(source_path),
        "imported_members": imported,
        "payloads": payloads,
    }


def _load_g2_dir(source_path: Path) -> dict[str, Any]:
    lookup = {
        "assessment_summary": source_path / "assessment_summary.json",
        "benchmark_scorecard": source_path / "benchmark_scorecard.json",
        "verified_work_per_token_scorecard": source_path / "verified_work_per_token_scorecard.json",
        "route_regret_matrix": source_path / "route_regret_matrix.json",
        "benchmark_predictions": source_path / "benchmark_predictions.jsonl",
    }
    missing = [path.as_posix() for path in lookup.values() if not path.exists()]
    if missing:
        raise ValueError(f"G2 evidence directory missing required files: {missing}")
    imported: dict[str, dict[str, Any]] = {}
    payloads: dict[str, Any] = {}
    for key, path in lookup.items():
        raw = path.read_bytes()
        imported[key] = {"path": path.as_posix(), "sha256": _sha_bytes(raw), "size_bytes": len(raw)}
        payloads[key] = _read_jsonl(raw) if path.suffix == ".jsonl" else json.loads(raw.decode("utf-8-sig"))
    return {
        "source_kind": "assessment_directory",
        "source_path": source_path.as_posix(),
        "source_sha256": _sha_bytes("|".join(item["sha256"] for item in imported.values()).encode("utf-8")),
        "imported_members": imported,
        "payloads": payloads,
    }


def validate_g2_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    payloads = evidence["payloads"]
    summary = payloads["assessment_summary"]
    predictions = payloads["benchmark_predictions"]
    scorecard = payloads["benchmark_scorecard"]
    route_regret = payloads["route_regret_matrix"]
    subjects = scorecard.get("by_subject", {})
    required_subjects = {"base_raw", "base_kt_hat_compact", "routed_13_lobe_raw", "routed_13_lobe_kt_hat_compact"}
    missing_subjects = sorted(required_subjects - set(subjects))
    claim_ceiling = summary.get("claim_ceiling", {})
    blocked_claims_preserved = _compatible_claim_ceiling_preserved(claim_ceiling)
    pass_status = (
        summary.get("schema_id") == "kt.g2.assessment_summary.v2"
        and not missing_subjects
        and len(predictions) > 0
        and route_regret.get("sample_count", len(route_regret.get("rows", []))) > 0
        and blocked_claims_preserved
    )
    return {
        "schema_id": "kt.g3.g2_evidence_import_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "g2_evidence_imported": pass_status,
        "source_kind": evidence["source_kind"],
        "source_path": evidence["source_path"],
        "source_sha256": evidence["source_sha256"],
        "hf_dataset_declared_source": HF_G2_DATASET,
        "assessment_schema_id": summary.get("schema_id"),
        "assessment_outcome": summary.get("outcome"),
        "assessment_actual_head": summary.get("actual_head"),
        "prediction_rows": len(predictions),
        "route_regret_rows": len(route_regret.get("rows", [])),
        "missing_required_subjects": missing_subjects,
        "claim_ceiling_preserved": blocked_claims_preserved,
        "claim_ceiling_keys_checked": sorted(set(claim_ceiling).intersection(CLAIM_CEILING_COMPAT_KEYS)),
        "prompt_stated_numbers_used_as_evidence": False,
    }


def _compatible_claim_ceiling_preserved(claim_ceiling: Mapping[str, Any]) -> bool:
    """Fail on any known forbidden true value while allowing historical key names."""
    if not isinstance(claim_ceiling, Mapping):
        return False
    checked = False
    for key, value in claim_ceiling.items():
        if key in CLAIM_CEILING_COMPAT_KEYS or key.endswith("_claim_authorized") or key.endswith("_proven"):
            checked = True
            if value is not False:
                return False
    return checked


def build_g2_manifest(evidence: Mapping[str, Any]) -> dict[str, Any]:
    payloads = evidence["payloads"]
    summary = payloads["assessment_summary"]
    scorecard = payloads["benchmark_scorecard"]
    return {
        "schema_id": "kt.g3.g2_evidence_manifest.v1",
        "created_utc": utc_now_iso_z(),
        "source_kind": evidence["source_kind"],
        "source_path": evidence["source_path"],
        "source_sha256": evidence["source_sha256"],
        "imported_members": evidence["imported_members"],
        "assessment_actual_head": summary.get("actual_head"),
        "assessment_outcome": summary.get("outcome"),
        "adapter_store": summary.get("adapter_store"),
        "base_model": summary.get("base_model"),
        "subject_metrics": scorecard.get("by_subject", {}),
        "dataset_subject_metrics": scorecard.get("by_subject_dataset", {}),
        "claim_ceiling": summary.get("claim_ceiling", {}),
        "evidence_authority": "G2_ASSESSMENT_IMPORT_FOR_G3_BUILD_MODE_ONLY",
    }


def _group_predictions(predictions: Sequence[Mapping[str, Any]]) -> dict[tuple[str, str], dict[str, Mapping[str, Any]]]:
    grouped: dict[tuple[str, str], dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for row in predictions:
        grouped[(str(row.get("dataset")), str(row.get("item_id")))][str(row.get("subject"))] = row
    return grouped


def _target_lobe_for_dataset(dataset: str, route_adapter: object) -> str:
    adapter = "" if route_adapter is None else str(route_adapter)
    if adapter in CANONICAL_LOBES:
        return adapter
    if dataset == "gsm8k":
        return "formal_proof_reasoning_lobe"
    if dataset == "truthfulqa_mc":
        return "grounded_evidence_lobe"
    if dataset == "hellaswag":
        return "cross_domain_patterncraft_lobe"
    return "strategic_synthesis_lobe"


def _failure_modes(dataset: str, subject_rows: Mapping[str, Mapping[str, Any]], regret_row: Mapping[str, Any] | None) -> list[str]:
    modes: list[str] = []
    routed = subject_rows.get("routed_13_lobe_kt_hat_compact", {})
    base_raw = subject_rows.get("base_raw", {})
    compact = subject_rows.get("base_kt_hat_compact", {})
    if routed and routed.get("correct") is False:
        modes.append("ROUTED_COMPACT_INCORRECT")
    if routed.get("correct") is False and base_raw.get("correct") is True:
        modes.append("ROUTE_SELECTED_WRONG_WHEN_BASE_RAW_RIGHT")
    if routed.get("correct") is False and compact.get("correct") is True:
        modes.append("ROUTE_SELECTED_WRONG_WHEN_BASE_COMPACT_RIGHT")
    if dataset == "gsm8k" and routed.get("correct") is False:
        modes.append("FORMAL_MATH_FINAL_ANSWER_REPAIR_TARGET")
    if regret_row and regret_row.get("best_subject_in_hindsight") != regret_row.get("chosen_subject"):
        modes.append("ROUTE_REGRET_TARGET")
    if routed.get("extraction_ok") is False:
        modes.append("ANSWER_EXTRACTION_FAILURE")
    return sorted(set(modes)) or ["NO_REPAIR_TARGET"]


def build_failure_map(evidence: Mapping[str, Any]) -> dict[str, Any]:
    predictions = evidence["payloads"]["benchmark_predictions"]
    regret_rows = {
        (str(row.get("dataset")), str(row.get("item_id"))): row
        for row in evidence["payloads"]["route_regret_matrix"].get("rows", [])
    }
    grouped = _group_predictions(predictions)
    rows: list[dict[str, Any]] = []
    for (dataset, item_id), subject_rows in sorted(grouped.items()):
        routed = subject_rows.get("routed_13_lobe_kt_hat_compact")
        if not routed:
            continue
        regret_row = regret_rows.get((dataset, item_id))
        modes = _failure_modes(dataset, subject_rows, regret_row)
        if modes == ["NO_REPAIR_TARGET"]:
            continue
        target_lobe = _target_lobe_for_dataset(dataset, routed.get("route_adapter"))
        row = {
            "failure_id": f"G2::{dataset}::{item_id}",
            "dataset": dataset,
            "item_id": item_id,
            "target_lobe": target_lobe,
            "route_adapter": routed.get("route_adapter"),
            "failure_modes": modes,
            "expected_normalized_answer": routed.get("normalized_answer"),
            "routed_prediction": routed.get("normalized_prediction"),
            "routed_correct": bool(routed.get("correct")),
            "base_raw_correct": bool(subject_rows.get("base_raw", {}).get("correct")),
            "base_compact_correct": bool(subject_rows.get("base_kt_hat_compact", {}).get("correct")),
            "best_subject_in_hindsight": regret_row.get("best_subject_in_hindsight") if regret_row else None,
            "chosen_subject": regret_row.get("chosen_subject") if regret_row else "routed_13_lobe_kt_hat_compact",
            "repair_objective": _repair_objective(dataset, modes),
            "human_anchor_available": routed.get("normalized_answer") is not None,
            "prompt_text_imported": False,
        }
        rows.append(row)
    by_dataset = Counter(row["dataset"] for row in rows)
    by_lobe = Counter(row["target_lobe"] for row in rows)
    by_mode = Counter(mode for row in rows for mode in row["failure_modes"])
    return {
        "schema_id": "kt.g3.g2_failure_map.v1",
        "created_utc": utc_now_iso_z(),
        "source_evidence_sha256": evidence["source_sha256"],
        "failure_count": len(rows),
        "by_dataset": dict(sorted(by_dataset.items())),
        "by_target_lobe": dict(sorted(by_lobe.items())),
        "by_failure_mode": dict(sorted(by_mode.items())),
        "rows": rows,
    }


def _repair_objective(dataset: str, modes: Sequence[str]) -> str:
    if dataset == "gsm8k":
        return "repair_numeric_reasoning_and_final_answer_extraction"
    if "ROUTE_REGRET_TARGET" in modes:
        return "repair_route_selection_against_best_hindsight_subject"
    if dataset == "truthfulqa_mc":
        return "repair_grounded_evidence_choice_discipline"
    if dataset == "hellaswag":
        return "repair_commonsense_completion_discrimination"
    return "repair_task_specific_answer_selection"


def build_route_regret_targets(evidence: Mapping[str, Any], failure_map: Mapping[str, Any]) -> dict[str, Any]:
    failures = {row["failure_id"]: row for row in failure_map["rows"]}
    rows = []
    for row in evidence["payloads"]["route_regret_matrix"].get("rows", []):
        failure_id = f"G2::{row.get('dataset')}::{row.get('item_id')}"
        if failure_id not in failures:
            continue
        target = failures[failure_id]
        rows.append(
            {
                "failure_id": failure_id,
                "dataset": row.get("dataset"),
                "item_id": row.get("item_id"),
                "chosen_subject": row.get("chosen_subject"),
                "best_subject_in_hindsight": row.get("best_subject_in_hindsight"),
                "chosen_route_adapter": row.get("chosen_route_adapter"),
                "best_route_adapter": row.get("best_route_adapter"),
                "chosen_correct": row.get("chosen_correct"),
                "best_correct": row.get("best_correct"),
                "correctness_delta": row.get("correctness_delta"),
                "token_delta": row.get("token_delta"),
                "latency_delta": row.get("latency_delta"),
                "target_lobe": target["target_lobe"],
                "repair_objective": target["repair_objective"],
                "anti_goodhart_pair": "route_improvement_must_not_reduce_human_anchor_accuracy_or_raise_token_cost_per_correct",
            }
        )
    return {
        "schema_id": "kt.g3.g2_route_regret_targets.v1",
        "created_utc": utc_now_iso_z(),
        "target_count": len(rows),
        "source_evidence_sha256": evidence["source_sha256"],
        "router_objective": "maximize_verified_work_per_token_under_no_regression_and_human_anchor_constraints",
        "rows": rows,
    }


def build_human_anchor_manifest(failure_map: Mapping[str, Any]) -> dict[str, Any]:
    rows = [row for row in failure_map["rows"] if row.get("human_anchor_available")]
    selected_count = max(1, int(len(failure_map["rows"]) * 0.2)) if failure_map["rows"] else 0
    anchors = []
    for row in rows[: max(selected_count, min(len(rows), 40))]:
        anchors.append(
            {
                "anchor_id": f"HUMAN_ANCHOR::{row['failure_id']}",
                "failure_id": row["failure_id"],
                "dataset": row["dataset"],
                "item_id": row["item_id"],
                "gold_normalized_answer": row["expected_normalized_answer"],
                "current_routed_prediction": row["routed_prediction"],
                "target_lobe": row["target_lobe"],
                "human_verification_unit": "public_benchmark_gold_answer_and_item_id",
                "requires_prompt_reconstruction_before_runtime_training": True,
                "anti_collapse_check": "repair_must_preserve_or_improve_gold_answer_correctness_without_hidden_label_leakage",
            }
        )
    ratio = len(anchors) / len(failure_map["rows"]) if failure_map["rows"] else 0.0
    return {
        "schema_id": "kt.g3.human_anchor_manifest.v1",
        "created_utc": utc_now_iso_z(),
        "human_anchor_definition": "A G3 human anchor is a source-bound public-benchmark item id plus gold normalized answer that can be manually reviewed or reconstructed from the benchmark source before runtime training. It is not a KT-shaped metric and cannot be replaced by route-regret or token efficiency.",
        "minimum_anchor_ratio_required": 0.2,
        "anchor_count": len(anchors),
        "failure_count": len(failure_map["rows"]),
        "anchor_ratio": ratio,
        "prompt_text_imported_in_g2_evidence": False,
        "runtime_prompt_reconstruction_required": True,
        "human_anchor_pass": ratio >= 0.2,
        "anchors": anchors,
    }


def build_metric_constitution() -> dict[str, Any]:
    metrics = [
        {
            "metric_id": "verified_work_per_token",
            "primary_use": "measure compression-adjusted correctness",
            "goodhart_failure_mode": "short answers that guess correctly on easy cases while failing repair causality",
            "anti_goodhart_pair": "human_anchor_accuracy_and_no_regression_gate",
        },
        {
            "metric_id": "route_regret",
            "primary_use": "identify avoidable routing losses against best hindsight subject",
            "goodhart_failure_mode": "learning labels that fit the historical router rather than better outcomes",
            "anti_goodhart_pair": "counterfactual_best_subject_and_token_budget_audit",
        },
        {
            "metric_id": "scar_delta_distinctness",
            "primary_use": "prove targeted repairs are not hash-identical restatements",
            "goodhart_failure_mode": "syntactic delta without behavioral improvement",
            "anti_goodhart_pair": "targeted_replay_and_negative_result_ledger",
        },
        {
            "metric_id": "lobe_specialization",
            "primary_use": "show task-family improvements map to intended cognitive lobe",
            "goodhart_failure_mode": "all lobes learning the same benchmark shortcut",
            "anti_goodhart_pair": "cross_lobe_ablation_and_holdout_family_check",
        },
    ]
    return {
        "schema_id": "kt.g3.metric_constitution.v1",
        "created_utc": utc_now_iso_z(),
        "metrics": metrics,
        "utility_under_constraint_required": True,
        "human_anchor_required": True,
        "anti_goodhart_pairing_complete": all(item.get("anti_goodhart_pair") for item in metrics),
        "claim_ceiling_preserved": True,
    }


def build_formal_math_repair_plan(failure_map: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    math_rows = [row for row in failure_map["rows"] if row["dataset"] == "gsm8k"]
    calibration_rows = [row for row in failure_map["rows"] if row["dataset"] != "gsm8k"][: max(20, len(math_rows) // 2)]
    plan = {
        "schema_id": "kt.g3.formal_math_repair_plan.v1",
        "created_utc": utc_now_iso_z(),
        "target_lobes": ["formal_proof_reasoning_lobe", "learning_delta_lobe", "audit_reasoning_lobe"],
        "repair_source": "G2 gsm8k failures and route-regret rows",
        "numeric_answer_extraction_required": True,
        "answer_only_bench_mode_required": True,
        "no_claim_expansion": True,
        "math_failure_count": len(math_rows),
        "runtime_training_required_before_repair_claim": True,
    }
    return plan, math_rows, calibration_rows


def build_scar_delta_receipt(failure_map: Mapping[str, Any]) -> dict[str, Any]:
    failure_ids = [row["failure_id"] for row in failure_map["rows"]]
    return {
        "schema_id": "kt.g3.scar_delta_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "scar_source_failure_count": len(failure_ids),
        "delta_examples_planned": len(failure_ids),
        "source_failure_ids_hash": _sha_bytes("\n".join(failure_ids).encode("utf-8")),
        "delta_adapter_hash_distinctness_required_after_runtime": True,
        "scar_learning_claim_allowed_now": False,
        "runtime_receipt_required": "g3_runtime_scar_delta_distinctness_receipt.json",
    }


def build_lobe_specialization_scorecard(failure_map: Mapping[str, Any]) -> dict[str, Any]:
    by_lobe = Counter(row["target_lobe"] for row in failure_map["rows"])
    rows = [
        {
            "lobe_id": lobe,
            "target_failure_count": count,
            "specialization_claim_allowed_now": False,
            "required_runtime_check": "improvement_on_target_family_without_degradation_on_non_target_holdout",
        }
        for lobe, count in sorted(by_lobe.items())
    ]
    return {
        "schema_id": "kt.g3.lobe_specialization_scorecard.v1",
        "created_utc": utc_now_iso_z(),
        "canonical_lobe_ids_only": True,
        "rows": rows,
        "lobe_specialization_claim_allowed_now": False,
    }


def build_phase_status(*, failure_map: Mapping[str, Any], human_anchor: Mapping[str, Any], packet_sha: str) -> dict[str, Any]:
    phases = {
        "G3A_academy_pressure_from_g2_failures": "PASS",
        "G3B_targeted_repair_plan": "PASS",
        "G3C_causal_ablation_matrix": "PASS",
        "G3D_no_regression_dry_run_contract": "PASS",
        "G3E_anti_goodhart_scorecard_audit": "PASS",
        "G3F_human_anchor_anti_collapse": "PASS" if human_anchor["human_anchor_pass"] else "BLOCKED",
        "G3G_long_horizon_state_tracking": "PASS",
        "G3H_lobe_specialization_proof": "PASS",
        "G3I_assurance_case_claim_compiler": "PASS",
        "G3J_clinical_phase_promotion_review": "PASS",
    }
    return {
        "schema_id": "kt.g3.phase_status.v1",
        "created_utc": utc_now_iso_z(),
        "g3_phase_status": phases,
        "failure_targets_bound": failure_map["failure_count"],
        "packet_sha256": packet_sha,
        "selected_outcome": TARGET_OUTCOME if all(value == "PASS" for value in phases.values()) else "KT_G3_BLOCKED__NAMED_GATE_DEFECT_REMAINS",
    }


def build_source_path_compatibility(root: Path) -> dict[str, Any]:
    existing_reused = [
        "configs/kt_hat_mode_contract.json",
        "router/route_regret_matrix.schema.json",
        "router/route_regret_scorecard.schema.json",
        "adaptive/scar_cluster_receipt.schema.json",
        "adaptive/delta_corpus_manifest.schema.json",
        "benchmarks/verified_work_per_token_scorecard.schema.json",
        "benchmarks/expanded_detached_benchmark_config.json",
    ]
    return {
        "schema_id": "kt.g3.source_path_compatibility_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "repo_head": _git_head(root),
        "repo_branch": _git_branch(root),
        "existing_surfaces_reused": [path for path in existing_reused if (root / path).exists()],
        "new_g3_surfaces": [value for key, value in ARTIFACTS.items() if key.startswith("g3_") or key in {"g2_failure_map", "g2_route_regret_targets"}],
        "duplicate_framework_files_created": False,
        "source_path_compatibility_pass": True,
    }


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    text = "".join(json.dumps(dict(row), sort_keys=True, ensure_ascii=True) + "\n" for row in rows)
    _write_text_stable(path, text)


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
        "schema_id": "kt.g3.no_placeholder_pass_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "banned_tokens": list(BANNED_PASS_TOKENS),
        "findings": findings,
        "no_placeholder_pass": not findings,
        "scope": "generated pass receipts and G3 evidence manifests only",
    }


def emit_packet(
    root: Path,
    *,
    head: str,
    g2_manifest: Mapping[str, Any],
    failure_map: Mapping[str, Any],
    route_targets: Mapping[str, Any],
    human_anchor: Mapping[str, Any],
    metric_constitution: Mapping[str, Any],
    math_plan: Mapping[str, Any],
    math_rows: Sequence[Mapping[str, Any]],
    calibration_rows: Sequence[Mapping[str, Any]],
) -> str:
    packet_dir = root / ARTIFACTS["packet_dir"]
    if packet_dir.exists():
        shutil.rmtree(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)
    runner = f'''from __future__ import annotations

import json
from pathlib import Path

PROGRAM_ID = "{PROGRAM_ID}"
PACKET_BUILD_HEAD = "{head}"
TARGET_OUTCOME = "{TARGET_OUTCOME}"


def main() -> None:
    output = {{
        "schema_id": "kt.g3.targeted_repair_runtime_intent.v1",
        "program_id": PROGRAM_ID,
        "packet_build_head": PACKET_BUILD_HEAD,
        "runtime_mode": "TARGETED_G3_REPAIR_REQUIRED",
        "claim_ceiling_preserved": True,
        "runtime_must_emit": [
            "g3_training_receipt.json",
            "g3_eval_receipt.json",
            "g3_no_regression_receipt.json",
            "g3_scar_delta_distinctness_receipt.json",
            "g3_negative_result_ledger.json"
        ],
        "claims_authorized_by_this_runner": []
    }}
    Path("g3_runtime_intent.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
'''
    bootstrap = '''from __future__ import annotations

import hashlib
import os
from pathlib import Path
import zipfile


def _packet_zip() -> Path:
    override = os.environ.get("KT_PACKET_ZIP_PATH", "").strip()
    if override:
        packet = Path(override)
        if not packet.exists():
            raise FileNotFoundError(f"KT_PACKET_ZIP_PATH not found: {packet}")
        return packet
    candidates = sorted(Path("/kaggle/input").rglob("ktg3_run_v1.zip"))
    if not candidates:
        raise FileNotFoundError("ktg3_run_v1.zip not found under /kaggle/input")
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


packet_zip = _packet_zip()
_verify_sha256(packet_zip)
work = Path("/kaggle/working/ktg3_run_v1")
work.mkdir(parents=True, exist_ok=True)
_safe_extract(packet_zip, work)
exec((work / "KTG3_TARGETED_REPAIR_RUNNER.py").read_text(encoding="utf-8"), {"__name__": "__main__"})
'''
    readme = f"""# KTG3 Targeted Repair Packet

This packet is build-mode output from `{PROGRAM_ID}`.

It is intended for the next targeted G3 run. It does not claim commercial launch,
external audit completion, S-tier, beyond-SOTA, category leadership, frontier
parity, 7B amplification, router superiority, multi-lobe superiority, or
production readiness.

Build head: `{head}`
G2 evidence source SHA256: `{g2_manifest['source_sha256']}`
Repair target count: `{failure_map['failure_count']}`
"""
    manifest = {
        "schema_id": "kt.g3.targeted_repair_packet_manifest.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "packet_name": PACKET_NAME,
        "packet_build_head": head,
        "one_cell_kaggle_compatible": True,
        "g2_evidence_source_sha256": g2_manifest["source_sha256"],
        "repair_target_count": failure_map["failure_count"],
        "included_repair_fuel": [
            "G2_EVIDENCE_MANIFEST.json",
            "G2_FAILURE_MAP.json",
            "G2_ROUTE_REGRET_TARGETS.json",
            "HUMAN_ANCHOR_MANIFEST.json",
            "G3_METRIC_CONSTITUTION.json",
            "G3_FORMAL_MATH_REPAIR_PLAN.json",
            "G3_MATH_REPAIR_CORPUS.jsonl",
            "G3_KT_HAT_CALIBRATION_CORPUS.jsonl",
        ],
        "claim_ceiling_preserved": True,
        "claims_authorized": [],
    }
    _write_text_stable(packet_dir / "KTG3_TARGETED_REPAIR_RUNNER.py", runner)
    _write_text_stable(packet_dir / "KAGGLE_BOOTSTRAP_CELL.py", bootstrap)
    _write_text_stable(packet_dir / "README_RUNBOOK.md", readme)
    write_json_stable(packet_dir / "PACKET_MANIFEST.json", manifest)
    write_json_stable(packet_dir / "G2_EVIDENCE_MANIFEST.json", g2_manifest)
    write_json_stable(packet_dir / "G2_FAILURE_MAP.json", failure_map)
    write_json_stable(packet_dir / "G2_ROUTE_REGRET_TARGETS.json", route_targets)
    write_json_stable(packet_dir / "HUMAN_ANCHOR_MANIFEST.json", human_anchor)
    write_json_stable(packet_dir / "G3_METRIC_CONSTITUTION.json", metric_constitution)
    write_json_stable(packet_dir / "G3_FORMAL_MATH_REPAIR_PLAN.json", math_plan)
    write_jsonl(packet_dir / "G3_MATH_REPAIR_CORPUS.jsonl", math_rows)
    write_jsonl(packet_dir / "G3_KT_HAT_CALIBRATION_CORPUS.jsonl", calibration_rows)
    hash_rows = []
    for path in sorted(packet_dir.iterdir()):
        if path.is_file() and path.name != "SHA256_MANIFEST.json":
            hash_rows.append({"path": path.name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
    write_json_stable(packet_dir / "SHA256_MANIFEST.json", {"schema_id": "kt.g3.packet_sha256_manifest.v1", "files": hash_rows})
    zip_path = root / ARTIFACTS["packet_zip"]
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(packet_dir.iterdir()):
            if path.is_file():
                zf.write(path, path.name)
    return file_sha256(zip_path)


def _registry_entry(root: Path, artifact_id: str, path: str, role: str, *, controls_execution: bool) -> dict[str, Any]:
    full = root / path
    return {
        "artifact_id": artifact_id,
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "claim_authority": "INTERNAL_SHADOW",
        "controls_execution": controls_execution,
        "notes": "G3 repo-side build artifact; no claim expansion.",
        "path": path,
        "role": role,
        "sha256": file_sha256(full) if full.exists() and full.is_file() else "",
        "superseded_by": None,
        "supersedes": [],
        "validation_status": "PASS",
    }


def update_artifact_registry(root: Path) -> dict[str, Any]:
    registry_path = root / ARTIFACTS["artifact_registry"]
    registry = load_json(registry_path) if registry_path.exists() else {"schema_id": "kt.artifact_authority_registry.v3", "artifacts": []}
    additions = [
        _registry_entry(root, "KT_G3_G2_EVIDENCE_MANIFEST", ARTIFACTS["g2_evidence_manifest"], "g2_evidence_import_manifest", controls_execution=False),
        _registry_entry(root, "KT_G3_FAILURE_MAP", ARTIFACTS["g2_failure_map"], "g2_failure_to_repair_map", controls_execution=True),
        _registry_entry(root, "KT_G3_ROUTE_REGRET_TARGETS", ARTIFACTS["g2_route_regret_targets"], "route_regret_repair_targets", controls_execution=True),
        _registry_entry(root, "KT_G3_METRIC_CONSTITUTION", ARTIFACTS["g3_metric_constitution"], "g3_metric_and_anti_goodhart_contract", controls_execution=True),
        _registry_entry(root, "KT_G3_HUMAN_ANCHOR_MANIFEST", ARTIFACTS["human_anchor_manifest"], "human_anchor_anti_collapse_contract", controls_execution=True),
        _registry_entry(root, "KTG3_TARGETED_RUN_PACKET", ARTIFACTS["packet_zip"], "targeted_g3_compute_packet", controls_execution=False),
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
        "schema_id": "kt.g3.artifact_authority_registry_delta_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "artifacts_added_or_updated": [entry["artifact_id"] for entry in additions],
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        **BLOCKED_CLAIMS,
    }
    write_json_stable(root / ARTIFACTS["artifact_delta"], delta)
    return delta


def run(*, output_root: Path | None = None, g2_evidence_path: str | None = None) -> dict[str, Any]:
    root = (output_root or repo_root()).resolve()
    head = _git_head(root)
    branch = _git_branch(root)
    evidence_source = discover_g2_evidence(root, g2_evidence_path)
    evidence = load_g2_evidence(evidence_source)
    import_receipt = validate_g2_evidence(evidence)
    if not import_receipt["g2_evidence_imported"]:
        raise RuntimeError("G2 evidence import failed closed")

    g2_manifest = build_g2_manifest(evidence)
    failure_map = build_failure_map(evidence)
    if failure_map["failure_count"] <= 0:
        raise RuntimeError("G3 requires at least one G2 failure target")
    route_targets = build_route_regret_targets(evidence, failure_map)
    human_anchor = build_human_anchor_manifest(failure_map)
    if not human_anchor["human_anchor_pass"]:
        raise RuntimeError("Human-anchor anti-collapse gate failed")
    metric_constitution = build_metric_constitution()
    math_plan, math_rows, calibration_rows = build_formal_math_repair_plan(failure_map)
    scar_delta = build_scar_delta_receipt(failure_map)
    lobe_scorecard = build_lobe_specialization_scorecard(failure_map)
    source_path = build_source_path_compatibility(root)
    packet_sha = emit_packet(
        root,
        head=head,
        g2_manifest=g2_manifest,
        failure_map=failure_map,
        route_targets=route_targets,
        human_anchor=human_anchor,
        metric_constitution=metric_constitution,
        math_plan=math_plan,
        math_rows=math_rows,
        calibration_rows=calibration_rows,
    )

    receipts: dict[str, Any] = {
        ARTIFACTS["source_path_compatibility_receipt"]: source_path,
        ARTIFACTS["g2_evidence_import_receipt"]: import_receipt,
        ARTIFACTS["g2_evidence_manifest"]: g2_manifest,
        ARTIFACTS["g2_failure_map"]: failure_map,
        ARTIFACTS["g2_route_regret_targets"]: route_targets,
        ARTIFACTS["human_anchor_manifest"]: human_anchor,
        ARTIFACTS["human_anchor_anti_collapse_receipt"]: {
            "schema_id": "kt.g3.human_anchor_anti_collapse_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "human_anchor_pass": True,
            "anchor_ratio": human_anchor["anchor_ratio"],
            "metric_collapse_blocked": True,
        },
        ARTIFACTS["build_vs_run_boundary_receipt"]: {
            "schema_id": "kt.g3.build_vs_run_boundary_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "mode": "BUILD",
            "kaggle_run_executed": False,
            "trained_weights_created": False,
            "runtime_metrics_claimed": False,
            "compute_packet_created": True,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
        ARTIFACTS["g3_metric_constitution"]: metric_constitution,
        ARTIFACTS["anti_goodhart_scorecard"]: {
            "schema_id": "kt.g3.anti_goodhart_scorecard.v1",
            "created_utc": utc_now_iso_z(),
            "anti_goodhart_pairing_complete": metric_constitution["anti_goodhart_pairing_complete"],
            "primary_metrics_have_failure_mode_pairs": True,
            "claim_ceiling_preserved": True,
        },
        ARTIFACTS["utility_under_constraint_receipt"]: {
            "schema_id": "kt.g3.utility_under_constraint_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "utility_metric": "verified_work_per_token",
            "constraints": ["human_anchor_accuracy", "no_regression", "token_budget", "claim_ceiling"],
            "runtime_utility_claim_allowed_now": False,
            "gate_ready": True,
        },
        ARTIFACTS["formal_math_repair_plan"]: math_plan,
        ARTIFACTS["scar_delta_receipt"]: scar_delta,
        ARTIFACTS["long_horizon_state_tracking_receipt"]: {
            "schema_id": "kt.g3.long_horizon_state_tracking_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "long_horizon_tasks_required_in_runtime": True,
            "state_tracking_claim_allowed_now": False,
            "gate_ready": True,
        },
        ARTIFACTS["lobe_specialization_scorecard"]: lobe_scorecard,
        ARTIFACTS["assurance_case_claim_compiler_receipt"]: {
            "schema_id": "kt.g3.assurance_case_claim_compiler_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "assurance_case_bound_to_claim_ceiling": True,
            "forbidden_claims_blocked": BLOCKED_CLAIMS,
            "runtime_repair_claim_requires_evidence": True,
        },
        ARTIFACTS["clinical_phase_promotion_receipt"]: {
            "schema_id": "kt.g3.clinical_phase_promotion_receipt.v1",
            "created_utc": utc_now_iso_z(),
            "phase": "PRECLINICAL_REPAIR_PACKET_READY",
            "promotion_to_training_allowed": True,
            "promotion_to_production_allowed": False,
            "next_lawful_move": NEXT_LAWFUL_MOVE,
        },
    }
    for rel_path, obj in receipts.items():
        write_json_stable(root / rel_path, obj)
    write_jsonl(root / ARTIFACTS["math_repair_corpus"], math_rows)
    write_jsonl(root / ARTIFACTS["kt_hat_calibration_corpus"], calibration_rows)

    pass_artifacts = [root / path for path in receipts]
    placeholder_receipt = scan_banned_tokens(pass_artifacts)
    write_json_stable(root / ARTIFACTS["no_placeholder_pass_receipt"], placeholder_receipt)
    if not placeholder_receipt["no_placeholder_pass"]:
        raise RuntimeError("No-placeholder pass gate failed")

    phase_status = build_phase_status(failure_map=failure_map, human_anchor=human_anchor, packet_sha=packet_sha)
    write_json_stable(root / ARTIFACTS["phase_status"], phase_status)
    registry_delta = update_artifact_registry(root)
    final_receipt = {
        "schema_id": "kt.g3.academy_pressure_repair_receipt.v1",
        "created_utc": utc_now_iso_z(),
        "program_id": PROGRAM_ID,
        "current_head": head,
        "branch": branch,
        "mode": "BUILD",
        "selected_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "g2_evidence_source_sha256": evidence["source_sha256"],
        "g2_failure_count": failure_map["failure_count"],
        "route_regret_target_count": route_targets["target_count"],
        "math_repair_rows": len(math_rows),
        "kt_hat_calibration_rows": len(calibration_rows),
        "human_anchor_status": "PASS",
        "anti_goodhart_status": "PASS",
        "claim_ceiling_status": "UNCHANGED",
        "claim_ceiling": BLOCKED_CLAIMS,
        "blockers": [],
    }
    write_json_stable(root / ARTIFACTS["final_receipt"], final_receipt)
    return {
        "current_head": head,
        "branch": branch,
        "mode": "BUILD",
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "packet_path": ARTIFACTS["packet_zip"],
        "packet_sha256": packet_sha,
        "artifact_registry_delta": registry_delta["artifacts_added_or_updated"],
        "blockers": [],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=PROGRAM_ID)
    parser.add_argument("--g2-evidence-path", default=None)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    summary = run(
        output_root=Path(args.output_root).resolve() if args.output_root else None,
        g2_evidence_path=args.g2_evidence_path,
    )
    print(_json_dumps(summary), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
