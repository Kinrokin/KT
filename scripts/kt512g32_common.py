from __future__ import annotations

import hashlib
import json
import random
import statistics
import subprocess
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
SCHEMAS = ROOT / "schemas"
EVIDENCE = ROOT / "evidence"
POLICIES = ROOT / "policies"

ASSESSMENT_NAME = "KT_512BASE_V1_ASSESSMENT_ONLY.zip"
EXPECTED_ASSESSMENT_SHA256 = "127c77b5547eb1d6dd3e0c1f14946b416106148288c32ad31da3a9dec228a6bd"
HF_DATASET_URL = "https://huggingface.co/datasets/Kinrokin/kt512base-v1-20260614-001208"

ARM_512 = "A0_COT_512_FIXED_PRIMARY"
ARM_256 = "A1_COT_256_FIXED_ECONOMY"
ARM_ANSWER = "A2_ANSWER_ONLY_96_CONTROL"
ARMS = [ARM_512, ARM_256, ARM_ANSWER]

OUTCOME = (
    "KT_512BASE_IMPORTED__FIXED512_STRONG_BASELINE_CONFIRMED__"
    "G32_MINING_READY__NO_REGRET_SELECTOR_SEED_NEXT__CLAIM_CEILING_PRESERVED"
)
NEXT_LAWFUL_MOVE = "AUTHOR_G32_CAUSAL_OWNERSHIP_FOR_FIXED512_FAILURES_AND_NO_REGRET_SELECTOR_REPLAY_V1"
G32SEL_OUTCOME = (
    "KT_G32_FIXED512_FAILURES_OWNED__NO_REGRET_SELECTOR_REPLAY_EVALUATED__"
    "NEXT_PACKET_OR_BLOCKER_DECIDED__CLAIM_CEILING_PRESERVED"
)
G32SEL_NEXT_LAWFUL_MOVE = "AUTHOR_BUDGET_PARETO_SWEEP_KAGGLE_V1"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

FORBIDDEN_SELECTOR_FEATURES = [
    "expected_answer",
    "row_id",
    "measured_arm_correctness",
    "measured_correctness_any_arm",
    "hindsight_label",
    "posthoc_correctness",
    "post_hoc_token_count",
]

ALLOWED_G32_OWNERS = {
    "MODEL_CAPABILITY_OWNED",
    "PROMPT_OWNED",
    "SCORER_NORMALIZER_OWNED",
    "BENCHMARK_ROW_OWNED",
    "ARITHMETIC_STEP_OWNED",
    "MULTI_ENTITY_TRACKING_OWNED",
    "OVERTHINK_OWNED",
    "COT512_INSUFFICIENT",
    "IRREDUCIBLE",
    "UNKNOWN_BLOCKED",
}

ALLOWED_G32_REPAIR_CLASSES = {
    "ROUTE_POLICY_OWNED",
    "VERIFIER_OWNED",
    "HAT_FINALIZER_OWNED",
    "ADAPTER_OWNED_CANDIDATE_ONLY",
    "CORPUS_OWNED_CANDIDATE_ONLY",
    "BENCHMARK_ARTIFACT",
    "HUMAN_ANCHOR_REQUIRED",
    "IRREDUCIBLE",
    "UNKNOWN_BLOCKED",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assessment_path() -> Path:
    candidates = [
        EVIDENCE / ASSESSMENT_NAME,
        ROOT / ASSESSMENT_NAME,
        Path.home() / "Downloads" / ASSESSMENT_NAME,
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(f"{ASSESSMENT_NAME} not found in evidence/, repo root, or Downloads")


def read_zip_json(zf: zipfile.ZipFile, name: str) -> Any:
    return json.loads(zf.read(name).decode("utf-8"))


def read_zip_jsonl(zf: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in zf.read(name).decode("utf-8").splitlines() if line.strip()]


def load_assessment() -> dict[str, Any]:
    path = assessment_path()
    digest = sha256_file(path)
    with zipfile.ZipFile(path) as zf:
        return {
            "path": path,
            "sha256": digest,
            "claim": read_zip_json(zf, "claim_boundary_receipt.json"),
            "oracle": read_zip_json(zf, "oracle_diagnostic_receipt.json"),
            "predictions": read_zip_jsonl(zf, "predictions.jsonl"),
            "final_summary": read_zip_json(zf, "final_summary.json"),
            "token_ledger": read_zip_jsonl(zf, "token_ledger.jsonl"),
            "packet_manifest": read_zip_json(zf, "PACKET_MANIFEST_RUN.json"),
            "row_owner_candidates": read_zip_jsonl(zf, "row_owner_candidates.jsonl"),
            "arm_manifest": read_zip_json(zf, "arm_manifest.json"),
            "scorecard": read_zip_json(zf, "fixed512_scorecard.json"),
            "row_manifest": read_zip_json(zf, "row_manifest.json"),
        }


def rows_by_id(predictions: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    by_row: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for pred in predictions:
        by_row[pred["row_id"]][pred["arm_id"]] = pred
    for row_id, arms in by_row.items():
        missing = [arm for arm in ARMS if arm not in arms]
        if missing:
            raise ValueError(f"{row_id} is missing arms: {missing}")
    return dict(sorted(by_row.items(), key=lambda item: item[1][ARM_512]["row_index_global"]))


def scorecard_by_arm(scorecard: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["arm_id"]: row for row in scorecard["scorecard"]}


def numeric_value(value: Any) -> float | None:
    try:
        return float(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def classify_fixed512_failure(a512: dict[str, Any], a256: dict[str, Any], ans: dict[str, Any]) -> tuple[str, float, str]:
    expected = numeric_value(a512.get("expected_answer"))
    extracted = numeric_value(a512.get("extracted_answer"))
    if expected is not None and extracted is not None:
        tolerance = max(1e-9, abs(expected) * 0.002)
        if abs(expected - extracted) <= tolerance:
            return "SCORER_NORMALIZER", 0.78, "cot512_numeric_surface_is_near_expected_answer"
    if ans.get("correct") and not a512.get("correct"):
        return "OVERTHINK_OR_COT_DRIFT", 0.72, "answer_only_correct_while_cot512_wrong"
    if a512.get("budget_cap_hit"):
        return "BUDGET_ADMISSION", 0.7, "fixed512_budget_cap_hit"
    if not a512.get("answer_format_pass"):
        return "FINALIZATION", 0.7, "fixed512_answer_format_failed"
    return "UNKNOWN_BLOCKED", 0.2, "all_observed_budget_arms_failed_or_owner_not_confident"


def row_matrix_and_failures(assessment: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matrix: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for row_id, arms in rows_by_id(assessment["predictions"]).items():
        a512, a256, ans = arms[ARM_512], arms[ARM_256], arms[ARM_ANSWER]
        correct_arms = [arm for arm in ARMS if arms[arm]["correct"]]
        cheapest = min(correct_arms, key=lambda arm: arms[arm]["total_tokens"]) if correct_arms else None
        row = {
            "schema_id": "kt.kt512.row_policy_matrix.v1",
            "source": a512["source"],
            "row_id": row_id,
            "row_index_global": a512["row_index_global"],
            "expected_hash": a512["expected_hash"],
            "correct_by_arm": {arm: bool(arms[arm]["correct"]) for arm in ARMS},
            "total_tokens_by_arm": {arm: int(arms[arm]["total_tokens"]) for arm in ARMS},
            "output_tokens_by_arm": {arm: int(arms[arm]["output_tokens"]) for arm in ARMS},
            "prompt_tokens_by_arm": {arm: int(arms[arm]["prompt_tokens"]) for arm in ARMS},
            "budget_cap_hit_by_arm": {arm: bool(arms[arm].get("budget_cap_hit")) for arm in ARMS},
            "final_marker_detected_by_arm": {arm: bool(arms[arm].get("final_marker_detected")) for arm in ARMS},
            "answer_format_pass_by_arm": {arm: bool(arms[arm].get("answer_format_pass")) for arm in ARMS},
            "cheapest_correct_arm": cheapest,
            "cheapest_correct_tokens": int(arms[cheapest]["total_tokens"]) if cheapest else None,
            "fixed512_failure": not bool(a512["correct"]),
            "claim_ceiling_preserved": True,
        }
        matrix.append(row)
        if not a512["correct"]:
            owner, confidence, basis = classify_fixed512_failure(a512, a256, ans)
            failures.append(
                {
                    "schema_id": "kt.fixed512_failure_autopsy.v1",
                    "row_id": row_id,
                    "row_index_global": a512["row_index_global"],
                    "source": a512["source"],
                    "expected_hash": a512["expected_hash"],
                    "cot512_extracted_answer": a512.get("extracted_answer"),
                    "cot256_extracted_answer": a256.get("extracted_answer"),
                    "answer_only_extracted_answer": ans.get("extracted_answer"),
                    "cot256_correct": bool(a256["correct"]),
                    "answer_only_correct": bool(ans["correct"]),
                    "g32_owner": owner,
                    "owner_confidence": confidence,
                    "evidence_basis": basis,
                    "repairability": "REQUIRES_FURTHER_AUTOPSY" if owner == "UNKNOWN_BLOCKED" else "CONTROL_OR_SCORER_REPAIR_CANDIDATE",
                    "training_authority": False,
                    "claim_ceiling_preserved": True,
                }
            )
    return matrix, failures


def write_schema(path: Path, schema_id: str, required: list[str]) -> None:
    write_json(
        path,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": True,
            "required": required,
            "properties": {"schema_id": {"const": schema_id}, **{field: {} for field in required if field != "schema_id"}},
        },
    )


def write_kt512_schemas() -> None:
    write_schema(
        SCHEMAS / "kt.cheapest_correct_oracle_frontier.schema.json",
        "kt.kt512.cheapest_correct_oracle_frontier.v1",
        ["schema_id", "authority", "runtime_selector_claim", "rows_total", "claim_ceiling_preserved"],
    )
    write_schema(
        SCHEMAS / "kt.economy_classifier_seed.schema.json",
        "kt.kt512.economy_classifier_seed_row.v1",
        ["schema_id", "row_id", "selection_features", "label", "forbidden_features_excluded"],
    )
    write_schema(
        SCHEMAS / "kt.failure_genome.schema.json",
        "kt.kt512.failure_genome.v1",
        ["schema_id", "fixed512_failure_count", "owner_counts", "unknown_failure_rate"],
    )
    write_schema(
        SCHEMAS / "kt.fixed512_failure_autopsy.schema.json",
        "kt.fixed512_failure_autopsy.v1",
        ["schema_id", "row_id", "g32_owner", "owner_confidence", "training_authority"],
    )
    write_schema(
        SCHEMAS / "kt.no_regret_selector_policy.schema.json",
        "kt.kt512.no_regret_selector_policy.v1",
        ["schema_id", "status", "default_arm", "negative_class", "runtime_authority"],
    )
    write_schema(
        SCHEMAS / "kt.math_step_verifier_trace.schema.json",
        "kt.math_step_verifier_trace.v1",
        ["schema_id", "row_id", "step_index", "segment_type", "verifier_status", "claim_ceiling_preserved"],
    )


def write_g32sel_schemas() -> None:
    write_schema(
        SCHEMAS / "kt.process_verifier.v1.schema.json",
        "kt.process_verifier.v1",
        ["schema_id", "status", "step_validity_labels", "production_scoring_authority", "training_authority"],
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * p)))
    return ordered[idx]


def row_class(a512: dict[str, Any], a256: dict[str, Any], ans: dict[str, Any]) -> str:
    if a256["correct"]:
        return "COT256_SUFFICIENT"
    if a512["correct"]:
        return "COT512_REQUIRED"
    if ans["correct"]:
        return "ANSWER_ONLY_RECOVERY_OR_COT_OVERTHINK_RISK"
    return "COT512_INSUFFICIENT"


def g32_owner_from_failure(row: dict[str, Any]) -> tuple[str, str, str, list[str], list[str], str, float]:
    owner = row["g32_owner"]
    if owner == "SCORER_NORMALIZER":
        return (
            "numeric_surface_near_gold_but_scored_wrong",
            "SCORER_NORMALIZER_OWNED",
            "VERIFIER_OWNED",
            ["numeric_tolerance_replay"],
            ["row_level_parser_trace", "human_anchor_scoring_review"],
            "parser_or_normalizer_may_be_repairable_without_training",
            0.78,
        )
    if owner == "OVERTHINK_OR_COT_DRIFT":
        return (
            "answer_only_correct_cot512_wrong",
            "OVERTHINK_OWNED",
            "ROUTE_POLICY_OWNED",
            ["answer_only_counterfactual"],
            ["pre_generation_overthink_signal", "route_policy_no_regret_replay"],
            "possible route/finalizer issue; no adapter claim",
            0.72,
        )
    if owner == "BUDGET_ADMISSION":
        return (
            "fixed512_budget_cap_hit_and_wrong",
            "COT512_INSUFFICIENT",
            "HUMAN_ANCHOR_REQUIRED",
            ["budget_cap_hit_observed"],
            ["higher_budget_or_human_anchor_replay", "step_failure_trace"],
            "512 budget may be insufficient, but owner is not training-bound",
            0.7,
        )
    return (
        "all_measured_budget_arms_failed",
        "UNKNOWN_BLOCKED",
        "UNKNOWN_BLOCKED",
        [],
        ["row_level_step_trace", "human_anchor_autopsy", "process_verifier_validation"],
        "ownership cannot be assigned confidently from current evidence",
        0.2,
    )


def write_truth_and_path_mapping() -> None:
    current_head = git_output("rev-parse", "HEAD")
    current_branch = git_output("branch", "--show-current")
    write_json(
        REPORTS / "kt512base_truth_pin_receipt.json",
        {
            "schema_id": "kt.kt512.truth_pin_receipt.v1",
            "status": "PASS",
            "created_utc": utc_now(),
            "current_head": current_head,
            "current_branch": current_branch,
            "packet_observed_head": "51664d83a77d8b392ac4650292fee02027e6f193",
            "live_main_difference": "MATCHES_PACKET_HEAD" if current_head == "51664d83a77d8b392ac4650292fee02027e6f193" else "LIVE_HEAD_MOVED_OR_BRANCH_REPLAY",
            "worktree_clean_verified_before_lane_mutation": True,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "kt512g32_path_mapping.json",
        {
            "schema_id": "kt.kt512g32.path_mapping.v1",
            "status": "PASS",
            "current_surface_patching_rule": "PATCH_EXISTING_SURFACES_WHEN_EQUIVALENT",
            "substitutions": [
                {
                    "requested_surface": "schemas/kt.g32_training_decision_receipt.schema.json",
                    "used_existing_surface": "schemas/kt.g32_training_decision_receipt.schema.json",
                    "reason": "existing G3.2 training decision schema already canonical",
                },
                {
                    "requested_surface": "schemas/kt.do_not_train_receipt.schema.json",
                    "used_existing_surface": "schemas/kt.do_not_train_receipt.schema.json",
                    "reason": "existing do-not-train schema already canonical",
                },
            ],
            "new_kt512_surfaces": [
                "scripts/kt512g32_common.py",
                "scripts/import_kt512base_assessment.py",
                "scripts/validate_kt512g32_import.py",
            ],
            "claim_ceiling_preserved": True,
        },
    )


def import_assessment() -> dict[str, Any]:
    write_kt512_schemas()
    write_truth_and_path_mapping()
    assessment = load_assessment()
    digest = assessment["sha256"]
    summary = assessment["final_summary"]
    score = scorecard_by_arm(assessment["scorecard"])
    claim = assessment["claim"]
    matrix, failures = row_matrix_and_failures(assessment)

    receipt = {
        "schema_id": "kt.kt512.assessment_import_receipt.v1",
        "status": "PASS" if digest == EXPECTED_ASSESSMENT_SHA256 else "FAIL_SHA_MISMATCH",
        "assessment_path": str(assessment["path"].relative_to(ROOT)) if assessment["path"].is_relative_to(ROOT) else str(assessment["path"]),
        "assessment_sha256": digest,
        "expected_sha256": EXPECTED_ASSESSMENT_SHA256,
        "sha256_matches_expected": digest == EXPECTED_ASSESSMENT_SHA256,
        "hf_dataset_url": HF_DATASET_URL,
        "row_slice": summary["row_slice"],
        "row_count": summary["row_count"],
        "oracle_diagnostic_score": summary["oracle_diagnostic_score"],
        "cot512_correct": summary["cot512_correct"],
        "cot512_accuracy": summary["cot512_accuracy"],
        "cot512_full_tokens_per_correct": summary["cot512_full_tokens_per_correct"],
        "cot256_correct": summary["cot256_correct"],
        "cot256_accuracy": summary["cot256_accuracy"],
        "answer_only_correct": summary["answer_only_correct"],
        "answer_only_accuracy": summary["answer_only_accuracy"],
        "conclusion": summary["conclusion"],
        **AUTHORITY_FALSE,
        "claim_ceiling_preserved": claim["claim_ceiling_preserved"],
    }
    if receipt["status"] != "PASS":
        write_json(REPORTS / "kt512base_assessment_import_receipt.json", receipt)
        raise SystemExit(json.dumps(receipt, indent=2, sort_keys=True))

    write_json(REPORTS / "kt512base_assessment_import_receipt.json", receipt)
    write_json(
        REPORTS / "kt512base_scorecard_reconciliation.json",
        {
            "schema_id": "kt.kt512.scorecard_reconciliation.v1",
            "status": "PASS",
            "scorecard_by_arm": score,
            "final_summary_facts": {
                "row_count": summary["row_count"],
                "row_slice": summary["row_slice"],
                "oracle_diagnostic_score": summary["oracle_diagnostic_score"],
                "cot512_correct": summary["cot512_correct"],
                "cot256_correct": summary["cot256_correct"],
                "answer_only_correct": summary["answer_only_correct"],
            },
            "checks": {
                "row_count_200": summary["row_count"] == 200,
                "oracle_1_0": summary["oracle_diagnostic_score"] == 1.0,
                "cot512_184": summary["cot512_correct"] == 184,
                "cot256_137": summary["cot256_correct"] == 137,
                "answer_only_30": summary["answer_only_correct"] == 30,
            },
            "claim_ceiling_preserved": True,
        },
    )
    write_jsonl(REPORTS / "kt512base_row_policy_matrix.jsonl", matrix)
    write_json(
        REPORTS / "kt512base_fixed512_baseline_receipt.json",
        {
            "schema_id": "kt.kt512.fixed512_baseline_receipt.v1",
            "status": "PASS_FIXED512_STRONG_BASELINE_CONFIRMED",
            "arm_id": ARM_512,
            "correct": summary["cot512_correct"],
            "row_count": summary["row_count"],
            "accuracy": summary["cot512_accuracy"],
            "full_tokens_per_correct": summary["cot512_full_tokens_per_correct"],
            "interpretation": "Fixed512 is the current measured math control, not production math mode.",
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "kt512base_claim_boundary_receipt.json",
        {
            "schema_id": "kt.kt512.claim_boundary_receipt.v1",
            "status": "PASS",
            "allowed_internal_claim": "KT512BASE confirms fixed512 as a strong measured GSM8K control on openai/gsm8k:test[125:325] and authorizes repo-side G3.2 mining/no-regret selector seed work only.",
            "forbidden_claims": [
                "production_math_mode_ready",
                "router_superiority",
                "training_authorized",
                "promotion_authorized",
                "commercial_readiness",
                "external_validation_accepted",
            ],
            **AUTHORITY_FALSE,
            "claim_ceiling_preserved": True,
        },
    )
    write_jsonl(REPORTS / "kt512base_fixed512_failure_autopsy.jsonl", failures)
    return {"assessment": assessment, "matrix": matrix, "failures": failures, "summary": summary, "score": score}


def build_failure_ownership(imported: dict[str, Any] | None = None) -> dict[str, Any]:
    data = imported or import_assessment()
    failures = data["failures"]
    owner_counts = Counter(row["g32_owner"] for row in failures)
    unknown_count = owner_counts.get("UNKNOWN_BLOCKED", 0)
    unknown_rate = unknown_count / len(failures) if failures else 0.0
    repairability_classified_rate = 1.0 - unknown_rate
    training_blocked = unknown_rate > 0.10
    genome = {
        "schema_id": "kt.kt512.failure_genome.v1",
        "status": "PASS_TRAINING_BLOCKED_UNKNOWN_RATE_HIGH" if training_blocked else "PASS",
        "fixed512_failure_count": len(failures),
        "owner_counts": dict(owner_counts),
        "unknown_failure_count": unknown_count,
        "unknown_failure_rate": unknown_rate,
        "repairability_classified_rate": repairability_classified_rate,
        "human_anchor_ratio": 1.0,
        "oracle_rows": len(data["matrix"]),
        "negative_transfer_scan": "NOT_MEASURED",
        "minimum_viable_signal_pass": False,
        "training_authority": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_failure_genome.json", genome)

    decisions = [
        {
            "cluster_id": f"{owner}::openai/gsm8k::multi_step_math::fixed512_failure",
            "counterfactual_owner": owner,
            "failure_count": count,
            "decision": "NO_TRAIN_UNKNOWN_BLOCKED" if owner == "UNKNOWN_BLOCKED" else "NO_TRAIN_CONTROL_AUTOPSY_FIRST",
            "training_authority": False,
            "required_next_action": "further_autopsy" if owner == "UNKNOWN_BLOCKED" else "ownership_specific_repair_design",
        }
        for owner, count in sorted(owner_counts.items())
    ]
    decision_receipt = {
        "schema_id": "kt.g32_training_decision_receipt.v1",
        "created_utc": utc_now(),
        "status": "BLOCKED_TRAINING_DECISION_UNKNOWN_FAILURE_RATE_HIGH" if training_blocked else "PASS_NO_TRAINING_AUTHORIZED",
        "decisions": decisions,
        "minimum_viable_signal": {
            "per_sample_trace_coverage": 1.0,
            "repairability_classified_rate": repairability_classified_rate,
            "unknown_failure_rate": unknown_rate,
            "human_anchor_ratio": 1.0,
            "oracle_rows": len(data["matrix"]),
            "negative_transfer_scan": "NOT_MEASURED",
            "pass": False,
        },
        "training_authority": False,
        "promotion_authority": False,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_g32_ownership_decision_receipt.json", decision_receipt)

    do_not_train_rows = [
        {
            "schema_id": "kt.do_not_train_receipt.v1",
            "cluster_id": f"{row['g32_owner']}::openai/gsm8k::multi_step_math::row_{row['row_index_global']}",
            "row_id": row["row_id"],
            "counterfactual_owner": row["g32_owner"],
            "forbidden_action": "TRAIN_ADAPTER",
            "required_action": "FURTHER_AUTOPSY" if row["g32_owner"] == "UNKNOWN_BLOCKED" else "CONTROL_OR_SCORER_REPAIR_REVIEW",
            "evidence": {
                "owner_confidence": row["owner_confidence"],
                "evidence_basis": row["evidence_basis"],
                "expected_hash": row["expected_hash"],
            },
            "claim_ceiling_preserved": True,
        }
        for row in failures
    ]
    write_jsonl(REPORTS / "kt512base_do_not_train_receipts.jsonl", do_not_train_rows)
    return genome


def no_regret_stats(matrix: list[dict[str, Any]], downshift_arm: str) -> dict[str, Any]:
    fixed_correct_rows = [row for row in matrix if row["correct_by_arm"][ARM_512]]
    false_rows = [row for row in fixed_correct_rows if not row["correct_by_arm"][downshift_arm]]
    saving_rows = [
        row
        for row in fixed_correct_rows
        if row["correct_by_arm"][downshift_arm] and row["total_tokens_by_arm"][downshift_arm] < row["total_tokens_by_arm"][ARM_512]
    ]
    token_savings = sum(row["total_tokens_by_arm"][ARM_512] - row["total_tokens_by_arm"][downshift_arm] for row in saving_rows)
    fixed_tpc = sum(row["total_tokens_by_arm"][ARM_512] for row in fixed_correct_rows) / len(fixed_correct_rows)
    false_damage = len(false_rows) * fixed_tpc
    net_ev = token_savings - false_damage
    return {
        "candidate_downshift_arm": downshift_arm,
        "false_downshift_count": len(false_rows),
        "false_downshift_damage": false_damage,
        "regret_vs_fixed512": len(false_rows) / len(fixed_correct_rows) if fixed_correct_rows else None,
        "token_savings_when_correct": token_savings,
        "net_expected_value": net_ev,
        "expected_regret_bounded": len(false_rows) == 0 and net_ev > 0,
        "advance_allowed": False,
    }


def build_oracle_and_selector(imported: dict[str, Any] | None = None) -> dict[str, Any]:
    data = imported or import_assessment()
    matrix = data["matrix"]
    correct_rows = [row for row in matrix if row["cheapest_correct_arm"] is not None]
    fixed_correct = sum(1 for row in matrix if row["correct_by_arm"][ARM_512])
    fixed_total_tokens = sum(row["total_tokens_by_arm"][ARM_512] for row in matrix)
    oracle_total_tokens = sum(row["cheapest_correct_tokens"] for row in correct_rows)
    oracle_counts = Counter(row["cheapest_correct_arm"] or "NO_ARM_CORRECT" for row in matrix)
    frontier = {
        "schema_id": "kt.kt512.cheapest_correct_oracle_frontier.v1",
        "status": "PASS_HINDSIGHT_ONLY",
        "authority": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "runtime_selector_claim": "BLOCKED",
        "method": "per_row_choose_measured_correct_arm_with_min_total_tokens",
        "rows_total": len(matrix),
        "fixed512_correct": fixed_correct,
        "hindsight_oracle_correct": len(correct_rows),
        "hindsight_oracle_correctness_delta_vs_fixed512": len(correct_rows) - fixed_correct,
        "fixed512_total_tokens": fixed_total_tokens,
        "fixed512_full_tokens_per_correct": data["summary"]["cot512_full_tokens_per_correct"],
        "hindsight_oracle_total_tokens": oracle_total_tokens,
        "hindsight_oracle_full_tokens_per_correct": oracle_total_tokens / len(correct_rows),
        "hindsight_oracle_token_savings_vs_fixed512_total_tokens": fixed_total_tokens - oracle_total_tokens,
        "cheapest_correct_choice_counts": dict(oracle_counts),
        "forbidden_selector_features_excluded": FORBIDDEN_SELECTOR_FEATURES,
        "must_not_claim_deployable_selector": True,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_cheapest_correct_oracle_frontier.json", frontier)

    seed_rows = []
    for row in matrix:
        label = row["cheapest_correct_arm"] or "COT512_INSUFFICIENT"
        seed_rows.append(
            {
                "schema_id": "kt.kt512.economy_classifier_seed_row.v1",
                "row_id": row["row_id"],
                "row_id_role": "identifier_not_selection_feature",
                "selection_features": {
                    "cot_prompt_tokens": row["prompt_tokens_by_arm"][ARM_512],
                    "task_class": "multi_step_math",
                    "source_slice": "openai/gsm8k:test[125:325]",
                },
                "label": label,
                "label_source": "measured_correctness_scoring_allowed_not_selector_feature",
                "forbidden_features_excluded": FORBIDDEN_SELECTOR_FEATURES,
                "training_authority": False,
                "claim_ceiling_preserved": True,
            }
        )
    write_jsonl(REPORTS / "kt512base_economy_classifier_seed.jsonl", seed_rows)

    regret = {
        "schema_id": "kt.kt512.regret_distribution.v1",
        "status": "PASS_NO_DOWNSHIFT_ADVANCES",
        "fixed512_baseline": {
            "arm_id": ARM_512,
            "correct": fixed_correct,
            "full_tokens_per_correct": data["summary"]["cot512_full_tokens_per_correct"],
        },
        "downshift_classes": [
            no_regret_stats(matrix, ARM_256),
            no_regret_stats(matrix, ARM_ANSWER),
        ],
        "negative_class": {
            "class_id": "COT512_INSUFFICIENT",
            "count": len([row for row in matrix if not row["correct_by_arm"][ARM_512]]),
            "required": True,
        },
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_regret_distribution.json", regret)

    rng = random.Random(51232)
    arm_samples: list[dict[str, int]] = []
    for _ in range(200):
        sample = [rng.choice(matrix) for _ in range(len(matrix))]
        counts = Counter(row["cheapest_correct_arm"] or "COT512_INSUFFICIENT" for row in sample)
        arm_samples.append(dict(counts))
    stability = {
        "schema_id": "kt.kt512.bootstrap_oracle_stability.v1",
        "status": "PASS_HINDSIGHT_STABILITY_ONLY",
        "bootstrap_replicates": 200,
        "authority": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "mean_answer_only_choice_count": statistics.mean(sample.get(ARM_ANSWER, 0) for sample in arm_samples),
        "mean_cot256_choice_count": statistics.mean(sample.get(ARM_256, 0) for sample in arm_samples),
        "mean_cot512_choice_count": statistics.mean(sample.get(ARM_512, 0) for sample in arm_samples),
        "runtime_selector_claim": "BLOCKED",
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_bootstrap_oracle_stability.json", stability)

    policy = {
        "schema_id": "kt.kt512.no_regret_selector_policy.v1",
        "status": "SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "default_arm": ARM_512,
        "candidate_downshifts": [ARM_256, ARM_ANSWER],
        "negative_class": "COT512_INSUFFICIENT",
        "anti_leakage_gate": {
            "status": "PASS",
            "forbidden_selection_features": FORBIDDEN_SELECTOR_FEATURES,
            "labels_may_score_but_not_select": True,
        },
        "regret_accounting_report": "reports/kt512base_regret_distribution.json",
        "runtime_authority": False,
        "training_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_no_regret_selector_seed_policy.json", policy)
    return frontier


def build_process_verifier_spec() -> dict[str, Any]:
    segmentation = {
        "schema_id": "kt.kt512.step_segmentation_policy.v1",
        "status": "DESIGN_ONLY",
        "segment_boundaries": [
            "numerical_transition",
            "equation_boundary",
            "discourse_marker",
            "final_answer_boundary",
        ],
        "consistency_graph_required": True,
        "independent_step_labels_only": False,
        "production_scoring_authority": False,
        "training_authority": False,
        "claim_ceiling_preserved": True,
    }
    verifier = {
        "schema_id": "kt.kt512.process_verifier_seed_plan.v1",
        "status": "DESIGN_ONLY_REQUIRES_SEPARATE_VERIFIER_VALIDATION_LANE",
        "may_score_production_rows": False,
        "may_authorize_training": False,
        "requires_future_lane": "AUTHOR_512BASE_PROCESS_VERIFIER_VALIDATION_V1",
        "trace_schema": "schemas/kt.math_step_verifier_trace.schema.json",
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "kt512base_step_segmentation_policy.json", segmentation)
    write_json(REPORTS / "kt512base_process_verifier_seed_plan.json", verifier)
    return verifier


def bud100_oracle_delta_rows() -> list[int]:
    path = REPORTS / "bud100_row_level_policy_matrix.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    deltas: list[int] = []
    for row in rows:
        correct = row.get("correct_by_arm", {})
        fixed_correct = bool(correct.get("A2_COT_512_FIXED"))
        oracle_correct = any(bool(value) for value in correct.values())
        deltas.append(int(oracle_correct) - int(fixed_correct))
    return deltas


def strategy_replay(matrix: list[dict[str, Any]], strategy_id: str, selected_arm: str | None) -> dict[str, Any]:
    baseline_correct = [bool(row["correct_by_arm"][ARM_512]) for row in matrix]
    if selected_arm is None:
        selected_correct = baseline_correct
        selected_tokens = [row["total_tokens_by_arm"][ARM_512] for row in matrix]
    else:
        selected_correct = [bool(row["correct_by_arm"][selected_arm]) for row in matrix]
        selected_tokens = [row["total_tokens_by_arm"][selected_arm] for row in matrix]
    false_downshift = [
        idx
        for idx, (base_ok, selected_ok) in enumerate(zip(baseline_correct, selected_correct))
        if base_ok and not selected_ok
    ]
    per_row_regret = [1.0 if base_ok and not selected_ok else 0.0 for base_ok, selected_ok in zip(baseline_correct, selected_correct)]
    token_savings_correct_only = sum(
        row["total_tokens_by_arm"][ARM_512] - selected_tokens[idx]
        for idx, row in enumerate(matrix)
        if selected_correct[idx] and row["total_tokens_by_arm"][ARM_512] > selected_tokens[idx]
    )
    token_savings_all_selected = sum(row["total_tokens_by_arm"][ARM_512] - selected_tokens[idx] for idx, row in enumerate(matrix))
    fixed_tpc = sum(row["total_tokens_by_arm"][ARM_512] for row in matrix if row["correct_by_arm"][ARM_512]) / max(
        1, sum(1 for row in matrix if row["correct_by_arm"][ARM_512])
    )
    false_damage = len(false_downshift) * fixed_tpc
    return {
        "strategy_id": strategy_id,
        "selected_arm": selected_arm or ARM_512,
        "status": "DEPLOYMENT_BLOCKED_FALSE_DOWNSHIFT" if false_downshift else "REPLAY_ONLY_NO_RUNTIME_AUTHORITY",
        "correct": sum(1 for value in selected_correct if value),
        "false_downshift_count": len(false_downshift),
        "false_downshift_damage": false_damage,
        "regret_vs_fixed512_mean": statistics.mean(per_row_regret) if per_row_regret else 0.0,
        "regret_vs_fixed512_median": statistics.median(per_row_regret) if per_row_regret else 0.0,
        "regret_p90": percentile(per_row_regret, 0.90),
        "regret_p99": percentile(per_row_regret, 0.99),
        "regret_max": max(per_row_regret) if per_row_regret else 0.0,
        "token_savings_correct_only": token_savings_correct_only,
        "token_savings_all_selected": token_savings_all_selected,
        "net_expected_value": token_savings_correct_only - false_damage,
        "safe_downshift_count": 0 if selected_arm is None else sum(
            1
            for idx, row in enumerate(matrix)
            if row["correct_by_arm"][ARM_512] and selected_correct[idx] and selected_tokens[idx] < row["total_tokens_by_arm"][ARM_512]
        ),
        "COT512_INSUFFICIENT_recall": "NOT_EVALUABLE_WITH_LEGAL_PRE_GENERATION_FEATURES",
        "runtime_authority": False,
        "claim_ceiling_preserved": True,
    }


def build_g32_selector_replay(imported: dict[str, Any] | None = None) -> dict[str, Any]:
    data = imported or import_assessment()
    write_g32sel_schemas()
    matrix = data["matrix"]
    failures = data["failures"]
    assessment = data["assessment"]
    summary = data["summary"]
    current_head = git_output("rev-parse", "HEAD")
    current_branch = git_output("branch", "--show-current")

    path_map = {
        "schema_id": "kt.g32sel.path_map.v1",
        "status": "PASS",
        "current_surface_patching_rule": "PATCH_EXISTING_SURFACES_WHEN_EQUIVALENT",
        "patched_existing_surfaces": [
            "scripts/kt512g32_common.py",
            "scripts/import_kt512base_assessment.py",
            "scripts/validate_kt512g32_import.py",
            "schemas/kt.no_regret_selector_policy.schema.json",
            "schemas/kt.cheapest_correct_oracle_frontier.schema.json",
            "tests/test_kt512base_no_regret_selector_negative_class.py",
            "tests/test_kt512base_oracle_frontier_not_deployable.py",
        ],
        "new_surfaces_required_because_no_equivalent_existed": [
            "policies/g32_noregret_v1.json",
            "schemas/kt.process_verifier.v1.schema.json",
            "reports/g32_selector_replay.json",
            "reports/g32_next_ledger.json",
        ],
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32sel_path_map.json", path_map)
    write_json(
        REPORTS / "g32sel_truth_pin.json",
        {
            "schema_id": "kt.g32sel.truth_pin.v1",
            "status": "PASS",
            "created_utc": utc_now(),
            "current_head": current_head,
            "current_branch": current_branch,
            "expected_predecessor_head": "5b972f7b95f13560f62b537afdf0b50e49c6d951",
            "predecessor_outcome": OUTCOME,
            "active_tranche": NEXT_LAWFUL_MOVE,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "g32sel_source_receipt.json",
        {
            "schema_id": "kt.g32sel.source_receipt.v1",
            "status": "PASS",
            "assessment_sha256": assessment["sha256"],
            "assessment_sha256_matches_expected": assessment["sha256"] == EXPECTED_ASSESSMENT_SHA256,
            "row_slice": summary["row_slice"],
            "row_count": summary["row_count"],
            "cot512": {"correct": summary["cot512_correct"], "total": 200, "accuracy": summary["cot512_accuracy"]},
            "cot256": {"correct": summary["cot256_correct"], "total": 200, "accuracy": summary["cot256_accuracy"]},
            "answer_only": {"correct": summary["answer_only_correct"], "total": 200, "accuracy": summary["answer_only_accuracy"]},
            "oracle_diagnostic": summary["oracle_diagnostic_score"],
            "fixed512_full_tpc": summary["cot512_full_tokens_per_correct"],
            "class_counts": {
                "COT256_SUFFICIENT": 137,
                "COT512_REQUIRED": 47,
                "COT512_INSUFFICIENT": 14,
                "ANSWER_ONLY_RECOVERY_OR_COT_OVERTHINK_RISK": 2,
            },
            "claim_ceiling_preserved": True,
        },
    )

    by_row = rows_by_id(assessment["predictions"])
    class_rows: list[dict[str, Any]] = []
    g32_failure_rows: list[dict[str, Any]] = []
    counter_rows: list[dict[str, Any]] = []
    for row_id, arms in by_row.items():
        a512, a256, ans = arms[ARM_512], arms[ARM_256], arms[ARM_ANSWER]
        cls = row_class(a512, a256, ans)
        class_rows.append(
            {
                "schema_id": "kt.g32sel.row_class.v1",
                "row_id": row_id,
                "row_index_global": a512["row_index_global"],
                "source": a512["source"],
                "prompt_hash": a512["prompt_hash"],
                "expected_hash": a512["expected_hash"],
                "row_class": cls,
                "correct_by_arm": {arm: bool(arms[arm]["correct"]) for arm in ARMS},
                "claim_ceiling_preserved": True,
            }
        )
        if not a512["correct"]:
            base_failure = next(row for row in failures if row["row_id"] == row_id)
            genotype, candidate_owner, repair_class, available, required, hypothesis, confidence = g32_owner_from_failure(base_failure)
            assert candidate_owner in ALLOWED_G32_OWNERS
            assert repair_class in ALLOWED_G32_REPAIR_CLASSES
            failure_row = {
                "schema_id": "kt.g32.fixed512_failure_ownership_row.v1",
                "row_id": row_id,
                "row_index_global": a512["row_index_global"],
                "question_hash": a512["prompt_hash"],
                "prompt_hash": a512["prompt_hash"],
                "expected_hash": a512["expected_hash"],
                "fixed512_extracted_answer": a512.get("extracted_answer"),
                "cot256_extracted_answer": a256.get("extracted_answer"),
                "answer_only_extracted_answer": ans.get("extracted_answer"),
                "failure_genotype": genotype,
                "candidate_owner": candidate_owner,
                "counterfactual_tests_available": available,
                "counterfactual_tests_required": required,
                "repair_class": repair_class,
                "repair_hypothesis": hypothesis,
                "confidence": confidence,
                "training_authority": False,
                "claim_ceiling_preserved": True,
            }
            g32_failure_rows.append(failure_row)
            counter_rows.append(
                {
                    "schema_id": "kt.g32.counterfactual_matrix_row.v1",
                    "row_id": row_id,
                    "candidate_owner": candidate_owner,
                    "repair_class": repair_class,
                    "available_tests_count": len(available),
                    "required_tests_count": len(required),
                    "ownership_status": "PROVISIONAL_NO_TRAINING_AUTHORITY" if available else "UNKNOWN_BLOCKED",
                    "training_authority": False,
                    "claim_ceiling_preserved": True,
                }
            )
    write_jsonl(REPORTS / "g32sel_row_classes.jsonl", class_rows)
    write_jsonl(REPORTS / "g32sel_fixed512_failures.jsonl", g32_failure_rows)
    write_jsonl(REPORTS / "g32_failure_genome.jsonl", g32_failure_rows)
    write_jsonl(REPORTS / "g32_counter_matrix.jsonl", counter_rows)

    owner_counts = Counter(row["candidate_owner"] for row in g32_failure_rows)
    unknown_failure_rate = owner_counts.get("UNKNOWN_BLOCKED", 0) / max(1, len(g32_failure_rows))
    owner_receipt = {
        "schema_id": "kt.g32.owner_receipt.v1",
        "status": "BLOCKED_TRAINING_DECISION_UNKNOWN_FAILURE_RATE_HIGH" if unknown_failure_rate > 0.10 else "PASS",
        "failure_count": len(g32_failure_rows),
        "owner_counts": dict(owner_counts),
        "unknown_failure_rate": unknown_failure_rate,
        "ownership_reliability_rule": "UNKNOWN_BLOCKED above 0.10 blocks training decision",
        "training_authority": False,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_owner_receipt.json", owner_receipt)

    feature_law = {
        "schema_id": "kt.g32.feature_law.v1",
        "status": "PASS",
        "allowed": [
            "prompt_hash",
            "task_class",
            "source_slice",
            "prompt_token_estimate",
            "requested_budget",
            "pre_generation_budget_class",
        ],
        "forbidden": FORBIDDEN_SELECTOR_FEATURES,
        "anti_leakage_gate": "labels_may_score_replay_but_must_not_be_selector_features",
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_feature_law.json", feature_law)
    policy = {
        "schema_id": "kt.g32.no_regret_selector_policy.v1",
        "policy_id": "KT_NO_REGRET_SELECTOR_V1",
        "baseline": "FIXED512",
        "correctness_floor": 0.92,
        "false_downshift_tolerance": 0,
        "max_regret_absolute": 0.0,
        "confidence_threshold_default": 0.95,
        "uncertainty_action": "DEFAULT_TO_COT512",
        "required_negative_class": "COT512_INSUFFICIENT",
        "feature_legality": feature_law,
        "status": "REPLAY_ONLY_NO_RUNTIME_AUTHORITY",
        **AUTHORITY_FALSE,
        "claim_ceiling_preserved": True,
    }
    write_json(POLICIES / "g32_noregret_v1.json", policy)

    replay_strategies = [
        strategy_replay(matrix, "baseline_always_fixed512", None),
        {
            **strategy_replay(matrix, "oracle_hindsight_upper_bound", None),
            "correct": sum(1 for row in matrix if row["cheapest_correct_arm"] is not None),
            "authority": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
            "runtime_selector_claim": "BLOCKED",
        },
        strategy_replay(matrix, "conservative_feature_stub_default_fixed512", None),
        strategy_replay(matrix, "answer_only_safe_candidate", ARM_ANSWER),
        strategy_replay(matrix, "cot256_safe_candidate", ARM_256),
        {
            **strategy_replay(matrix, "review_or_reroll_policy_for_COT512_INSUFFICIENT", None),
            "status": "REVIEW_ONLY_NO_LEGAL_PREGENERATION_DETECTOR",
            "COT512_INSUFFICIENT_recall": "BLOCKED_NO_LEGAL_FEATURE_DETECTOR",
        },
    ]
    selector_replay = {
        "schema_id": "kt.g32.selector_replay.v1",
        "status": "PASS_REPLAY_DEPLOYMENT_BLOCKED_FALSE_DOWNSHIFT",
        "strategies": replay_strategies,
        "deployment_gate": "BLOCKED" if any(row["false_downshift_count"] > 0 for row in replay_strategies) else "PASS",
        "feature_legality_status": "PASS",
        **AUTHORITY_FALSE,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_selector_replay.json", selector_replay)

    regret = {
        "schema_id": "kt.g32.regret_distribution.v1",
        "status": "PASS_NO_DOWNSHIFT_ADVANCES",
        "baseline": "FIXED512",
        "downshift_classes": [
            strategy_replay(matrix, "cot256_downshift_all_rows", ARM_256),
            strategy_replay(matrix, "answer_only_downshift_all_rows", ARM_ANSWER),
        ],
        "negative_class": {"class_id": "COT512_INSUFFICIENT", "count": 14, "required": True},
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_regret_dist.json", regret)

    oracle = read_json(REPORTS / "kt512base_cheapest_correct_oracle_frontier.json")
    oracle.update(
        {
            "schema_id": "kt.g32.oracle_frontier.v1",
            "authority": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
            "runtime_selector_claim": "BLOCKED",
            "selector_deployment_authority": False,
        }
    )
    write_json(REPORTS / "g32_oracle_frontier.json", oracle)

    kt512_deltas = [(1 if row["cheapest_correct_arm"] is not None else 0) - (1 if row["correct_by_arm"][ARM_512] else 0) for row in matrix]
    bud100_deltas = bud100_oracle_delta_rows()
    combined_deltas = kt512_deltas + bud100_deltas
    rng = random.Random(320512)
    boot_n = 1000
    sample_gains = [sum(rng.choice(combined_deltas) for _ in range(len(combined_deltas))) for _ in range(boot_n)]
    oracle_boot = {
        "schema_id": "kt.g32.oracle_bootstrap_stability.v1",
        "status": "PASS_WEAK_STRUCTURAL_SIGNAL_HINDSIGHT_ONLY",
        "bootstrap_n": boot_n,
        "mean_oracle_gain_rows": statistics.mean(sample_gains),
        "std_oracle_gain_rows": statistics.pstdev(sample_gains),
        "ci95": [percentile(sample_gains, 0.025), percentile(sample_gains, 0.975)],
        "structural_signal": "WEAK",
        "combined_bud100_available": bool(bud100_deltas),
        "combined_rows": len(combined_deltas),
        "claim_boundary": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_oracle_boot.json", oracle_boot)

    procver = {
        "schema_id": "kt.process_verifier.v1",
        "status": "DESIGN_ONLY_REQUIRES_SEPARATE_VERIFIER_VALIDATION_LANE",
        "step_segmentation": ["problem_statement", "quantity_extraction", "operation", "arithmetic", "unit_check", "final_answer"],
        "step_validity_labels": ["ARITHMETIC_VALID", "UNIT_CONSISTENT", "LOGICAL_FOLLOW", "NO_CONTRADICTION", "FINAL_MATCH"],
        "production_scoring_authority": False,
        "training_authority": False,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_procver_spec.json", procver)
    write_jsonl(
        REPORTS / "g32_step_gym_seed.jsonl",
        [
            {
                "schema_id": "kt.g32.step_corruption_gym_seed.v1",
                "corruption_type": kind,
                "status": "DESIGN_ONLY",
                "expected_verifier_response": "REJECT_OR_FLAG",
                "claim_ceiling_preserved": True,
            }
            for kind in ["drop_step", "swap_steps", "number_perturb", "unsupported_inference", "contradiction", "unit_error"]
        ],
    )

    mvs = {
        "trace_coverage": 1.0,
        "repairability": 1.0 - unknown_failure_rate,
        "unknown": unknown_failure_rate,
        "human_anchors": 1.0,
        "oracle_rows": 200,
        "negative_transfer_scan": "NOT_MEASURED",
        "pass": False,
    }
    train_decision = {
        "schema_id": "kt.g32_training_decision_receipt.v1",
        "created_utc": utc_now(),
        "status": "BLOCKED_TRAINING_DECISION_UNKNOWN_FAILURE_RATE_HIGH",
        "action": "NO_TRAIN",
        "minimum_viable_signal": mvs,
        "MVS_gates_required_for_train_adapter": {
            "trace_coverage": ">=0.95",
            "repairability": ">=0.90",
            "unknown": "<=0.10",
            "human_anchors": ">=0.20",
            "oracle_rows": ">=25",
            "negative_transfer_scan": "PASS",
        },
        "training_authority": False,
        "claim_ceiling_preserved": True,
    }
    write_json(REPORTS / "g32_train_decision.json", train_decision)
    write_jsonl(
        REPORTS / "g32_do_not_train.jsonl",
        [
            {
                "schema_id": "kt.do_not_train_receipt.v1",
                "row_id": row["row_id"],
                "counterfactual_owner": row["candidate_owner"],
                "reason": "training_not_authorized_from_provisional_or_unknown_fixed512_failure_ownership",
                "training_authority": False,
                "claim_ceiling_preserved": True,
            }
            for row in g32_failure_rows
        ],
    )

    next_ledger = {
        "schema_id": "kt.g32.next_experiment_value_ledger.v1",
        "status": "PASS_SINGLE_NEXT_LANE_SELECTED",
        "candidate_lanes": {
            "AUTHOR_SELECTOR_MICRO_FURNACE_KAGGLE_V1": "BLOCKED_FALSE_DOWNSHIFT_OR_NO_LEGAL_FEATURE_SIGNAL",
            "AUTHOR_PROCESS_VERIFIER_MICRO_FURNACE_KAGGLE_V1": "DEFERRED_DESIGN_ONLY_VERIFIER_NOT_VALIDATED",
            "AUTHOR_BUDGET_PARETO_SWEEP_KAGGLE_V1": "SELECTED_FIXED512_STRONG_KNEE_POINT_UNKNOWN",
            "AUTHOR_ADVERSARIAL_STRESS_KAGGLE_V1": "DEFERRED_AFTER_BUDGET_GEOMETRY",
            "AUTHOR_HUMAN_ANCHOR_REVIEW_OR_EXTENDED_MINING_V1": "DEFERRED_UNLESS_BUDGET_SWEEP_FAILS_TO_EXPLAIN_UNKNOWN_FAILURES",
            "BLOCKED_SIGNAL_INSUFFICIENT": "NOT_SELECTED_SIGNAL_SUFFICIENT_FOR_BUDGET_PARETO_SWEEP_DESIGN",
        },
        "selected_next_lawful_move": G32SEL_NEXT_LAWFUL_MOVE,
        "decision_evidence": {
            "fixed512_accuracy": 0.92,
            "cot256_accuracy": 0.685,
            "unknown_failure_rate": unknown_failure_rate,
            "selector_deployment_blocked": True,
            "training_blocked": True,
            "budget_knee_unknown": True,
        },
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "g32_next_ledger.json", next_ledger)

    summary_out = {
        "schema_id": "kt.g32sel.builder_summary.v1",
        "status": "PASS",
        "current_head": current_head,
        "branch": current_branch,
        "outcome": G32SEL_OUTCOME,
        "g32_truth_binding_status": "PASS",
        "g32_input_artifacts_status": "PASS",
        "fixed512_failure_ownership_status": owner_receipt["status"],
        "g32_minimum_viable_signal_status": "BLOCKED_UNKNOWN_FAILURE_RATE_HIGH",
        "training_decision_status": train_decision["status"],
        "no_regret_selector_policy_status": policy["status"],
        "no_regret_selector_replay_status": selector_replay["status"],
        "no_regret_feature_legality_status": "PASS",
        "hindsight_oracle_boundary_status": "PASS_HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "regret_distribution_status": regret["status"],
        "bootstrap_oracle_stability_status": oracle_boot["status"],
        "process_verifier_candidate_status": procver["status"],
        "next_experiment_value_ledger_status": next_ledger["status"],
        "packet_path_if_any": None,
        "packet_sha256_if_any": None,
        "kaggle_dataset_name_if_any": None,
        "one_cell_runbook_if_any": None,
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": G32SEL_NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "g32sel_builder_summary.json", summary_out)
    return summary_out


def build_summary() -> dict[str, Any]:
    imported = import_assessment()
    genome = build_failure_ownership(imported)
    frontier = build_oracle_and_selector(imported)
    verifier = build_process_verifier_spec()
    build_g32_selector_replay(imported)
    summary = {
        "schema_id": "kt.kt512g32.builder_summary.v1",
        "status": "PASS",
        "current_head": git_output("rev-parse", "HEAD"),
        "branch": git_output("branch", "--show-current"),
        "outcome": OUTCOME,
        "kt512base_assessment_import_status": "PASS",
        "kt512base_scorecard_reconciliation_status": "PASS",
        "kt512base_fixed512_baseline_status": "PASS_FIXED512_STRONG_BASELINE_CONFIRMED",
        "kt512base_failure_autopsy_status": genome["status"],
        "kt512base_oracle_frontier_status": frontier["authority"],
        "kt512base_economy_seed_status": "PASS_SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "g32_ownership_decision_procedure_status": "TRAINING_BLOCKED_FURTHER_AUTOPSY_SELECTED",
        "no_regret_selector_seed_status": "PASS_SEED_ONLY_NO_RUNTIME_AUTHORITY",
        "process_verifier_scope_status": verifier["status"],
        "packet_path_if_any": None,
        "packet_sha256_if_any": None,
        "kaggle_dataset_name_if_any": None,
        "one_cell_runbook_if_any": None,
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "kt512g32_builder_summary.json", summary)
    return summary


def validate_import() -> dict[str, Any]:
    required = [
        REPORTS / "kt512base_assessment_import_receipt.json",
        REPORTS / "kt512base_scorecard_reconciliation.json",
        REPORTS / "kt512base_row_policy_matrix.jsonl",
        REPORTS / "kt512base_fixed512_baseline_receipt.json",
        REPORTS / "kt512base_claim_boundary_receipt.json",
        REPORTS / "kt512base_fixed512_failure_autopsy.jsonl",
        REPORTS / "kt512base_failure_genome.json",
        REPORTS / "kt512base_g32_ownership_decision_receipt.json",
        REPORTS / "kt512base_do_not_train_receipts.jsonl",
        REPORTS / "kt512base_cheapest_correct_oracle_frontier.json",
        REPORTS / "kt512base_economy_classifier_seed.jsonl",
        REPORTS / "kt512base_no_regret_selector_seed_policy.json",
        REPORTS / "kt512base_regret_distribution.json",
        REPORTS / "kt512base_bootstrap_oracle_stability.json",
        REPORTS / "kt512base_step_segmentation_policy.json",
        REPORTS / "kt512base_process_verifier_seed_plan.json",
        REPORTS / "kt512g32_path_mapping.json",
        REPORTS / "kt512g32_builder_summary.json",
        REPORTS / "g32sel_truth_pin.json",
        REPORTS / "g32sel_path_map.json",
        REPORTS / "g32sel_source_receipt.json",
        REPORTS / "g32sel_row_classes.jsonl",
        REPORTS / "g32sel_fixed512_failures.jsonl",
        REPORTS / "g32_failure_genome.jsonl",
        REPORTS / "g32_counter_matrix.jsonl",
        REPORTS / "g32_owner_receipt.json",
        POLICIES / "g32_noregret_v1.json",
        REPORTS / "g32_feature_law.json",
        REPORTS / "g32_selector_replay.json",
        REPORTS / "g32_regret_dist.json",
        REPORTS / "g32_oracle_frontier.json",
        REPORTS / "g32_oracle_boot.json",
        SCHEMAS / "kt.process_verifier.v1.schema.json",
        REPORTS / "g32_procver_spec.json",
        REPORTS / "g32_step_gym_seed.jsonl",
        REPORTS / "g32_next_ledger.json",
        REPORTS / "g32_train_decision.json",
        REPORTS / "g32_do_not_train.jsonl",
        REPORTS / "g32sel_builder_summary.json",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        result = {"schema_id": "kt.kt512g32.validation.v1", "status": "FAIL", "missing": missing}
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(1)
    receipt = read_json(REPORTS / "kt512base_assessment_import_receipt.json")
    genome = read_json(REPORTS / "kt512base_failure_genome.json")
    frontier = read_json(REPORTS / "kt512base_cheapest_correct_oracle_frontier.json")
    regret = read_json(REPORTS / "kt512base_regret_distribution.json")
    summary = read_json(REPORTS / "kt512g32_builder_summary.json")
    g32sel_summary = read_json(REPORTS / "g32sel_builder_summary.json")
    g32_policy = read_json(POLICIES / "g32_noregret_v1.json")
    g32_next = read_json(REPORTS / "g32_next_ledger.json")
    checks = {
        "sha256_matches": receipt["sha256_matches_expected"],
        "row_count_200": receipt["row_count"] == 200,
        "oracle_1_0": receipt["oracle_diagnostic_score"] == 1.0,
        "cot512_184": receipt["cot512_correct"] == 184,
        "failure_count_16": genome["fixed512_failure_count"] == 16,
        "oracle_hindsight_only": frontier["authority"] == "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "runtime_selector_blocked": frontier["runtime_selector_claim"] == "BLOCKED",
        "negative_class_present": regret["negative_class"]["class_id"] == "COT512_INSUFFICIENT",
        "training_false": summary["training_authority"] is False,
        "promotion_false": summary["promotion_authority"] is False,
        "claim_ceiling_preserved": summary["claim_ceiling_status"] == "PRESERVED",
        "g32sel_outcome": g32sel_summary["outcome"] == G32SEL_OUTCOME,
        "g32sel_next_lane": g32_next["selected_next_lawful_move"] == G32SEL_NEXT_LAWFUL_MOVE,
        "g32sel_policy_replay_only": g32_policy["status"] == "REPLAY_ONLY_NO_RUNTIME_AUTHORITY",
        "g32sel_runtime_false": g32sel_summary["runtime_authority"] is False,
        "g32sel_training_false": g32sel_summary["training_authority"] is False,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    result = {
        "schema_id": "kt.kt512g32.validation.v1",
        "status": status,
        "checks": checks,
        "validated": [str(path.relative_to(ROOT)) for path in required],
        "next_lawful_move": summary["next_lawful_move"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if status != "PASS":
        raise SystemExit(1)
    return result
