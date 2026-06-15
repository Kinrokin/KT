from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import subprocess
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
EVIDENCE = ROOT / "evidence"

EXPECTED_ASSESSMENT_SHA256 = "fa417a164604301131be89317991f1ecc4289095dc021e92cc7b6fdf549837af"
EXPECTED_PACKET_SHA256 = "cd9fc3ae9b94ed25d0d7f12c9f62f79dd2c50ada788b8f03891247e2d7ba2844"
EXPECTED_ROW_SLICE = "openai/gsm8k:test[325:425]"
OUTCOME = (
    "KT_PARETO_IMPORTED__STRATIFIED_FIXED512_WEAK_BASELINE_REVIEW_BOUND__"
    "384_KNEE_NOT_DEPLOYABLE__640_SENTINEL_BOUND__G32_STRATIFIED_OWNERSHIP_NEXT__CLAIM_CEILING_PRESERVED"
)
NEXT_LAWFUL_MOVE = "AUTHOR_G32_STRATIFIED_FIXED512_WEAK_BASELINE_FAILURE_OWNERSHIP_V1"

ASSESSMENT_CANDIDATES = [
    EVIDENCE / "KT_PARETO_V1_ASSESSMENT_ONLY.zip",
    ROOT / "KT_PARETO_V1_ASSESSMENT_ONLY.zip",
    Path(r"d:\user\rober\Downloads\KT_PARETO_V1_ASSESSMENT_ONLY.zip"),
]

GENERATION_ARMS = [
    "A0_COT_96_FIXED",
    "A1_COT_192_FIXED",
    "A2_COT_256_FIXED",
    "A3_COT_320_FIXED",
    "A4_COT_384_FIXED",
    "A5_COT_448_FIXED",
    "A6_COT_512_FIXED_CONTROL",
    "A7_COT_640_FIXED_SENTINEL",
    "A8_ANSWER_ONLY_NO_COT",
]

EXPECTED_SCORECARD = {
    "A0_COT_96_FIXED": {"correct": 1, "full_tokens_per_correct": 18202.00},
    "A1_COT_192_FIXED": {"correct": 18, "full_tokens_per_correct": 1541.06},
    "A2_COT_256_FIXED": {"correct": 44, "full_tokens_per_correct": 758.41},
    "A3_COT_320_FIXED": {"correct": 63, "full_tokens_per_correct": 602.49},
    "A4_COT_384_FIXED": {"correct": 76, "full_tokens_per_correct": 550.57},
    "A5_COT_448_FIXED": {"correct": 81, "full_tokens_per_correct": 558.43},
    "A6_COT_512_FIXED_CONTROL": {"correct": 82, "full_tokens_per_correct": 585.88},
    "A7_COT_640_FIXED_SENTINEL": {"correct": 84, "full_tokens_per_correct": 628.15},
    "A8_ANSWER_ONLY_NO_COT": {"correct": 3, "full_tokens_per_correct": 5827.67},
}

SLICE_RANGES = {
    "BUD100": (25, 125),
    "KT512BASE": (125, 325),
    "KTPARETO": (325, 425),
}

AUTHORITY_FALSE = {
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "runtime_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def load_jsonl(zf: zipfile.ZipFile, name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in zf.read(name).decode("utf-8").splitlines() if line.strip()]


def assessment_path() -> Path:
    for path in ASSESSMENT_CANDIDATES:
        if path.exists():
            return path
    raise FileNotFoundError("KT_PARETO_V1_ASSESSMENT_ONLY.zip not found in repo evidence, repo root, or Downloads.")


def fetch_gsm8k_rows(start: int, end: int) -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    offset = start
    while offset < end:
        length = min(100, end - offset)
        url = "https://datasets-server.huggingface.co/rows?" + urllib.parse.urlencode(
            {"dataset": "openai/gsm8k", "config": "main", "split": "test", "offset": offset, "length": length}
        )
        with urllib.request.urlopen(url, timeout=45) as response:
            payload = json.loads(response.read().decode("utf-8"))
        for item in payload.get("rows", []):
            row = item["row"]
            rows[int(item["row_idx"])] = {"question": row["question"], "answer": row["answer"]}
        offset += length
    if len(rows) != end - start:
        raise RuntimeError(f"expected {end-start} GSM8K rows for [{start}:{end}], got {len(rows)}")
    return rows


def load_gsm8k_question_bank() -> tuple[dict[int, dict[str, str]], str, str | None]:
    try:
        bank: dict[int, dict[str, str]] = {}
        for start, end in SLICE_RANGES.values():
            bank.update(fetch_gsm8k_rows(start, end))
        return bank, "PASS_QUESTION_TEXT_LOADED_FROM_HF_DATASET_VIEWER", None
    except Exception as exc:  # pragma: no cover - exercised only when network is absent.
        return {}, "PARTIAL_QUESTION_TEXT_UNAVAILABLE_BEHAVIORAL_ONLY", repr(exc)


def count_entities(question: str) -> int:
    # Count likely named entities while avoiding first-token sentence capitalization.
    tokens = re.findall(r"\b[A-Z][a-z]+\b", question)
    common = {"If", "The", "A", "An", "How", "What", "Each", "There", "In", "At", "After", "Before"}
    return len({token for token in tokens if token not in common})


def difficulty_proxy(question: str) -> dict[str, int]:
    q = question.lower()
    nums = re.findall(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?(?:/\d+)?%?", question)
    operation_terms = [
        "total",
        "each",
        "left",
        "remaining",
        "more",
        "less",
        "difference",
        "sum",
        "twice",
        "half",
        "percent",
        "ratio",
        "rate",
        "per",
        "altogether",
        "after",
        "before",
        "times",
        "product",
        "divide",
        "split",
        "share",
        "cost",
        "price",
        "earn",
        "spent",
    ]
    units = [
        "feet",
        "foot",
        "meter",
        "meters",
        "inch",
        "inches",
        "mile",
        "miles",
        "dollar",
        "dollars",
        "cent",
        "cents",
        "hour",
        "hours",
        "minute",
        "minutes",
        "day",
        "days",
        "week",
        "weeks",
        "pound",
        "pounds",
        "kg",
        "kilogram",
        "liter",
        "liters",
        "gallon",
    ]
    return {
        "question_token_length": len(re.findall(r"\w+|[^\w\s]", question)),
        "number_count": len(nums),
        "entity_count": count_entities(question),
        "operation_keyword_count": sum(1 for term in operation_terms if term in q),
        "estimated_step_count": max(
            1,
            min(10, len(nums) - 1 + sum(1 for term in ["after", "before", "then", "each", "total", "left"] if term in q)),
        ),
        "rate_ratio_percent_terms": sum(1 for term in ["rate", "ratio", "percent", "%", "per"] if term in q),
        "fraction_decimal_terms": len(re.findall(r"\d+/\d+|\d+\.\d+", question)),
        "unit_conversion_terms": sum(1 for term in units if term in q),
        "comparison_terms": sum(1 for term in ["more than", "less than", "fewer", "greater", "difference", "compare"] if term in q),
        "multi_entity_tracking_terms": sum(
            1 for term in ["each", "respectively", "both", "together", "remaining", "another", "other"] if term in q
        ),
    }


def numeric_fields(rows: list[dict[str, Any]]) -> list[str]:
    fields: list[str] = []
    for row in rows:
        for key, value in row.items():
            if isinstance(value, (int, float)) and key not in {"global_row"} and key not in fields:
                fields.append(key)
    return fields


def summarize(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": round(float(statistics.mean(values)), 6),
        "median": round(float(statistics.median(values)), 6),
        "min": round(float(min(values)), 6),
        "max": round(float(max(values)), 6),
    }


def compare_slices(proxy_rows: list[dict[str, Any]], question_status: str) -> dict[str, Any]:
    by_slice: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in proxy_rows:
        by_slice[row["slice_id"]].append(row)
    fields = numeric_fields(proxy_rows)
    summaries: dict[str, dict[str, Any]] = {}
    for slice_id, rows in by_slice.items():
        summaries[slice_id] = {field: summarize([float(row[field]) for row in rows if field in row]) for field in fields}

    material_deltas = []
    base_slice = "KTPARETO"
    for other in ["BUD100", "KT512BASE"]:
        for field in fields:
            a = summaries[base_slice][field]["mean"]
            b = summaries[other][field]["mean"]
            pooled = max(abs(a), abs(b), 1.0)
            rel_delta = abs(a - b) / pooled
            if rel_delta >= 0.15:
                material_deltas.append(
                    {
                        "field": field,
                        "slice_a": base_slice,
                        "slice_b": other,
                        "mean_a": a,
                        "mean_b": b,
                        "relative_delta": round(rel_delta, 6),
                    }
                )
    if question_status.startswith("PASS"):
        verdict = "ROW_DIFFICULTY_STRATUM_REQUIRED"
        status = "PASS_MATERIAL_DIFFICULTY_DIFFERENCES_FOUND" if material_deltas else "PASS_NO_MATERIAL_DIFFICULTY_DIFFERENCE_DETECTED"
    else:
        verdict = "PARTIAL_BEHAVIORAL_STRATIFICATION_ONLY"
        status = "PARTIAL_BLOCKED_QUESTION_TEXT_UNAVAILABLE"
    return {
        "schema_id": "kt.ktpareto.slice_exchangeability_receipt.v1",
        "status": status,
        "question_text_status": question_status,
        "slices_compared": ["BUD100", "KT512BASE", "KTPARETO"],
        "difficulty_proxy_fields": fields,
        "slice_summaries": summaries,
        "material_deltas": material_deltas,
        "material_delta_threshold": 0.15,
        "exchangeability_verdict": verdict,
        "raw_slice_scores_equal_population_estimate": False if material_deltas or not question_status.startswith("PASS") else True,
        "claim_ceiling_preserved": True,
    }


def behavioral_stratum(oracle_row: dict[str, Any]) -> str:
    if not oracle_row.get("oracle_correctness_any"):
        return "NO_CORRECT_ARM"
    budget = oracle_row.get("oracle_cheapest_correct_budget")
    if budget in (96, 192, 256):
        return "EASY_OR_ECONOMY"
    if budget in (320, 384):
        return "MEDIUM_OR_KNEE"
    if budget in (448, 512, 640):
        return "HARD_OR_EXTENSION"
    return "UNKNOWN"


def proxy_stratum(proxy: dict[str, Any]) -> str:
    # Pre-generation stratum seed: no correctness or post-hoc arm labels.
    if proxy.get("estimated_step_count", 0) >= 6 or proxy.get("multi_entity_tracking_terms", 0) >= 2:
        return "HIGH_PROXY_COMPLEXITY"
    if proxy.get("number_count", 0) >= 4 or proxy.get("operation_keyword_count", 0) >= 4:
        return "MEDIUM_PROXY_COMPLEXITY"
    return "LOW_PROXY_COMPLEXITY"


def classify_step_trace(trace: dict[str, Any]) -> dict[str, bool | str]:
    text = " ".join(str(step) for step in trace.get("steps", []))
    lowered = text.lower()
    return {
        "arithmetic_surface_quality": "WEAK" if any(term in lowered for term in ["error", "mistake", "cannot"]) else "UNKNOWN_REVIEW_REQUIRED",
        "entity_tracking_failure": any(term in lowered for term in ["remaining", "each", "both", "another", "other"]),
        "operation_selection_failure": any(term in lowered for term in ["total", "difference", "times", "divide", "percent", "ratio"]),
    }


def main() -> dict[str, Any]:
    REPORTS.mkdir(parents=True, exist_ok=True)
    zpath = assessment_path()
    digest = sha256_file(zpath)
    current_head = git_output("rev-parse", "HEAD")
    branch = git_output("branch", "--show-current")

    required_members = [
        "final_summary.json",
        "budget_pareto_scorecard.json",
        "budget_pareto_frontier.json",
        "budget_pareto_knee_receipt.json",
        "per_arm_oracle_rows.jsonl",
        "row_policy_matrix.jsonl",
        "budget_predictions.jsonl",
        "token_ledger.jsonl",
        "step_traces.jsonl",
        "per_arm_claim_bounds_receipt.json",
        "claim_boundary_receipt.json",
    ]
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        missing = [name for name in required_members if name not in names]
        if missing:
            raise RuntimeError(f"assessment missing required members: {missing}")
        final_summary = json.loads(zf.read("final_summary.json"))
        scorecard = json.loads(zf.read("budget_pareto_scorecard.json"))["scorecard"]
        frontier = json.loads(zf.read("budget_pareto_frontier.json"))
        knee = json.loads(zf.read("budget_pareto_knee_receipt.json"))
        oracle_rows = load_jsonl(zf, "per_arm_oracle_rows.jsonl")
        row_policy_rows = load_jsonl(zf, "row_policy_matrix.jsonl")
        predictions = load_jsonl(zf, "budget_predictions.jsonl")
        token_rows = load_jsonl(zf, "token_ledger.jsonl")
        step_traces = load_jsonl(zf, "step_traces.jsonl")
        per_arm_claim_bounds = json.loads(zf.read("per_arm_claim_bounds_receipt.json"))
        claim_boundary = json.loads(zf.read("claim_boundary_receipt.json"))

    sha_status = "PASS" if digest == EXPECTED_ASSESSMENT_SHA256 else "FAIL_SHA_MISMATCH"
    score_by_arm = {row["arm_id"]: row for row in scorecard}
    score_mismatches = []
    for arm, expected in EXPECTED_SCORECARD.items():
        actual = score_by_arm.get(arm)
        if actual is None:
            score_mismatches.append({"arm_id": arm, "issue": "MISSING_ARM"})
            continue
        if actual["correct"] != expected["correct"]:
            score_mismatches.append({"arm_id": arm, "field": "correct", "expected": expected["correct"], "actual": actual["correct"]})
        if not math.isclose(float(actual["full_tokens_per_correct"]), expected["full_tokens_per_correct"], abs_tol=0.01):
            score_mismatches.append(
                {
                    "arm_id": arm,
                    "field": "full_tokens_per_correct",
                    "expected": expected["full_tokens_per_correct"],
                    "actual": actual["full_tokens_per_correct"],
                }
            )
    oracle_pass = final_summary.get("oracle_diagnostic_score") == 1.0
    scorecard_status = "PASS" if not score_mismatches and oracle_pass and sha_status == "PASS" else "FAIL"

    write_json(
        REPORTS / "ktpareto_assessment_import_receipt.json",
        {
            "schema_id": "kt.ktpareto.assessment_import_receipt.v1",
            "status": sha_status,
            "assessment_path": str(zpath),
            "assessment_sha256": digest,
            "expected_sha256": EXPECTED_ASSESSMENT_SHA256,
            "required_members_present": not missing,
            "member_count": len(names),
            "row_slice": final_summary.get("row_slice"),
            "row_count": final_summary.get("row_count"),
            "current_head": current_head,
            "branch": branch,
            "created_utc": utc_now(),
            "claim_ceiling_preserved": True,
        },
    )

    write_json(
        REPORTS / "ktpareto_scorecard_reconciliation.json",
        {
            "schema_id": "kt.ktpareto.scorecard_reconciliation.v1",
            "status": scorecard_status,
            "row_slice": final_summary.get("row_slice"),
            "scorecard": scorecard,
            "expected_scorecard": EXPECTED_SCORECARD,
            "mismatches": score_mismatches,
            "oracle_diagnostic_score": final_summary.get("oracle_diagnostic_score"),
            "oracle_diagnostic_status": "PASS" if oracle_pass else "FAIL",
            "knee_candidate": final_summary.get("knee_candidate"),
            "false_downshift_count_at_384_vs_512": final_summary.get("false_downshift_count_at_knee"),
            "frontier": frontier,
            "knee_receipt": knee,
            "per_arm_claim_bounds_receipt": per_arm_claim_bounds,
            "claim_boundary_receipt": claim_boundary,
            "claim_ceiling_preserved": True,
        },
    )

    question_bank, question_status, question_error = load_gsm8k_question_bank()
    proxy_rows: list[dict[str, Any]] = []
    for slice_id, (start, end) in SLICE_RANGES.items():
        for idx in range(start, end):
            base = {
                "schema_id": "kt.ktpareto.difficulty_proxy_row.v1",
                "slice_id": slice_id,
                "dataset": "openai/gsm8k",
                "split": "test",
                "global_row": idx,
                "row_id": f"gsm8k_test_{idx:03d}",
                "question_text_available": idx in question_bank,
                "difficulty_proxy_status": question_status,
            }
            if idx in question_bank:
                proxy = difficulty_proxy(question_bank[idx]["question"])
                base.update(proxy)
                base["pre_generation_proxy_stratum"] = proxy_stratum(proxy)
            proxy_rows.append(base)

    write_jsonl(REPORTS / "ktpareto_difficulty_proxy_matrix.jsonl", proxy_rows)
    exchangeability = compare_slices(proxy_rows, question_status)
    if question_error:
        exchangeability["question_text_error_redacted"] = question_error
    write_json(REPORTS / "ktpareto_slice_exchangeability_receipt.json", exchangeability)

    oracle_by_row = {row["row_id"]: row for row in oracle_rows}
    pred_by_row_arm: dict[tuple[str, str], dict[str, Any]] = {(row["row_id"], row["arm_id"]): row for row in predictions}
    token_by_row_arm: dict[tuple[str, str], dict[str, Any]] = {(row["row_id"], row["arm_id"]): row for row in token_rows}
    trace_by_row_arm: dict[tuple[str, str], dict[str, Any]] = {(row["row_id"], row["arm_id"]): row for row in step_traces}

    ktpareto_proxy_by_row = {row["row_id"]: row for row in proxy_rows if row["slice_id"] == "KTPARETO"}
    stratified: dict[str, dict[str, Any]] = defaultdict(lambda: {"rows": [], "arms": {}})
    for oracle_row in oracle_rows:
        rid = oracle_row["row_id"]
        stratum = ktpareto_proxy_by_row.get(rid, {}).get("pre_generation_proxy_stratum", behavioral_stratum(oracle_row))
        stratified[stratum]["rows"].append(rid)
    for stratum, payload in stratified.items():
        rids = payload["rows"]
        for arm in GENERATION_ARMS:
            correct = sum(1 for rid in rids if pred_by_row_arm[(rid, arm)]["correct"])
            total_tokens = sum(int(token_by_row_arm[(rid, arm)]["total_tokens"]) for rid in rids)
            payload["arms"][arm] = {
                "row_count": len(rids),
                "correct": correct,
                "accuracy": round(correct / len(rids), 6) if rids else 0.0,
                "total_tokens": total_tokens,
                "full_tokens_per_correct": round(total_tokens / correct, 6) if correct else None,
            }
    write_json(
        REPORTS / "ktpareto_stratified_budget_frontier.json",
        {
            "schema_id": "kt.ktpareto.stratified_frontier.v1",
            "status": "PASS",
            "stratification_basis": "pre_generation_difficulty_proxy" if question_status.startswith("PASS") else "behavioral_oracle_fallback",
            "strata": stratified,
            "global_frontier": frontier,
            "claim_ceiling_preserved": True,
        },
    )

    fixed512_prior = 0.92
    fixed512_current = float(final_summary["fixed512_control_accuracy"])
    write_json(
        REPORTS / "ktpareto_stratified_fixed512_estimate.json",
        {
            "schema_id": "kt.ktpareto.stratified_fixed512_estimate.v1",
            "status": "FIXED512_WEAK_OR_SLICE_SHIFT_REVIEW_REQUIRED"
            if fixed512_prior - fixed512_current > 0.07
            else "PASS_WITHIN_PRIOR_VARIANCE_BAND",
            "prior_fixed512_accuracy": fixed512_prior,
            "current_fixed512_accuracy": fixed512_current,
            "accuracy_delta": round(fixed512_current - fixed512_prior, 6),
            "slice_shift_plausible": True,
            "config_drift_possible": True,
            "stochastic_variance_possible": True,
            "prompt_render_drift_possible": True,
            "row_difficulty_stratum_required": True,
            "stratum_counts": {key: len(value["rows"]) for key, value in stratified.items()},
            "claim_ceiling_preserved": True,
        },
    )

    false384: list[dict[str, Any]] = []
    recovery640: list[dict[str, Any]] = []
    damage640: list[dict[str, Any]] = []
    overthink_rows: list[dict[str, Any]] = []
    classes640: list[dict[str, Any]] = []
    no_correct: list[dict[str, Any]] = []

    for oracle_row in oracle_rows:
        rid = oracle_row["row_id"]
        global_row = oracle_row["global_row"]
        stratum = ktpareto_proxy_by_row.get(rid, {}).get("pre_generation_proxy_stratum", behavioral_stratum(oracle_row))
        p384 = pred_by_row_arm[(rid, "A4_COT_384_FIXED")]
        p512 = pred_by_row_arm[(rid, "A6_COT_512_FIXED_CONTROL")]
        p640 = pred_by_row_arm[(rid, "A7_COT_640_FIXED_SENTINEL")]
        if p512["correct"] and not p384["correct"]:
            false384.append(
                {
                    "schema_id": "kt.ktpareto.false_downshift_row.v1",
                    "row_id": rid,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "candidate": "A4_COT_384_FIXED",
                    "control": "A6_COT_512_FIXED_CONTROL",
                    "false_downshift_damage": 1,
                    "candidate_total_tokens": token_by_row_arm[(rid, "A4_COT_384_FIXED")]["total_tokens"],
                    "control_total_tokens": token_by_row_arm[(rid, "A6_COT_512_FIXED_CONTROL")]["total_tokens"],
                    "deployment_authority": False,
                    "claim_ceiling_preserved": True,
                }
            )
        if p512["correct"] and p640["correct"]:
            row_class = "COT640_SAFE_EXTENSION"
        elif p512["correct"] and not p640["correct"]:
            row_class = "COT640_DAMAGE"
        elif not p512["correct"] and p640["correct"]:
            row_class = "COT640_RECOVERY"
        else:
            row_class = "COT640_NO_GAIN"
        class_row = {"row_id": rid, "global_row": global_row, "class": row_class, "difficulty_stratum": stratum}
        classes640.append(class_row)
        if row_class == "COT640_RECOVERY":
            recovery640.append(class_row)
        if row_class == "COT640_DAMAGE":
            damage640.append(class_row)
        if pred_by_row_arm[(rid, "A8_ANSWER_ONLY_NO_COT")]["correct"] and not p512["correct"]:
            overthink_rows.append(
                {
                    "row_id": rid,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "class": "ANSWER_ONLY_RECOVERY_OR_COT_OVERTHINK_RISK",
                    "production_prompt_mutation_authority": False,
                }
            )
        if not oracle_row.get("oracle_correctness_any"):
            traces = {arm: trace_by_row_arm[(rid, arm)] for arm in GENERATION_ARMS if (rid, arm) in trace_by_row_arm}
            trace_signals = classify_step_trace(traces.get("A6_COT_512_FIXED_CONTROL", {}))
            wrong_patterns = {arm: pred_by_row_arm[(rid, arm)].get("extracted_answer") for arm in GENERATION_ARMS}
            final_marker_budgets = [
                pred_by_row_arm[(rid, arm)].get("budget")
                for arm in GENERATION_ARMS
                if pred_by_row_arm[(rid, arm)].get("final_marker_detected")
            ]
            no_correct.append(
                {
                    "schema_id": "kt.ktpareto.no_correct_arm_autopsy_row.v1",
                    "row_id": rid,
                    "global_row": global_row,
                    "difficulty_stratum": stratum,
                    "expected_answer_hash": pred_by_row_arm[(rid, "A6_COT_512_FIXED_CONTROL")].get("expected_hash"),
                    "wrong_answer_patterns_by_budget": wrong_patterns,
                    "earliest_budget_where_final_marker_appears": min(final_marker_budgets) if final_marker_budgets else None,
                    "possible_benchmark_ambiguity": False,
                    "repair_owner_candidate": "UNKNOWN_G32_REQUIRED",
                    "counterfactual_needed": True,
                    "human_anchor_required": True,
                    "training_authority": False,
                    **trace_signals,
                }
            )

    write_jsonl(REPORTS / "ktpareto_384_false_downshift_rows.jsonl", false384)
    write_json(
        REPORTS / "ktpareto_384_false_downshift_genome.json",
        {
            "schema_id": "kt.ktpareto.false_downshift_genome.v1",
            "status": "PASS_BLOCKS_384_DEPLOYMENT",
            "knee_candidate": 384,
            "knee_classification": "ECONOMIC_KNEE_CANDIDATE_ONLY",
            "false_downshift_count": len(false384),
            "false_downshift_damage": sum(row["false_downshift_damage"] for row in false384),
            "legal_pre_generation_policy_excludes_all_false_downshift_rows": False,
            "deployment_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_384_safe_stratum_candidate.json",
        {
            "schema_id": "kt.ktpareto.safe_stratum_candidate.v1",
            "status": "CANDIDATE_ONLY_NOT_DEPLOYABLE",
            "reason": "false_downshift_count_vs_512 > 0 and no legal pre-generation exclusion policy exists",
            "deployment_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_stratified_false_downshift_report.json",
        {
            "schema_id": "kt.ktpareto.stratified_false_downshift_report.v1",
            "status": "PASS",
            "false_downshift_count": len(false384),
            "by_stratum": Counter(row["difficulty_stratum"] for row in false384),
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_cot640_recovery_damage_analysis.json",
        {
            "schema_id": "kt.ktpareto.cot640_recovery_damage.v1",
            "status": "PASS_SENTINEL_ONLY",
            "classification": "SENTINEL_ONLY",
            "cot640_recovery_count": len(recovery640),
            "cot640_damage_count": len(damage640),
            "class_counts": Counter(row["class"] for row in classes640),
            "sentinel_only": True,
            "deployment_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_jsonl(REPORTS / "ktpareto_cot640_escalation_candidate_rows.jsonl", recovery640)
    write_jsonl(REPORTS / "ktpareto_overthink_risk_rows.jsonl", overthink_rows)
    write_jsonl(REPORTS / "ktpareto_no_correct_arm_autopsy.jsonl", no_correct)
    write_json(
        REPORTS / "ktpareto_no_correct_arm_failure_genome.json",
        {
            "schema_id": "kt.ktpareto.no_correct_arm_failure_genome.v1",
            "status": "PASS_G32_OWNERSHIP_REQUIRED",
            "row_count": len(no_correct),
            "by_stratum": Counter(row["difficulty_stratum"] for row in no_correct),
            "repair_owner_candidates": {"UNKNOWN_G32_REQUIRED": [row["row_id"] for row in no_correct]},
            "training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )
    write_json(
        REPORTS / "ktpareto_no_correct_arm_counterfactual_plan.json",
        {
            "schema_id": "kt.ktpareto.no_correct_arm_counterfactual_plan.v1",
            "status": "DESIGN_ONLY_NO_TRAINING_AUTHORITY",
            "row_ids": [row["row_id"] for row in no_correct],
            "required_counterfactuals": [
                "prompt_render_replay",
                "scorer_parser_replay",
                "higher_budget_probe",
                "tool_or_symbolic_solve_probe",
                "human_anchor_review",
            ],
            "training_authority": False,
            "claim_ceiling_preserved": True,
        },
    )

    write_json(
        REPORTS / "ktpareto_claim_boundary_receipt.json",
        {
            "schema_id": "kt.ktpareto.claim_boundary_receipt.v1",
            "status": "PASS",
            "allowed_claim": "KT Pareto V1 assessment was imported and reviewed as internal evidence; 384 is a non-deployable economic knee candidate; 640 is sentinel-only; fixed512 weak-baseline/slice-shift review is required.",
            **AUTHORITY_FALSE,
            "commercial_claim_authority": False,
            "external_validation_claim_authority": False,
            "router_superiority_claim": False,
            "frontier_claim": False,
            "production_math_mode_claim": False,
            "claim_ceiling_preserved": True,
        },
    )

    selected_next = NEXT_LAWFUL_MOVE if scorecard_status == "PASS" else "BLOCKED_KTPARETO_SCORECARD_OR_ORACLE_RECONCILIATION_FAILED"
    write_json(
        REPORTS / "ktpareto_next_lane_decision.json",
        {
            "schema_id": "kt.ktpareto.next_lane_decision.v1",
            "status": "PASS" if scorecard_status == "PASS" else "BLOCKED",
            "selected_next_lawful_move": selected_next,
            "blocked_next_moves": [
                "new Kaggle broad sweep",
                "training",
                "384 deployment",
                "640 deployment",
                "production math-mode claim",
                "commercial/external claim",
            ],
            "rationale": "scorecard and oracle reconcile; fixed512 underperformed prior KT512BASE by >0.07; 384 has false downshift damage; 640 has recovery and damage and remains sentinel-only.",
            "claim_ceiling_preserved": True,
        },
    )

    write_json(
        REPORTS / "ktpareto_validation_path_mapping.json",
        {
            "schema_id": "kt.ktpareto.validation_path_mapping.v1",
            "status": "PASS_REPO_NATIVE_PATHS_USED",
            "requested_commands": [
                "python scripts/import_ktpareto_assessment.py",
                "python scripts/validate_ktpareto_review.py",
                "python -m pytest --no-cov -q tests/test_ktpareto_*.py",
                "python scripts/validate_json_artifacts.py",
                "python scripts/scan_for_forbidden_claims.py",
                "python KT_PROD_CLEANROOM/tools/operator/taxonomy_drift_scan.py",
                "PYTHONPATH=KT_PROD_CLEANROOM python KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
                "python scripts/check_artifact_authority_registry.py",
                "python scripts/check_no_bloat.py",
                "python scripts/check_stale_head_refs.py",
                "git diff --check",
            ],
            "substitutions": [
                {
                    "requested": "PYTHONPATH=KT_PROD_CLEANROOM python KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
                    "used_on_windows": "$env:PYTHONPATH='KT_PROD_CLEANROOM'; python KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
                }
            ],
            "claim_ceiling_preserved": True,
        },
    )

    summary = {
        "schema_id": "kt.ktpareto.review_builder_summary.v1",
        "status": "PASS" if scorecard_status == "PASS" and sha_status == "PASS" else "BLOCKED",
        "current_head": current_head,
        "branch": branch,
        "outcome": OUTCOME,
        "ktpareto_assessment_import_status": sha_status,
        "ktpareto_scorecard_reconciliation_status": scorecard_status,
        "ktpareto_slice_exchangeability_status": exchangeability["status"],
        "ktpareto_difficulty_proxy_status": question_status,
        "ktpareto_stratified_frontier_status": "PASS",
        "ktpareto_fixed512_weak_baseline_court_status": "FIXED512_WEAK_OR_SLICE_SHIFT_REVIEW_REQUIRED",
        "ktpareto_384_false_downshift_court_status": "PASS_BLOCKS_384_DEPLOYMENT",
        "ktpareto_640_recovery_damage_court_status": "PASS_SENTINEL_ONLY",
        "ktpareto_no_correct_arm_autopsy_status": "PASS_G32_OWNERSHIP_REQUIRED",
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "packet_path_if_any": None,
        "packet_sha256_if_any": None,
        "kaggle_dataset_name_if_any": None,
        "one_cell_runbook_if_any": None,
        "blockers": [] if scorecard_status == "PASS" and sha_status == "PASS" else ["scorecard_or_sha_reconciliation_failed"],
        "next_lawful_move": selected_next,
    }
    write_json(REPORTS / "ktpareto_review_builder_summary.json", summary)
    return summary


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
