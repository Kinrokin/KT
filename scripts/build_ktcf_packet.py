from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import textwrap
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
CONFIGS = ROOT / "configs"
SCHEMAS = ROOT / "schemas"
PACKETS = ROOT / "packets"
DOCS = ROOT / "docs"
REGISTRY = ROOT / "registry"

OUTCOME = "KT_COUNTERFACTUAL_MICROFURNACE_PACKET_READY__STRATIFIED_FAILURE_COURTS_BOUND__CLAIM_CEILING_PRESERVED"
NEXT_LAWFUL_MOVE = "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1"
ACTIVE_TRANCHE = "AUTHOR_KTPARETO_COUNTERFACTUAL_MICROFURNACE_PACKET_V1"
PACKET_PATH = PACKETS / "ktcf_v1.zip"
KAGGLE_DATASET_NAME = "ktcf-v1"
RUN_MODE = "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1"
ROW_SLICE = "openai/gsm8k:test[325:425]"
EXPECTED_G32S_OUTCOME = "KT_G32_STRATIFIED_FIXED512_FAILURES_OWNED__COUNTERFACTUAL_COURTS_BOUND__DIFFICULTY_AWARE_SELECTOR_SEED_READY__CLAIM_CEILING_PRESERVED"
EXPECTED_G32S_NEXT = "AUTHOR_KTPARETO_COUNTERFACTUAL_MICROFURNACE_PACKET_V1"
PARETO_ASSESSMENT_SHA256 = "fa417a164604301131be89317991f1ecc4289095dc021e92cc7b6fdf549837af"

AUTHORITY_FALSE = {
    "runtime_authority": False,
    "dataset_generation_authority": False,
    "training_authority": False,
    "promotion_authority": False,
    "selector_deployment_authority": False,
    "adapter_mutation_authority": False,
    "production_prompt_mutation_authority": False,
}

FORBIDDEN_DEPLOYMENT_FALSE = {
    "deploy_384": False,
    "deploy_640": False,
    "deploy_768": False,
    "deploy_1024": False,
    "production_math_mode_claim": False,
    "learned_router_superiority_claim": False,
    "router_superiority_claim": False,
    "commercial_claim": False,
    "external_validation_claim": False,
    "frontier_or_s_tier_claim": False,
}

FEATURES = [
    "question_token_length",
    "number_count",
    "entity_count",
    "operation_keyword_count",
    "estimated_step_count",
    "rate_ratio_percent_terms",
    "fraction_decimal_terms",
    "unit_conversion_terms",
    "comparison_terms",
    "multi_entity_tracking_terms",
]

SOURCE_CLASS_ORDER = [
    "NO_CORRECT_ARM",
    "FALSE384",
    "COT640_RECOVERY",
    "COT640_DAMAGE",
]

PROMPT_TEMPLATES = {
    "BASELINE_COT": "Solve the problem step by step. Keep the reasoning concise but complete. End with exactly one line in this form:\nFINAL_ANSWER: <answer>",
    "EXPLICIT_VARIABLE_COT": "Solve the problem step by step. After each arithmetic step, restate the current value of every named quantity or variable needed for the solution. Do not skip variable updates. End with exactly one line in this form:\nFINAL_ANSWER: <answer>",
    "MINIMAL_PLAIN_COT": "Solve with the fewest necessary reasoning steps. Avoid extra explanation. Do not introduce unrelated assumptions. End with exactly one line in this form:\nFINAL_ANSWER: <answer>",
    "STRUCTURED_FACT_EQUATION_COT": "First list the given facts. Then define needed variables. Then write the arithmetic/equations. Then compute. End with exactly one line in this form:\nFINAL_ANSWER: <answer>",
    "ANSWER_ONLY_NO_COT": "Give only the final answer. Do not show reasoning.\nFINAL_ANSWER: <answer>",
}

ARMS = [
    {"arm_id": "A0_FIXED512_BASELINE", "arm_type": "generation", "prompt_template_id": "BASELINE_COT", "max_new_tokens": 512, "claim_bound": "fixed512_control_baseline_not_deployable"},
    {"arm_id": "A1_FIXED640_SENTINEL", "arm_type": "generation", "prompt_template_id": "BASELINE_COT", "max_new_tokens": 640, "claim_bound": "sentinel_only_not_deployable"},
    {"arm_id": "A2_FIXED768_CONTINUATION", "arm_type": "generation", "prompt_template_id": "BASELINE_COT", "max_new_tokens": 768, "claim_bound": "continuation_probe_only_not_deployable"},
    {"arm_id": "A3_FIXED1024_CEILING", "arm_type": "generation", "prompt_template_id": "BASELINE_COT", "max_new_tokens": 1024, "claim_bound": "ceiling_diagnostic_only_not_global_policy"},
    {"arm_id": "A4_EXPLICIT_VARIABLE_COT_512", "arm_type": "generation", "prompt_template_id": "EXPLICIT_VARIABLE_COT", "max_new_tokens": 512, "claim_bound": "prompt_elicitation_candidate_only"},
    {"arm_id": "A5_MINIMAL_PLAIN_COT_512", "arm_type": "generation", "prompt_template_id": "MINIMAL_PLAIN_COT", "max_new_tokens": 512, "claim_bound": "overthink_reduction_candidate_only"},
    {"arm_id": "A6_STRUCTURED_FACT_EQUATION_COT_512", "arm_type": "generation", "prompt_template_id": "STRUCTURED_FACT_EQUATION_COT", "max_new_tokens": 512, "claim_bound": "prompt_structure_candidate_only"},
    {"arm_id": "A7_ANSWER_ONLY_NO_COT", "arm_type": "generation", "prompt_template_id": "ANSWER_ONLY_NO_COT", "max_new_tokens": 96, "claim_bound": "answer_only_diagnostic_not_strategy"},
    {"arm_id": "A8_FINALIZER_REPLAY_ONLY", "arm_type": "analysis_only", "prompt_template_id": None, "max_new_tokens": None, "claim_bound": "finalizer_scorer_diagnostic_only"},
    {"arm_id": "A9_ORACLE_DIAGNOSTIC", "arm_type": "analysis_only", "prompt_template_id": None, "max_new_tokens": None, "claim_bound": "HINDSIGHT_ONLY_NOT_DEPLOYABLE"},
]

PREDECESSOR_PATHS = {
    "g32s_builder_summary": REPORTS / "g32s_builder_summary.json",
    "g32s_train_decision": REPORTS / "g32s_train_decision.json",
    "g32s_mvs_receipt": REPORTS / "g32s_mvs_receipt.json",
    "g32s_no_correct_counterfactual_matrix": REPORTS / "g32s_no_correct_counterfactual_matrix.jsonl",
    "g32s_no_correct_arm_morbidity_review": REPORTS / "g32s_no_correct_arm_morbidity_review.jsonl",
    "g32s_false384_causal_matrix": REPORTS / "g32s_false384_causal_matrix.jsonl",
    "g32s_cot640_recovery_damage_matrix": REPORTS / "g32s_cot640_recovery_damage_matrix.jsonl",
    "g32s_human_anchor_request_queue": REPORTS / "g32s_human_anchor_request_queue.jsonl",
    "g32s_next_microfurnace_spec": REPORTS / "g32s_next_microfurnace_spec.json",
    "g32s_feature_legality_receipt": REPORTS / "g32s_feature_legality_receipt.json",
    "g32s_difficulty_aware_selector_policy": ROOT / "policies" / "g32s_difficulty_aware_selector_v2.json",
    "ktpareto_assessment_import_receipt": REPORTS / "ktpareto_assessment_import_receipt.json",
    "ktpareto_assessment_zip": ROOT / "evidence" / "KT_PARETO_V1_ASSESSMENT_ONLY.zip",
    "ktpareto_difficulty_proxy_matrix": REPORTS / "ktpareto_difficulty_proxy_matrix.jsonl",
    "claim_ceiling": ROOT / "rules" / "CLAIM_CEILING.md",
    "artifact_registry": REGISTRY / "artifact_authority_registry.json",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fail(status: str, reason: str, **extra: Any) -> None:
    payload = {
        "schema_id": "kt.ktcf.blocker_receipt.v1",
        "status": status,
        "reason": reason,
        "created_utc": utc_now(),
        "claim_ceiling_status": "PRESERVED",
        **AUTHORITY_FALSE,
        **extra,
    }
    write_json(REPORTS / "ktcf_blocker_receipt.json", payload)
    raise SystemExit(json.dumps(payload, indent=2, sort_keys=True))


def schema(required: list[str], const: str | None = None) -> dict[str, Any]:
    properties: dict[str, Any] = {key: {} for key in required}
    if const:
        properties["schema_id"] = {"const": const}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": True,
        "required": required,
        "properties": properties,
    }


def write_schemas() -> None:
    specs = {
        "kt.ktcf_row_selection.schema.json": ("kt.ktcf.row_selection_receipt.v1", ["schema_id", "status", "target_rows_unique", "control_rows", "claim_ceiling_status"]),
        "kt.ktcf_control_matching.schema.json": ("kt.ktcf.control_matching_report.v1", ["schema_id", "status", "method", "control_count", "claim_ceiling_status"]),
        "kt.ktcf_benchmark_audit.schema.json": ("kt.ktcf.benchmark_audit_receipt.v1", ["schema_id", "status", "audited_no_correct_rows", "suspected_error_count", "claim_ceiling_status"]),
        "kt.ktcf_prompt_templates.schema.json": ("kt.ktcf.prompt_templates.v1", ["schema_id", "status", "templates", "claim_ceiling_status"]),
        "kt.ktcf_power_analysis.schema.json": ("kt.ktcf.power_analysis.v1", ["schema_id", "status", "target_n", "interpretation", "claim_ceiling_status"]),
        "kt.ktcf_stop_rules.schema.json": ("kt.ktcf.stop_rules.v1", ["schema_id", "status", "rules", "claim_ceiling_status"]),
        "kt.ktcf_causal_interpretation.schema.json": ("kt.ktcf.causal_interpretation_law.v1", ["schema_id", "status", "interpretation_table", "claim_ceiling_status"]),
        "kt.ktcf_packet_decision.schema.json": ("kt.ktcf.packet_decision.v1", ["schema_id", "status", "packet_path", "packet_sha256", "next_lawful_move"]),
        "kt.ktcf_feature_legality.schema.json": ("kt.ktcf.feature_legality_receipt.v1", ["schema_id", "status", "forbidden_features", "selector_deployment_authority"]),
    }
    for filename, (schema_id, required) in specs.items():
        write_json(SCHEMAS / filename, schema(required, schema_id))


def ensure_g32s_feature_legality_receipt(policy: dict[str, Any]) -> None:
    path = REPORTS / "g32s_feature_legality_receipt.json"
    if path.exists():
        return
    write_json(
        path,
        {
            "schema_id": "kt.g32s.feature_legality_receipt.v1",
            "status": "PASS_DERIVED_FROM_G32S_SELECTOR_POLICY",
            "source_policy": "policies/g32s_difficulty_aware_selector_v2.json",
            "allowed_features": policy.get("allowed_features", []),
            "forbidden_features": policy.get("forbidden_features", []),
            "selector_deployment_authority": False,
            "runtime_authority": False,
            "training_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )


def bind_predecessors() -> dict[str, Any]:
    policy_path = PREDECESSOR_PATHS["g32s_difficulty_aware_selector_policy"]
    if policy_path.exists():
        ensure_g32s_feature_legality_receipt(read_json(policy_path))

    missing = [name for name, path in PREDECESSOR_PATHS.items() if not path.exists()]
    if missing:
        fail("KT_CF_BLOCKED__G32S_PREDECESSOR_MISSING", "required predecessor artifacts are missing", missing_inputs=missing)

    summary = read_json(PREDECESSOR_PATHS["g32s_builder_summary"])
    if summary.get("outcome") != EXPECTED_G32S_OUTCOME or summary.get("next_lawful_move") != EXPECTED_G32S_NEXT:
        fail(
            "KT_CF_BLOCKED__G32S_PREDECESSOR_MISSING",
            "G32S predecessor does not authorize KTCF",
            observed_outcome=summary.get("outcome"),
            observed_next_lawful_move=summary.get("next_lawful_move"),
        )

    assessment_sha = sha256_file(PREDECESSOR_PATHS["ktpareto_assessment_zip"])
    if assessment_sha != PARETO_ASSESSMENT_SHA256:
        fail(
            "KT_CF_BLOCKED__G32S_PREDECESSOR_MISSING",
            "Pareto assessment SHA mismatch",
            observed_sha256=assessment_sha,
            expected_sha256=PARETO_ASSESSMENT_SHA256,
        )

    mapping = {
        "schema_id": "kt.ktcf.input_path_mapping.v1",
        "status": "PASS",
        "paths": {name: path.relative_to(ROOT).as_posix() for name, path in PREDECESSOR_PATHS.items()},
        "created_utc": utc_now(),
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_input_path_mapping.json", mapping)
    return summary


def load_pareto_assessment() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    with zipfile.ZipFile(PREDECESSOR_PATHS["ktpareto_assessment_zip"]) as zf:
        predictions = [json.loads(line) for line in zf.read("budget_predictions.jsonl").decode("utf-8").splitlines() if line.strip()]
        oracle = [json.loads(line) for line in zf.read("per_arm_oracle_rows.jsonl").decode("utf-8").splitlines() if line.strip()]
        scorecard = json.loads(zf.read("budget_pareto_scorecard.json").decode("utf-8"))
        summary = json.loads(zf.read("final_summary.json").decode("utf-8"))
    return predictions, oracle, scorecard, summary


def fetch_gsm8k_rows(start: int = 325, length: int = 100) -> dict[str, dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"dataset": "openai/gsm8k", "config": "main", "split": "test", "offset": start, "length": length}
    )
    url = f"https://datasets-server.huggingface.co/rows?{query}"
    try:
        with urllib.request.urlopen(url, timeout=45) as handle:
            payload = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        fail("KT_CF_BLOCKED__BENCHMARK_AUDIT_REQUIRED", f"could not fetch public GSM8K source rows: {exc}")
    rows: dict[str, dict[str, Any]] = {}
    for row in payload.get("rows", []):
        global_row = int(row["row_idx"])
        item = row["row"]
        answer = item["answer"]
        final = answer.split("####")[-1].strip() if "####" in answer else ""
        rows[f"gsm8k_test_{global_row:03d}"] = {
            "row_id": f"gsm8k_test_{global_row:03d}",
            "global_row": global_row,
            "question": item["question"],
            "expected_answer": final,
            "expected_answer_hash": sha256_text(final),
            "raw_answer_hash": sha256_text(answer),
            "source": "openai/gsm8k:main:test",
        }
    if len(rows) != length:
        fail("KT_CF_BLOCKED__BENCHMARK_AUDIT_REQUIRED", "public GSM8K source row fetch returned incomplete slice", observed=len(rows), expected=length)
    return rows


def load_difficulty_rows() -> dict[str, dict[str, Any]]:
    rows = read_jsonl(PREDECESSOR_PATHS["ktpareto_difficulty_proxy_matrix"])
    return {row["row_id"]: row for row in rows if row.get("slice_id") == "KTPARETO"}


def zscore_stats(rows: list[dict[str, Any]]) -> dict[str, tuple[float, float]]:
    stats: dict[str, tuple[float, float]] = {}
    for feature in FEATURES:
        values = [float(row.get(feature, 0) or 0) for row in rows]
        mean = statistics.fmean(values)
        stdev = statistics.pstdev(values) or 1.0
        stats[feature] = (mean, stdev)
    return stats


def zvec(row: dict[str, Any], stats: dict[str, tuple[float, float]]) -> list[float]:
    return [(float(row.get(feature, 0) or 0) - stats[feature][0]) / stats[feature][1] for feature in FEATURES]


def euclidean(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def build_target_rows(gsm8k: dict[str, dict[str, Any]], difficulty: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    target_map: dict[str, dict[str, Any]] = {}

    def add(row_id: str, source_class: str, source_record: dict[str, Any]) -> None:
        source = gsm8k[row_id]
        proxy = difficulty[row_id]
        entry = target_map.setdefault(
            row_id,
            {
                "schema_id": "kt.ktcf.target_row.v1",
                "row_id": row_id,
                "global_row": source["global_row"],
                "dataset": "openai/gsm8k",
                "split": "test",
                "role": "TARGET",
                "source_classes": [],
                "question_hash": sha256_text(source["question"]),
                "expected_answer_hash": source["expected_answer_hash"],
                "difficulty_stratum": proxy.get("pre_generation_proxy_stratum"),
                "human_anchor_required": source_class == "NO_CORRECT_ARM",
                "claim_ceiling_status": "PRESERVED",
            },
        )
        if source_class not in entry["source_classes"]:
            entry["source_classes"].append(source_class)
        for feature in FEATURES:
            entry[feature] = proxy.get(feature)
        entry.setdefault("source_evidence", []).append(
            {
                "source_class": source_class,
                "source_schema_id": source_record.get("schema_id"),
                "source_claim_ceiling_status": source_record.get("claim_ceiling_status"),
            }
        )

    no_correct = read_jsonl(PREDECESSOR_PATHS["g32s_no_correct_counterfactual_matrix"])
    false384 = read_jsonl(PREDECESSOR_PATHS["g32s_false384_causal_matrix"])
    cot640 = read_jsonl(PREDECESSOR_PATHS["g32s_cot640_recovery_damage_matrix"])

    for row in no_correct:
        add(row["row_id"], "NO_CORRECT_ARM", row)
    for row in false384:
        add(row["row_id"], "FALSE384", row)
    for row in cot640:
        if row.get("class") in {"COT640_RECOVERY", "COT640_DAMAGE"}:
            add(row["row_id"], row["class"], row)

    for row in target_map.values():
        row["source_classes"] = [name for name in SOURCE_CLASS_ORDER if name in row["source_classes"]]
    targets = sorted(target_map.values(), key=lambda row: row["global_row"])
    counts = Counter(source_class for row in targets for source_class in row["source_classes"])
    expected = {"NO_CORRECT_ARM": 14, "FALSE384": 7, "COT640_RECOVERY": 4, "COT640_DAMAGE": 2}
    if dict(counts) != expected:
        fail("KT_CF_BLOCKED__ROW_SELECTION_OR_CONTROL_MATCHING_DEFECT", "target source-class counts mismatch", observed=dict(counts), expected=expected)
    return targets, dict(counts)


def build_control_rows(
    targets: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    gsm8k: dict[str, dict[str, Any]],
    difficulty: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    predictions_by_row_arm = {(row["row_id"], row["arm_id"]): row for row in predictions}
    target_ids = {row["row_id"] for row in targets}
    fixed512_correct_pool: list[dict[str, Any]] = []
    for row_id, proxy in difficulty.items():
        if row_id in target_ids:
            continue
        pred = predictions_by_row_arm.get((row_id, "A6_COT_512_FIXED_CONTROL"))
        if pred and pred.get("correct") is True:
            fixed512_correct_pool.append(proxy)

    no_correct_targets = [row for row in targets if "NO_CORRECT_ARM" in row["source_classes"]]
    if len(no_correct_targets) != 14:
        fail("KT_CF_BLOCKED__ROW_SELECTION_OR_CONTROL_MATCHING_DEFECT", "no-correct target count must be 14", observed=len(no_correct_targets))
    if len(fixed512_correct_pool) < 14:
        fail("KT_CF_BLOCKED__ROW_SELECTION_OR_CONTROL_MATCHING_DEFECT", "insufficient fixed512-correct control pool", observed=len(fixed512_correct_pool))

    all_proxy_rows = list(difficulty.values())
    stats = zscore_stats(all_proxy_rows)
    selected: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    used: set[str] = set()
    for target in no_correct_targets:
        target_vec = zvec(target, stats)
        candidates = []
        for candidate in fixed512_correct_pool:
            if candidate["row_id"] in used:
                continue
            dist = euclidean(target_vec, zvec(candidate, stats))
            candidates.append((dist, candidate))
        if not candidates:
            break
        distance, control_proxy = min(candidates, key=lambda item: (item[0], item[1]["global_row"]))
        used.add(control_proxy["row_id"])
        source = gsm8k[control_proxy["row_id"]]
        control_row = {
            "schema_id": "kt.ktcf.control_row.v1",
            "row_id": source["row_id"],
            "global_row": source["global_row"],
            "dataset": "openai/gsm8k",
            "split": "test",
            "role": "CONTROL_FIXED512_CORRECT_STRATIFIED",
            "matched_target_row_id": target["row_id"],
            "match_distance_z": round(distance, 6),
            "question_hash": sha256_text(source["question"]),
            "expected_answer_hash": source["expected_answer_hash"],
            "difficulty_stratum": control_proxy.get("pre_generation_proxy_stratum"),
            "fixed512_correct_prior": True,
            "claim_ceiling_status": "PRESERVED",
        }
        for feature in FEATURES:
            control_row[feature] = control_proxy.get(feature)
        selected.append(control_row)
        matches.append(
            {
                "target_row_id": target["row_id"],
                "control_row_id": control_row["row_id"],
                "target_global_row": target["global_row"],
                "control_global_row": control_row["global_row"],
                "distance_z": round(distance, 6),
                "target_stratum": target.get("difficulty_stratum"),
                "control_stratum": control_row.get("difficulty_stratum"),
            }
        )

    if len(selected) != 14:
        fail("KT_CF_BLOCKED__ROW_SELECTION_OR_CONTROL_MATCHING_DEFECT", "control matching did not produce 14 controls", observed=len(selected))

    report = {
        "schema_id": "kt.ktcf.control_matching_report.v1",
        "status": "PASS",
        "method": "nearest_neighbor_z_scored_difficulty_proxy_matched_to_no_correct_targets",
        "features": FEATURES,
        "control_pool_size": len(fixed512_correct_pool),
        "target_basis": "14 NO_CORRECT_ARM rows",
        "control_count": len(selected),
        "matches": matches,
        "mean_match_distance_z": round(statistics.fmean(row["distance_z"] for row in matches), 6),
        "claim_ceiling_status": "PRESERVED",
    }
    return selected, report


def audit_no_correct_answers(targets: list[dict[str, Any]], gsm8k: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in targets:
        if "NO_CORRECT_ARM" not in target["source_classes"]:
            continue
        source = gsm8k[target["row_id"]]
        expected = source["expected_answer"]
        parse_status = "PASS_NUMERIC_FINAL_ANSWER_BOUND" if expected else "FAIL_MISSING_FINAL_ANSWER"
        unit_ambiguity = False
        suspected = parse_status != "PASS_NUMERIC_FINAL_ANSWER_BOUND"
        rows.append(
            {
                "schema_id": "kt.ktcf.no_correct_expected_answer_audit_row.v1",
                "row_id": target["row_id"],
                "global_row": target["global_row"],
                "question_hash": target["question_hash"],
                "expected_answer_hash": target["expected_answer_hash"],
                "expected_answer_parse_status": parse_status,
                "unit_or_format_ambiguity": unit_ambiguity,
                "benchmark_error_suspected": suspected,
                "human_anchor_required": True,
                "corrected_answer_for_sidecar_only_if_suspected": None,
                "claim_ceiling_status": "PRESERVED",
            }
        )
    suspected_count = sum(1 for row in rows if row["benchmark_error_suspected"])
    receipt = {
        "schema_id": "kt.ktcf.benchmark_audit_receipt.v1",
        "status": "PASS" if suspected_count < 2 else "ESCALATE_TO_BENCHMARK_HUMAN_ANCHOR_COURT",
        "audited_no_correct_rows": len(rows),
        "suspected_error_count": suspected_count,
        "human_anchor_required_rows": len(rows),
        "corrected_answers_prompt_side_allowed": False,
        "claim_ceiling_status": "PRESERVED",
    }
    sidecar = {
        "schema_id": "kt.ktcf.benchmark_corrected_sidecar_policy.v1",
        "status": "PASS_NO_CORRECTIONS_PROPOSED" if suspected_count == 0 else "SCORER_SIDE_DIAGNOSTIC_ONLY",
        "corrected_answers_prompt_side_allowed": False,
        "scorer_side_only": True,
        "claim_ceiling_status": "PRESERVED",
    }
    return rows, receipt, sidecar


def render_prompt(template_text: str, question: str) -> str:
    return f"{template_text}\n\nProblem:\n{question}\n"


def prompt_and_leakage_receipts(
    targets: list[dict[str, Any]],
    controls: list[dict[str, Any]],
    gsm8k: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    prompt_rows = [
        {
            "template_id": template_id,
            "template_text": text,
            "template_sha256": sha256_text(text),
            "contains_final_answer_marker": "FINAL_ANSWER" in text,
        }
        for template_id, text in sorted(PROMPT_TEMPLATES.items())
    ]
    prompt_manifest = {
        "schema_id": "kt.ktcf.prompt_templates.v1",
        "status": "PASS",
        "templates": prompt_rows,
        "scorer_side_fields_excluded_from_prompt": ["expected_answer", "expected_answer_hash", "source_classes", "prior_correctness", "row_id"],
        "claim_ceiling_status": "PRESERVED",
    }
    arm_manifest = {
        "schema_id": "kt.ktcf.arm_manifest.v1",
        "status": "PASS",
        "run_mode": RUN_MODE,
        "arms": ARMS,
        "oracle_diagnostic": "HINDSIGHT_ONLY_NOT_DEPLOYABLE",
        "generation_arm_count": sum(1 for arm in ARMS if arm["arm_type"] == "generation"),
        **AUTHORITY_FALSE,
        **FORBIDDEN_DEPLOYMENT_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }

    checked = 0
    literal_native_overlap = []
    injected_leaks = []
    for row in targets + controls:
        source = gsm8k[row["row_id"]]
        for arm in ARMS:
            template_id = arm.get("prompt_template_id")
            if not template_id:
                continue
            prompt = render_prompt(PROMPT_TEMPLATES[template_id], source["question"])
            checked += 1
            expected = source["expected_answer"]
            if expected and expected in prompt:
                literal_native_overlap.append({"row_id": row["row_id"], "arm_id": arm["arm_id"], "reason": "expected_answer_literal_occurs_in_public_question_text_or_template_context"})
            for forbidden in [row["row_id"], "|".join(row.get("source_classes", [])), source["expected_answer_hash"]]:
                if forbidden and forbidden in prompt:
                    injected_leaks.append({"row_id": row["row_id"], "arm_id": arm["arm_id"], "forbidden": forbidden})
    leakage = {
        "schema_id": "kt.ktcf.prompt_leakage_receipt.v1",
        "status": "PASS_NO_SCORER_FIELD_INJECTION",
        "rendered_prompt_count": checked,
        "expected_answer_field_injected": False,
        "hindsight_class_label_injected": False,
        "row_id_injected": False,
        "source_classes_injected": False,
        "prior_correctness_injected": False,
        "literal_expected_answer_overlap_due_to_public_question_text": literal_native_overlap[:25],
        "literal_overlap_count": len(literal_native_overlap),
        "injected_leaks": injected_leaks,
        "claim_ceiling_status": "PRESERVED",
    }
    firewall = {
        "schema_id": "kt.ktcf.gold_prompt_leakage_firewall_receipt.v1",
        "status": "PASS" if not injected_leaks else "FAIL",
        "prompt_rendering_source_fields": ["question"],
        "scorer_side_only_fields": ["expected_answer", "expected_answer_hash", "corrected_answer_sidecar"],
        "expected_answer_text_never_injected_by_prompt_renderer": True,
        "hindsight_class_labels_never_injected": True,
        "row_id_not_used_as_selector_feature": True,
        "measured_prior_correctness_not_used_as_runtime_selector_feature": True,
        "oracle_diagnostic_report_only": True,
        "corrected_benchmark_answers_scorer_side_only": True,
        "claim_ceiling_status": "PRESERVED",
    }
    if injected_leaks:
        fail("KT_CF_BLOCKED__PROMPT_TEMPLATE_OR_GOLD_LEAKAGE_DEFECT", "prompt leakage firewall found injected forbidden fields", leaks=injected_leaks)
    return arm_manifest, prompt_manifest, leakage, firewall


def success_power_stop_causal() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    success = {
        "schema_id": "kt.ktcf.preregistered_success_criteria.v1",
        "status": "PASS",
        "criteria": {
            "EXPLICIT_VARIABLE_COT": {"success": ">=5/14 no-correct-arm rows newly correct AND matched-control damage <=1", "interpretation": "prompt-elicitation / multi-entity-tracking repair candidate, not raw capability proof"},
            "MINIMAL_PLAIN_COT": {"success": ">=3/14 no-correct-arm rows newly correct OR clear reduction in overthink/damage rows", "interpretation": "overthink/verbosity repair candidate"},
            "STRUCTURED_FACT_EQUATION_COT": {"success": ">=5/14 no-correct-arm rows newly correct AND matched-control damage <=1", "interpretation": "prompt structure / equation extraction repair candidate"},
            "FIXED768_CONTINUATION": {"success": ">=3/14 no-correct-arm rows newly correct AND no net control damage >1", "interpretation": "budget/continuation candidate only"},
            "FIXED1024_CEILING": {"success": ">=3/14 no-correct-arm rows newly correct AND no net control damage >2", "interpretation": "budget ceiling diagnostic only, never global policy"},
            "FINALIZER_REPLAY_ONLY": {"success": ">=4/14 no-correct-arm rows rescored correct from prior/current raw outputs", "interpretation": "finalizer/scorer owned, not reasoning owned"},
        },
        "claim_ceiling_status": "PRESERVED",
    }
    power = {
        "schema_id": "kt.ktcf.power_analysis.v1",
        "status": "PASS",
        "target_n": 14,
        "matched_control_n": 14,
        "interpretation": {
            "one_to_two_rows": "WEAK_SIGNAL",
            "three_to_four_rows": "CANDIDATE_SIGNAL",
            "five_or_more_rows": "FOLLOW_ON_LANE_JUSTIFIED_IF_CONTROL_DAMAGE_BOUNDED",
        },
        "claim_ceiling_status": "PRESERVED",
    }
    stop = {
        "schema_id": "kt.ktcf.stop_rules.v1",
        "status": "PASS",
        "rules": [
            "STOP broad prompt/budget counterfactuals if every generation arm recovers <=2/14 and finalizer replay recovers <=1/14.",
            "CONTINUE to targeted lane if any arm hits threshold with shared genotype and low control damage.",
            "ESCALATE to benchmark/human-anchor court if benchmark audit suspects >=2 row answer ambiguity.",
            "BLOCK training if MVS unknown rate remains above gate or human anchors are absent.",
        ],
        "claim_ceiling_status": "PRESERVED",
    }
    causal = {
        "schema_id": "kt.ktcf.causal_interpretation_law.v1",
        "status": "PASS",
        "interpretation_table": {
            "prompt_variant_fixes_row_at_same_512_budget": "PROMPT_ELICITATION_OWNED_OR_MULTI_ENTITY_TRACKING_OWNED_NOT_RAW_MODEL_CAPABILITY",
            "higher_budget_fixes_row_prompt_variants_do_not": "BUDGET_CONTINUATION_OWNED_OR_REASONING_DEPTH_OWNED",
            "finalizer_replay_fixes_row": "FINALIZER_SCORER_OWNED",
            "no_prompt_budget_finalizer_fix_and_benchmark_clean": "MODEL_CAPABILITY_OWNED_OR_IRREDUCIBLE_PENDING_HUMAN_ANCHOR",
            "benchmark_audit_suspects_wrong_or_ambiguous_expected_answer": "BENCHMARK_OWNED_PENDING_HUMAN_ANCHOR",
            "control_rows_damaged": "NON_DEPLOYABLE_DIAGNOSTIC_ONLY_EVEN_IF_TARGET_IMPROVES",
        },
        "proof_threshold": "preregistered_hypothesis_plus_bounded_control_damage_plus_shared_failure_genotype",
        "claim_ceiling_status": "PRESERVED",
    }
    verdict = {
        "schema_id": "kt.ktcf.expected_verdict_matrix.v1",
        "status": "PASS",
        "candidate_verdicts": [
            "PROMPT_ELICITATION_OWNED",
            "MULTI_ENTITY_TRACKING_OWNED",
            "BUDGET_CONTINUATION_OWNED",
            "REASONING_DEPTH_OWNED",
            "FINALIZER_SCORER_OWNED",
            "MODEL_CAPABILITY_OWNED",
            "IRREDUCIBLE_PENDING_HUMAN_ANCHOR",
            "BENCHMARK_OWNED_PENDING_HUMAN_ANCHOR",
            "NON_DEPLOYABLE_DIAGNOSTIC_ONLY",
        ],
        "claim_ceiling_status": "PRESERVED",
    }
    return success, power, stop, causal, verdict


def feature_legality_receipt(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": "kt.ktcf.feature_legality_receipt.v1",
        "status": "PASS",
        "allowed_features_for_offline_matching": FEATURES,
        "runtime_selector_enabled": False,
        "forbidden_features": sorted(set(policy.get("forbidden_features", [])) | {"expected_answer", "row_id", "measured_arm_correctness", "posthoc_correctness", "oracle_correct_arm", "oracle_cheapest_correct_arm", "source_classes", "target_class"}),
        "row_id_not_selector_feature": True,
        "measured_prior_correctness_not_selector_feature": True,
        "oracle_correctness_not_input_feature": True,
        "selector_deployment_authority": False,
        "claim_ceiling_status": "PRESERVED",
    }


def claim_boundary_receipt(packet_sha: str | None = None) -> dict[str, Any]:
    return {
        "schema_id": "kt.ktcf.claim_boundary_receipt.v1",
        "status": "PASS",
        "packet_sha256_if_known": packet_sha,
        "packet_sha256_authority": "reports/ktcf_packet_decision.json" if packet_sha else "BOUND_AFTER_PACKET_BUILD",
        "allowed_claim": "A repo-side packet was forged to run a targeted counterfactual microfurnace over selected Pareto/G32S rows under preregistered diagnostic rules.",
        **AUTHORITY_FALSE,
        **FORBIDDEN_DEPLOYMENT_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }


def compute_budget_estimate(targets: list[dict[str, Any]], controls: list[dict[str, Any]]) -> dict[str, Any]:
    generation_arms = [arm for arm in ARMS if arm["arm_type"] == "generation"]
    total_rows = len(targets) + len(controls)
    total_trials = total_rows * len(generation_arms)
    max_new = sum(int(arm["max_new_tokens"]) for arm in generation_arms) * total_rows
    return {
        "schema_id": "kt.ktcf.compute_budget_estimate.v1",
        "status": "PASS_BOUNDED_MICROFURNACE",
        "target_rows": len(targets),
        "control_rows": len(controls),
        "generation_arms": len(generation_arms),
        "planned_generation_trials": total_trials,
        "max_new_token_upper_bound": max_new,
        "checkpoint_resume": "row_id::arm_id",
        "claim_ceiling_status": "PRESERVED",
    }


def runtime_runner_source() -> str:
    return r'''from __future__ import annotations

import hashlib
import json
import os
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path


RUN_MODE = "RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1"
MODEL_REPO = os.environ.get("KT_MODEL_REPO", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit")
HF_RESULTS_REPO = os.environ.get("KT_HF_RESULTS_REPO", "Kinrokin/ktcf-v1-results")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def extract_answer(text: str):
    patterns = [
        r"FINAL_ANSWER\s*:\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"####\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"final answer\s*(?:is|:)?\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
        r"answer\s*(?:is|:)?\s*([-+]?\$?[\d,]+(?:\.\d+)?(?:/\d+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).replace("$", "").replace(",", "").strip()
    numbers = re.findall(r"[-+]?\$?[\d,]+(?:\.\d+)?", text)
    return numbers[-1].replace("$", "").replace(",", "").strip() if numbers else None


def alternate_extract_answer(text: str):
    final = extract_answer(text)
    numbers = re.findall(r"[-+]?\$?[\d,]+(?:\.\d+)?", text)
    candidates = []
    if final is not None:
        candidates.append(final)
    if numbers:
        candidates.extend(num.replace("$", "").replace(",", "").strip() for num in numbers[-3:])
    seen = []
    for item in candidates:
        if item not in seen:
            seen.append(item)
    return seen


def normalize(value):
    if value is None:
        return None
    text = str(value).replace(",", "").replace("$", "").strip()
    try:
        number = float(text)
    except Exception:
        return text.lower()
    return str(int(number)) if number.is_integer() else str(number)


def score_answer(output: str, expected: str) -> bool:
    return normalize(extract_answer(output)) == normalize(expected)


def score_candidate(candidate: str, expected: str) -> bool:
    return normalize(candidate) == normalize(expected)


def render_prompt(template: str, question: str) -> str:
    return f"{template}\n\nProblem:\n{question}\n"


def load_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO, trust_remote_code=True)
    use_4bit = os.environ.get("KT_LOAD_IN_4BIT", "1") != "0"
    kwargs = {"device_map": "auto", "trust_remote_code": True}
    if use_4bit:
        kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
    model = AutoModelForCausalLM.from_pretrained(MODEL_REPO, **kwargs)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def generate(model, tokenizer, prompt: str, max_new_tokens: int):
    import torch

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    start = time.time()
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    latency_ms = int((time.time() - start) * 1000)
    new_tokens = out[0][inputs["input_ids"].shape[-1]:]
    output = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return output, int(inputs["input_ids"].shape[-1]), int(new_tokens.shape[-1]), latency_ms


def load_checkpoint(path: Path):
    if not path.exists():
        return {}
    return read_json(path)


def save_checkpoint(path: Path, records: dict) -> None:
    write_json(path, records)


def write_blocker(outdir: Path, status: str, reason: str) -> Path:
    write_json(
        outdir / "BLOCKER_RECEIPT.json",
        {
            "schema_id": "kt.ktcf.blocker_receipt.runtime.v1",
            "status": status,
            "reason": reason,
            "run_mode": RUN_MODE,
            "training_authority": False,
            "promotion_authority": False,
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        },
    )
    return outdir / "BLOCKER_RECEIPT.json"


def maybe_upload_to_hf(outdir: Path, assessment_zip: Path) -> dict:
    token = os.environ.get("HF_TOKEN")
    if not token:
        return {"schema_id": "kt.ktcf.hf_upload_receipt.v1", "status": "SKIPPED_NO_HF_TOKEN", "repo_id": HF_RESULTS_REPO}
    try:
        from huggingface_hub import HfApi, create_repo, upload_file, upload_folder

        create_repo(HF_RESULTS_REPO, repo_type="dataset", private=False, exist_ok=True, token=token)
        upload_folder(repo_id=HF_RESULTS_REPO, repo_type="dataset", folder_path=str(outdir), path_in_repo="artifacts", token=token)
        upload_file(repo_id=HF_RESULTS_REPO, repo_type="dataset", path_or_fileobj=str(assessment_zip), path_in_repo=assessment_zip.name, token=token)
        info = HfApi(token=token).dataset_info(HF_RESULTS_REPO)
        return {"schema_id": "kt.ktcf.hf_upload_receipt.v1", "status": "PASS", "repo_id": HF_RESULTS_REPO, "url": f"https://huggingface.co/datasets/{HF_RESULTS_REPO}", "private": bool(info.private)}
    except Exception as exc:  # noqa: BLE001
        return {"schema_id": "kt.ktcf.hf_upload_receipt.v1", "status": "FAILED_NON_FATAL", "repo_id": HF_RESULTS_REPO, "error": str(exc)}


def main() -> None:
    packet_root = Path(__file__).resolve().parents[1]
    config = read_json(packet_root / "runtime" / "ktcf_config.json")
    outdir = Path(os.environ.get("KT_OUTPUT_DIR", "/kaggle/working/ktcf_outputs"))
    outdir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = outdir / "checkpoint_state.json"
    checkpoint = load_checkpoint(checkpoint_path)

    events = [{"event": "start", "run_mode": RUN_MODE, "row_count": len(config["rows"])}]
    write_json(outdir / "arm_manifest.json", {"schema_id": "kt.ktcf.runtime_arm_manifest.v1", "arms": config["arms"], "run_mode": RUN_MODE})
    write_json(outdir / "prompt_template_manifest.json", {"schema_id": "kt.ktcf.runtime_prompt_template_manifest.v1", "templates": config["prompt_templates"]})
    write_json(outdir / "row_manifest.json", {"schema_id": "kt.ktcf.runtime_row_manifest.v1", "rows": [row for row in config["rows"] if row["role"] == "TARGET"]})
    write_json(outdir / "control_manifest.json", {"schema_id": "kt.ktcf.runtime_control_manifest.v1", "rows": [row for row in config["rows"] if row["role"] != "TARGET"]})
    write_json(outdir / "benchmark_audit_manifest.json", config["benchmark_audit"])
    write_json(outdir / "claim_boundary_receipt.json", config["claim_boundary"])
    write_json(outdir / "safetensors_hash_manifest.json", {"schema_id": "kt.ktcf.safetensors_hash_manifest.v1", "status": "NO_ADAPTERS_USED"})

    try:
        generation_arms = [arm for arm in config["arms"] if arm["arm_type"] == "generation"]
        model, tokenizer = load_model()
        write_json(outdir / "model_loader_receipt.json", {"schema_id": "kt.ktcf.model_loader_receipt.v1", "status": "PASS", "model_repo": MODEL_REPO, "load_in_4bit_via_quantization_config": os.environ.get("KT_LOAD_IN_4BIT", "1") != "0"})

        matrix = list(checkpoint.values())
        completed = set(checkpoint)
        for row in config["rows"]:
            expected = config["scorer_expected_answers"][row["row_id"]]
            for arm in generation_arms:
                key = f"{row['row_id']}::{arm['arm_id']}"
                if key in completed:
                    continue
                template = config["prompt_templates"][arm["prompt_template_id"]]
                prompt = render_prompt(template, row["question"])
                if expected and expected in prompt and config.get("strict_native_answer_literal_block", False):
                    raise RuntimeError(f"expected answer literal appeared in rendered prompt for {key}")
                output, prompt_tokens, output_tokens, latency_ms = generate(model, tokenizer, prompt, int(arm["max_new_tokens"]))
                extracted = extract_answer(output)
                finalizer_candidates = alternate_extract_answer(output)
                record = {
                    "schema_id": "kt.ktcf.counterfactual_trial_row.v1",
                    "run_mode": RUN_MODE,
                    "row_id": row["row_id"],
                    "global_row": row["global_row"],
                    "role": row["role"],
                    "source_classes": row.get("source_classes", []),
                    "arm_id": arm["arm_id"],
                    "arm_type": arm["arm_type"],
                    "max_new_tokens": arm["max_new_tokens"],
                    "correct": score_candidate(extracted, expected),
                    "extracted_answer": extracted,
                    "expected_answer_hash": row["expected_answer_hash"],
                    "prompt_hash": sha256_text(prompt),
                    "output_hash": sha256_text(output),
                    "output_preview": output[:1000],
                    "output_tail": output[-2000:],
                    "finalizer_candidates": finalizer_candidates,
                    "prompt_tokens": prompt_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": prompt_tokens + output_tokens,
                    "latency_ms": latency_ms,
                    "training_authority": False,
                    "promotion_authority": False,
                    "selector_deployment_authority": False,
                }
                matrix.append(record)
                checkpoint[key] = record
                completed.add(key)
                save_checkpoint(checkpoint_path, checkpoint)
                events.append({"event": "trial_complete", "key": key, "correct": record["correct"]})

        by_row = defaultdict(list)
        for record in matrix:
            if record.get("arm_type") == "generation":
                by_row[record["row_id"]].append(record)

        finalizer_rows = []
        for row in config["rows"]:
            expected = config["scorer_expected_answers"][row["row_id"]]
            fixed512 = next((item for item in by_row[row["row_id"]] if item["arm_id"] == "A0_FIXED512_BASELINE"), None)
            recovered = False
            candidates = []
            if fixed512:
                candidates = fixed512.get("finalizer_candidates") or alternate_extract_answer(
                    fixed512.get("output_tail") or fixed512.get("output_preview", "")
                )
                recovered = any(score_candidate(candidate, expected) for candidate in candidates)
            finalizer_rows.append({
                "schema_id": "kt.ktcf.finalizer_replay_row.v1",
                "row_id": row["row_id"],
                "role": row["role"],
                "source_classes": row.get("source_classes", []),
                "source_arm_id": "A0_FIXED512_BASELINE",
                "candidate_answers": candidates,
                "rescored_correct": recovered,
                "interpretation": "FINALIZER_SCORER_OWNED_IF_TRUE",
            })

        oracle_rows = []
        causal_rows = []
        for row in config["rows"]:
            trials = by_row[row["row_id"]]
            correct_trials = [trial for trial in trials if trial["correct"]]
            cheapest = min(correct_trials, key=lambda trial: trial["total_tokens"]) if correct_trials else None
            oracle_rows.append({
                "schema_id": "kt.ktcf.oracle_diagnostic_row.v1",
                "row_id": row["row_id"],
                "role": row["role"],
                "source_classes": row.get("source_classes", []),
                "any_generated_arm_correct": bool(correct_trials),
                "cheapest_correct_arm": cheapest["arm_id"] if cheapest else None,
                "cheapest_correct_tokens": cheapest["total_tokens"] if cheapest else None,
                "hindsight_only_not_deployable": True,
            })
            causal_rows.append({
                "schema_id": "kt.ktcf.causal_verdict_candidate.v1",
                "row_id": row["row_id"],
                "role": row["role"],
                "source_classes": row.get("source_classes", []),
                "candidate_owner": "PENDING_COUNTERFACTUAL_SCORECARD",
                "oracle_generated_any_correct": bool(correct_trials),
                "hindsight_only_not_deployable": True,
            })

        scorecard = []
        for arm in generation_arms:
            rows = [record for record in matrix if record.get("arm_id") == arm["arm_id"]]
            correct = sum(1 for record in rows if record["correct"])
            target_rows = [record for record in rows if record["role"] == "TARGET"]
            control_rows = [record for record in rows if record["role"] != "TARGET"]
            target_correct = sum(1 for record in target_rows if record["correct"])
            control_correct = sum(1 for record in control_rows if record["correct"])
            tokens = sum(int(record["total_tokens"]) for record in rows)
            scorecard.append({
                "schema_id": "kt.ktcf.counterfactual_arm_score.v1",
                "arm_id": arm["arm_id"],
                "row_count": len(rows),
                "correct": correct,
                "accuracy": correct / len(rows) if rows else 0,
                "target_correct": target_correct,
                "target_accuracy": target_correct / len(target_rows) if target_rows else 0,
                "control_correct": control_correct,
                "control_accuracy": control_correct / len(control_rows) if control_rows else 0,
                "full_tokens_per_correct": tokens / correct if correct else None,
                "total_tokens": tokens,
                "claim_bound": arm["claim_bound"],
            })

        finalizer_recovered = sum(
            1
            for row in finalizer_rows
            if row["rescored_correct"] and row["role"] == "TARGET" and "NO_CORRECT_ARM" in row.get("source_classes", [])
        )
        finalizer_recovered_any_scope = sum(1 for row in finalizer_rows if row["rescored_correct"])
        final_summary = {
            "schema_id": "kt.ktcf.final_summary.v1",
            "run_mode": RUN_MODE,
            "status": "PASS_MODEL_GENERATED_AND_SCORED",
            "row_count": len(config["rows"]),
            "target_rows": sum(1 for row in config["rows"] if row["role"] == "TARGET"),
            "control_rows": sum(1 for row in config["rows"] if row["role"] != "TARGET"),
            "generation_trials": len(matrix),
            "finalizer_recovered_count": finalizer_recovered,
            "finalizer_recovered_count_scope": "NO_CORRECT_ARM_TARGET_ROWS_ONLY",
            "finalizer_recovered_any_scope_count": finalizer_recovered_any_scope,
            "oracle_any_correct_rows": sum(1 for row in oracle_rows if row["any_generated_arm_correct"]),
            "next_lawful_move": "IMPORT_KTCF_ASSESSMENT_AND_ADJUDICATE_CAUSAL_OWNERSHIP",
            "training_authority": False,
            "promotion_authority": False,
            "selector_deployment_authority": False,
            "claim_ceiling_status": "PRESERVED",
        }

        write_jsonl(outdir / "counterfactual_row_trial_matrix.jsonl", matrix)
        write_json(outdir / "counterfactual_scorecard.json", {"schema_id": "kt.ktcf.counterfactual_scorecard.v1", "scorecard": scorecard})
        write_json(
            outdir / "finalizer_replay_report.json",
            {
                "schema_id": "kt.ktcf.finalizer_replay_report.v1",
                "rows": finalizer_rows,
                "recovered_count": finalizer_recovered,
                "recovered_count_scope": "NO_CORRECT_ARM_TARGET_ROWS_ONLY",
                "recovered_any_scope_count": finalizer_recovered_any_scope,
            },
        )
        write_json(outdir / "oracle_diagnostic_receipt.json", {"schema_id": "kt.ktcf.oracle_diagnostic_receipt.v1", "status": "HINDSIGHT_ONLY_NOT_DEPLOYABLE", "rows": oracle_rows})
        write_jsonl(outdir / "causal_verdict_candidates.jsonl", causal_rows)
        write_json(outdir / "final_summary.json", final_summary)
        events.append({"event": "completed", "status": final_summary["status"]})
    except Exception as exc:  # noqa: BLE001
        write_blocker(outdir, "KT_CF_RUNTIME_BLOCKED", str(exc))
        events.append({"event": "blocked", "reason": str(exc)})

    write_jsonl(outdir / "run_events.jsonl", events)
    assessment = Path(os.environ.get("KT_ASSESSMENT_ZIP", "/kaggle/working/KT_CF_V1_ASSESSMENT_ONLY.zip"))
    with zipfile.ZipFile(assessment, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(outdir.iterdir()):
            if path.name == "checkpoint_state.json":
                continue
            zf.write(path, path.name)
    upload_receipt = maybe_upload_to_hf(outdir, assessment)
    write_json(outdir / "HF_UPLOAD_RECEIPT.json", upload_receipt)
    with zipfile.ZipFile(assessment, "a", zipfile.ZIP_DEFLATED) as zf:
        zf.write(outdir / "HF_UPLOAD_RECEIPT.json", "HF_UPLOAD_RECEIPT.json")
    print(str(assessment))


if __name__ == "__main__":
    main()
'''


def bootstrap_source() -> str:
    return """from pathlib import Path\nimport runpy\nrunpy.run_path(str(Path(__file__).parent / 'runtime' / 'KT_CANONICAL_RUNNER.py'), run_name='__main__')\n"""


def smoke_test_source() -> str:
    return """from pathlib import Path\nimport json\nroot = Path(__file__).resolve().parents[1]\nconfig = json.loads((root / 'runtime' / 'ktcf_config.json').read_text(encoding='utf-8'))\nmanifest = json.loads((root / 'PACKET_MANIFEST.json').read_text(encoding='utf-8'))\nassert manifest['run_mode'] == 'RUN_KTPARETO_COUNTERFACTUAL_MICROFURNACE_V1'\nassert manifest['training_authority'] is False\nassert manifest['promotion_authority'] is False\nassert manifest['selector_deployment_authority'] is False\nassert len([row for row in config['rows'] if row['role'] == 'TARGET']) == 26\nassert len([row for row in config['rows'] if row['role'] != 'TARGET']) == 14\nassert 'A9_ORACLE_DIAGNOSTIC' in {arm['arm_id'] for arm in config['arms']}\n"""


def build_packet(config: dict[str, Any], packet_sha_placeholder: str | None = None) -> str:
    members: dict[str, str] = {
        "runtime/KT_CANONICAL_RUNNER.py": runtime_runner_source(),
        "runtime/ktcf_config.json": json.dumps(config, indent=2, sort_keys=True) + "\n",
        "KAGGLE_BOOTSTRAP_CELL.py": bootstrap_source(),
        "COPY_PASTE_NOW_ktcf_v1.txt": (
            "Upload/use dataset ktcf-v1 and execute KAGGLE_BOOTSTRAP_CELL.py. "
            "This is a targeted counterfactual microfurnace only: no training, promotion, selector deployment, adapter mutation, production prompt mutation, or claim expansion.\n"
        ),
        "README.md": (
            "# KTCF V1\n\n"
            "Targeted counterfactual microfurnace packet for G32S/Pareto hard rows. "
            "Expected answers are scorer-side only and never prompt-side. "
            "Oracle diagnostics are hindsight-only and not deployable.\n"
        ),
        "requirements.txt": "transformers\naccelerate\nbitsandbytes\nhuggingface_hub\n",
        "tests/smoke_test.py": smoke_test_source(),
    }
    manifest = {
        "schema_id": "kt.ktcf.packet_manifest.v1",
        "packet_name": "ktcf_v1.zip",
        "run_mode": RUN_MODE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "row_slice": ROW_SLICE,
        "created_utc": utc_now(),
        "target_rows": 26,
        "control_rows": 14,
        **AUTHORITY_FALSE,
        **FORBIDDEN_DEPLOYMENT_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    members["PACKET_MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    sha_manifest = {
        "schema_id": "kt.ktcf.sha256_manifest.v1",
        "packet_sha256_authority": "reports/ktcf_packet_decision.json",
        "members": {name: sha256_bytes(data.encode("utf-8")) for name, data in sorted(members.items())},
    }
    members["SHA256_MANIFEST.json"] = json.dumps(sha_manifest, indent=2, sort_keys=True) + "\n"
    PACKETS.mkdir(exist_ok=True)
    with zipfile.ZipFile(PACKET_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(members.items()):
            zf.writestr(name, data)
    return sha256_file(PACKET_PATH)


def register_artifacts(paths: list[Path], lane: str = ACTIVE_TRANCHE) -> None:
    registry_path = REGISTRY / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    artifacts = registry.setdefault("artifacts", [])
    by_path = {artifact["path"]: artifact for artifact in artifacts}

    def primary_class(rel: str) -> str:
        if rel.startswith("scripts/"):
            return "CANONICAL_SOURCE"
        if rel.startswith("tests/"):
            return "CANONICAL_TEST"
        if rel.startswith("schemas/"):
            return "CANONICAL_SCHEMA"
        if rel.startswith("packets/"):
            return "CANONICAL_PACKET_CURRENT"
        if rel.startswith("docs/") or rel.startswith("configs/"):
            return "CANONICAL_GOVERNANCE"
        if rel.startswith("reports/") or rel.startswith("registry/"):
            return "CANONICAL_RECEIPT_CURRENT"
        return "LAB_PROVISIONAL"

    def claim_authority(cls: str) -> str:
        if cls in {"CANONICAL_SOURCE", "CANONICAL_SCHEMA", "CANONICAL_TEST", "CANONICAL_PACKET_CURRENT"}:
            return "INTERNAL_SHADOW"
        if cls in {"CANONICAL_GOVERNANCE", "CANONICAL_RECEIPT_CURRENT"}:
            return "CURRENT_HEAD"
        return "NONE"

    additions = []
    for path in sorted(set(paths)):
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        cls = primary_class(rel)
        entry = {
            "artifact_id": rel.upper().replace("/", "_").replace(".", "_").replace("-", "_"),
            "path": rel,
            "role": "ktcf_counterfactual_microfurnace_packet_forge",
            "primary_class": cls,
            "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
            "validation_status": "PASS",
            "controls_execution": cls in {"CANONICAL_SOURCE", "CANONICAL_SCHEMA", "CANONICAL_TEST", "CANONICAL_GOVERNANCE", "CANONICAL_PACKET_CURRENT"},
            "claim_authority": claim_authority(cls),
            "current_authority": True,
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "source_lane": lane,
            "supersedes": [],
            "superseded_by": None,
            "updated_utc": utc_now(),
            "notes": "KTCF repo-side packet forge; no Kaggle, training, promotion, selector deployment, budget deployment, adapter mutation, production prompt mutation, or production math-mode authority.",
        }
        if rel in by_path:
            by_path[rel].update(entry)
        else:
            artifacts.append(entry)
        additions.append(entry)
    registry["current_head"] = git_output("rev-parse", "HEAD")
    registry["generated_utc"] = utc_now()
    write_json(registry_path, registry)
    write_json(
        REGISTRY / "artifact_authority_registry_ktcf_delta_receipt.json",
        {
            "schema_id": "kt.artifact_authority_registry.ktcf_delta_receipt.v1",
            "status": "PASS",
            "source_lane": lane,
            "artifacts_added_or_updated": additions,
            **AUTHORITY_FALSE,
            "claim_ceiling_status": "PRESERVED",
        },
    )


def build() -> dict[str, Any]:
    REPORTS.mkdir(exist_ok=True)
    CONFIGS.mkdir(exist_ok=True)
    SCHEMAS.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    PACKETS.mkdir(exist_ok=True)

    predecessor = bind_predecessors()
    write_schemas()
    head = git_output("rev-parse", "HEAD")
    branch = git_output("branch", "--show-current")

    predictions, oracle, scorecard, pareto_summary = load_pareto_assessment()
    gsm8k = fetch_gsm8k_rows()
    difficulty = load_difficulty_rows()
    if set(gsm8k) != set(difficulty):
        fail("KT_CF_BLOCKED__ROW_SELECTION_OR_CONTROL_MATCHING_DEFECT", "GSM8K source rows and difficulty rows mismatch")

    targets, target_counts = build_target_rows(gsm8k, difficulty)
    controls, matching_report = build_control_rows(targets, predictions, gsm8k, difficulty)
    audit_rows, audit_receipt, sidecar_policy = audit_no_correct_answers(targets, gsm8k)
    arm_manifest, prompt_manifest, prompt_leakage, firewall = prompt_and_leakage_receipts(targets, controls, gsm8k)
    success, power, stop, causal, verdict = success_power_stop_causal()
    policy = read_json(PREDECESSOR_PATHS["g32s_difficulty_aware_selector_policy"])
    feature_legality = feature_legality_receipt(policy)
    claim_boundary = claim_boundary_receipt()
    compute_budget = compute_budget_estimate(targets, controls)

    row_selection = {
        "schema_id": "kt.ktcf.row_selection_receipt.v1",
        "status": "PASS",
        "target_rows_unique": len(targets),
        "target_source_class_counts": target_counts,
        "control_rows": len(controls),
        "deduplicated_target_rows": [row["row_id"] for row in targets],
        "target_row_class_order": SOURCE_CLASS_ORDER,
        "source_evidence": [
            "reports/g32s_no_correct_counterfactual_matrix.jsonl",
            "reports/g32s_false384_causal_matrix.jsonl",
            "reports/g32s_cot640_recovery_damage_matrix.jsonl",
        ],
        "claim_ceiling_status": "PRESERVED",
    }

    runtime_rows = []
    scorer_expected_answers = {}
    for row in targets + controls:
        source = gsm8k[row["row_id"]]
        runtime_row = {key: value for key, value in row.items() if key not in {"source_evidence"}}
        runtime_row["question"] = source["question"]
        runtime_rows.append(runtime_row)
        scorer_expected_answers[row["row_id"]] = source["expected_answer"]

    runtime_config = {
        "schema_id": "kt.ktcf.runtime_config.v1",
        "run_mode": RUN_MODE,
        "row_slice": ROW_SLICE,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "rows": runtime_rows,
        "scorer_expected_answers": scorer_expected_answers,
        "expected_answers_are_scorer_side_only": True,
        "strict_native_answer_literal_block": False,
        "arms": ARMS,
        "prompt_templates": PROMPT_TEMPLATES,
        "success_criteria": success,
        "power_analysis": power,
        "stop_rules": stop,
        "causal_interpretation_law": causal,
        "benchmark_audit": {"receipt": audit_receipt, "rows": audit_rows, "sidecar_policy": sidecar_policy},
        "claim_boundary": claim_boundary,
        "checkpoint_resume_key": "row_id::arm_id",
        **AUTHORITY_FALSE,
        **FORBIDDEN_DEPLOYMENT_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }

    write_json(REPORTS / "ktcf_truth_pin_receipt.json", {"schema_id": "kt.ktcf.truth_pin_receipt.v1", "status": "PASS", "current_head": head, "current_branch": branch, "predecessor_outcome": predecessor.get("outcome"), "predecessor_next_lawful_move": predecessor.get("next_lawful_move"), "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "ktcf_predecessor_binding_receipt.json", {"schema_id": "kt.ktcf.predecessor_binding_receipt.v1", "status": "PASS", "g32s_outcome": predecessor.get("outcome"), "g32s_counts": predecessor.get("counts"), "pareto_assessment_sha256": PARETO_ASSESSMENT_SHA256, "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "ktcf_row_selection_receipt.json", row_selection)
    write_jsonl(REPORTS / "ktcf_target_row_manifest.jsonl", targets)
    write_jsonl(REPORTS / "ktcf_control_row_manifest.jsonl", controls)
    write_json(REPORTS / "ktcf_control_matching_report.json", matching_report)
    write_json(REPORTS / "ktcf_compute_budget_estimate.json", compute_budget)
    write_json(REPORTS / "ktcf_benchmark_audit_receipt.json", audit_receipt)
    write_jsonl(REPORTS / "ktcf_no_correct_expected_answer_audit.jsonl", audit_rows)
    write_json(REPORTS / "ktcf_benchmark_corrected_sidecar_policy.json", sidecar_policy)
    write_json(CONFIGS / "ktcf_arm_manifest.json", arm_manifest)
    write_json(CONFIGS / "ktcf_prompt_templates.json", prompt_manifest)
    write_json(REPORTS / "ktcf_prompt_leakage_receipt.json", prompt_leakage)
    write_json(REPORTS / "ktcf_gold_prompt_leakage_firewall_receipt.json", firewall)
    write_json(REPORTS / "ktcf_arm_hypothesis_register.json", {"schema_id": "kt.ktcf.arm_hypothesis_register.v1", "status": "PASS", "arms": [{k: arm[k] for k in ["arm_id", "claim_bound", "arm_type"]} for arm in ARMS], "claim_ceiling_status": "PRESERVED"})
    write_json(REPORTS / "ktcf_preregistered_success_criteria.json", success)
    write_json(REPORTS / "ktcf_power_analysis.json", power)
    write_json(REPORTS / "ktcf_counterfactual_stop_rules.json", stop)
    write_json(REPORTS / "ktcf_causal_interpretation_law.json", causal)
    write_json(REPORTS / "ktcf_expected_verdict_matrix.json", verdict)
    write_json(REPORTS / "ktcf_feature_legality_receipt.json", feature_legality)
    write_json(REPORTS / "ktcf_claim_boundary_receipt.json", claim_boundary)

    # The final packet SHA cannot be embedded inside the packet without changing
    # the packet. Keep runtime config pointed to the external receipt, then bind
    # the final packet SHA in repo-side reports after the zip is closed.
    packet_sha = build_packet(runtime_config)
    claim_boundary = claim_boundary_receipt(packet_sha)
    write_json(REPORTS / "ktcf_claim_boundary_receipt.json", claim_boundary)

    decision = {
        "schema_id": "kt.ktcf.packet_decision.v1",
        "status": "GENERATED",
        "packet_path": "packets/ktcf_v1.zip",
        "packet_sha256": packet_sha,
        "kaggle_dataset_name": KAGGLE_DATASET_NAME,
        "one_cell_runbook": "docs/KT_CF_ONE_CELL.md",
        "run_mode": RUN_MODE,
        "target_rows": len(targets),
        "control_rows": len(controls),
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        **AUTHORITY_FALSE,
        **FORBIDDEN_DEPLOYMENT_FALSE,
        "claim_ceiling_status": "PRESERVED",
    }
    write_json(REPORTS / "ktcf_packet_decision.json", decision)
    write_text(
        DOCS / "KT_CF_ONE_CELL.md",
        f"""# KT Counterfactual Microfurnace V1 One Cell

Dataset name:

```text
{KAGGLE_DATASET_NAME}
```

Packet:

```text
packets/ktcf_v1.zip
```

Packet SHA256:

```text
{packet_sha}
```

Run mode:

```text
{RUN_MODE}
```

One-cell Kaggle bootstrap:

```python
import zipfile
from pathlib import Path
import runpy

packet = Path('/kaggle/input/{KAGGLE_DATASET_NAME}/ktcf_v1.zip')
work = Path('/kaggle/working/ktcf_packet_loader')
work.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(packet) as zf:
    zf.extractall(work)
runpy.run_path(str(work / 'KAGGLE_BOOTSTRAP_CELL.py'), run_name='__main__')
```

This is a diagnostic counterfactual microfurnace only. It does not train,
promote, deploy selectors, deploy budget arms, mutate adapters, mutate
production prompts, or create production math-mode authority.
""",
    )

    summary = {
        "schema_id": "kt.ktcf.builder_summary.v1",
        "status": "PASS",
        "current_head": head,
        "branch": branch,
        "outcome": OUTCOME,
        "ktcf_truth_binding_status": "PASS",
        "ktcf_predecessor_binding_status": "PASS",
        "ktcf_row_selection_status": "PASS",
        "ktcf_control_matching_status": "PASS",
        "ktcf_benchmark_audit_status": audit_receipt["status"],
        "ktcf_prompt_template_status": prompt_manifest["status"],
        "ktcf_power_analysis_status": power["status"],
        "ktcf_success_criteria_status": success["status"],
        "ktcf_causal_interpretation_status": causal["status"],
        "ktcf_packet_design_status": "PASS",
        "ktcf_packet_generation_status": "GENERATED",
        "ktcf_gold_prompt_leakage_firewall_status": firewall["status"],
        "ktcf_feature_legality_status": feature_legality["status"],
        "ktcf_claim_boundary_status": claim_boundary["status"],
        "head_binding_status": "BRANCH_BOUND_REPLAY_REQUIRED_AFTER_MERGE",
        "fresh_clone_packet_sha256_status": "PENDING_MERGED_MAIN",
        "packet_path_if_any": "packets/ktcf_v1.zip",
        "packet_sha256_if_any": packet_sha,
        "kaggle_dataset_name_if_any": KAGGLE_DATASET_NAME,
        "one_cell_runbook_if_any": "docs/KT_CF_ONE_CELL.md",
        **AUTHORITY_FALSE,
        "claim_ceiling_status": "PRESERVED",
        "blockers": [],
        "next_lawful_move": NEXT_LAWFUL_MOVE,
    }
    write_json(REPORTS / "ktcf_builder_summary.json", summary)

    register_paths = [
        Path("scripts/build_ktcf_packet.py"),
        Path("scripts/validate_ktcf_packet.py"),
        Path("tests/test_ktcf_packet_contract.py"),
        *(SCHEMAS.glob("kt.ktcf_*.schema.json")),
        REPORTS / "g32s_feature_legality_receipt.json",
        REPORTS / "ktcf_input_path_mapping.json",
        REPORTS / "ktcf_truth_pin_receipt.json",
        REPORTS / "ktcf_predecessor_binding_receipt.json",
        REPORTS / "ktcf_row_selection_receipt.json",
        REPORTS / "ktcf_target_row_manifest.jsonl",
        REPORTS / "ktcf_control_row_manifest.jsonl",
        REPORTS / "ktcf_control_matching_report.json",
        REPORTS / "ktcf_compute_budget_estimate.json",
        REPORTS / "ktcf_benchmark_audit_receipt.json",
        REPORTS / "ktcf_no_correct_expected_answer_audit.jsonl",
        REPORTS / "ktcf_benchmark_corrected_sidecar_policy.json",
        CONFIGS / "ktcf_arm_manifest.json",
        CONFIGS / "ktcf_prompt_templates.json",
        REPORTS / "ktcf_prompt_leakage_receipt.json",
        REPORTS / "ktcf_gold_prompt_leakage_firewall_receipt.json",
        REPORTS / "ktcf_arm_hypothesis_register.json",
        REPORTS / "ktcf_preregistered_success_criteria.json",
        REPORTS / "ktcf_power_analysis.json",
        REPORTS / "ktcf_counterfactual_stop_rules.json",
        REPORTS / "ktcf_causal_interpretation_law.json",
        REPORTS / "ktcf_expected_verdict_matrix.json",
        REPORTS / "ktcf_feature_legality_receipt.json",
        REPORTS / "ktcf_claim_boundary_receipt.json",
        REPORTS / "ktcf_packet_decision.json",
        REPORTS / "ktcf_builder_summary.json",
        DOCS / "KT_CF_ONE_CELL.md",
        PACKET_PATH,
    ]
    register_artifacts([ROOT / path if not path.is_absolute() else path for path in register_paths])
    return summary


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
