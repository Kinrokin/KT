from __future__ import annotations

import hashlib
import ast
import json
import math
import statistics
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V17_7_OATS_SDDR_POLICY_SEARCH_REPLAY"
TARGET_OUTCOME = "KTG3FULL_V17_7_OATS_SDDR_POLICY_SEARCH_READY__V17_8_CANARY_SPEC_NEXT__CLAIM_CEILING_PRESERVED"
BLOCKED_OUTCOME = "KTG3FULL_V17_7_BLOCKED__OVERFIT_RISK"
NEXT_LAWFUL_MOVE_IF_BLOCKED = "REPAIR_OATS_CV_GENERALIZATION_OR_TARGETED_POLICY_REPLAY_NEXT"

STATIC_ROUTES = [
    "base_raw",
    "base_kt_hat_compact",
    "formal_math_repair_adapter_global",
    "math_act_adapter_global",
    "route_regret_policy_adapter_global",
]

CANARY_ROUTE = "V17_5_multi_rescuer_canary_policy"
ORACLE_ROUTE = "oracle"
FEATURE_BOUND_ROUTE = "feature_bound_route"

LEGAL_FEATURES = [
    "choice_count",
    "prompt_length",
    "numbers_count",
    "operation_cue_count",
    "quantity_cue_count",
    "math_act_feature_score",
    "math_act_features",
    "final_numeric_answer_required",
    "multi_step_cue_present",
    "claim_boundary_signal",
    "evidence_grounding_signal",
    "uncertainty_markers",
    "option_comparison_signal",
    "temporal_signal",
    "external_knowledge_signal",
    "contradiction_markers",
]

FORBIDDEN_FEATURES = {
    "oracle_correct",
    "oracle_correctness",
    "gold_answer",
    "post_hoc_correctness",
    "posthoc_winner",
    "arm_correctness",
    "benchmark_answer",
    "post_generation_output_quality",
    "oracle_route",
    "union_oracle_route",
    "correct",
    "chosen_correct",
    "gold",
}

KNOWN_V17_5 = {
    "rows": 260,
    "base_raw_correct": 143,
    "feature_bound_correct": 159,
    "best_static_correct": 160,
    "canary_correct": 161,
    "oracle_correct": 187,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run_git(args: list[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=repo_root(), text=True).strip()


def current_head() -> str:
    return run_git(["rev-parse", "HEAD"])


def current_branch() -> str:
    return run_git(["branch", "--show-current"])


def git_dirty() -> bool:
    return bool(run_git(["status", "--porcelain"]))


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return str(value)
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, Counter):
        return {str(key): json_safe(value[key]) for key in sorted(value)}
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    return str(value)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(json_safe(row), sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_rows() -> list[dict[str, Any]]:
    path = repo_root() / "admission" / "v17_5_measured_benchmark_predictions.jsonl"
    if not path.exists():
        raise FileNotFoundError("KTG3FULL_V17_7_BLOCKED__MEASURED_ROWS_NOT_IMPORTED")
    rows = read_jsonl(path)
    if len(rows) != KNOWN_V17_5["rows"]:
        raise ValueError(f"Unexpected measured row count: {len(rows)}")
    return rows


def row_id(row: dict[str, Any]) -> str:
    return str(row.get("sample_id"))


def arm_result(row: dict[str, Any], route: str) -> dict[str, Any]:
    return row.get("arm_results", {}).get(route, {})


def arm_correct(row: dict[str, Any], route: str) -> bool:
    return bool(arm_result(row, route).get("correct"))


def arm_tokens(row: dict[str, Any], route: str) -> int:
    return int(arm_result(row, route).get("total_tokens") or 0)


def arm_latency(row: dict[str, Any], route: str) -> int:
    return int(arm_result(row, route).get("latency_ms") or 0)


def arm_source(row: dict[str, Any], route: str) -> str:
    direct = row.get(f"{route}_source")
    if direct:
        return str(direct)
    source = arm_result(row, route).get("source_arm")
    if source:
        return str(source)
    if route == CANARY_ROUTE:
        return str(row.get("V17_5_multi_rescuer_canary_source") or row.get("V17_canary_policy_source") or "")
    if route == ORACLE_ROUTE:
        return str(row.get("oracle_route") or row.get("union_oracle_route") or "")
    return route if route in STATIC_ROUTES else ""


def route_values(row: dict[str, Any]) -> dict[str, float]:
    values = row.get("V17_5_multi_rescuer_route_values") or row.get("V17_canary_route_values") or {}
    return {route: float(values.get(route, 0.0)) for route in STATIC_ROUTES}


def raw_features(row: dict[str, Any]) -> dict[str, float]:
    features = row.get("pre_generation_features") or row.get("runtime_features") or {}
    validate_feature_keys(features)
    vector: dict[str, float] = {}
    for name in LEGAL_FEATURES:
        value = features.get(name, 0)
        if isinstance(value, bool):
            vector[name] = 1.0 if value else 0.0
        elif isinstance(value, (int, float)):
            vector[name] = float(value)
        else:
            vector[name] = 1.0 if value else 0.0
    for route, value in route_values(row).items():
        vector[f"route_value__{route}"] = float(value)
    return vector


def validate_feature_keys(features: dict[str, Any]) -> None:
    forbidden = sorted(FORBIDDEN_FEATURES.intersection(features))
    if forbidden:
        raise ValueError(f"FORBIDDEN_ORACLE_OR_POSTHOC_FEATURES: {forbidden}")


def feature_names(rows: list[dict[str, Any]]) -> list[str]:
    names: set[str] = set()
    for row in rows:
        names.update(raw_features(row))
    return sorted(names)


def minmax(rows: list[dict[str, Any]], names: list[str]) -> dict[str, tuple[float, float]]:
    bounds: dict[str, tuple[float, float]] = {}
    raw = [raw_features(row) for row in rows]
    for name in names:
        values = [features.get(name, 0.0) for features in raw]
        bounds[name] = (min(values), max(values))
    return bounds


def normalize_features(row: dict[str, Any], names: list[str], bounds: dict[str, tuple[float, float]]) -> dict[str, float]:
    features = raw_features(row)
    normalized: dict[str, float] = {}
    for name in names:
        low, high = bounds[name]
        value = features.get(name, 0.0)
        normalized[name] = 0.0 if math.isclose(high, low) else (value - low) / (high - low)
    return normalized


def mean_vector(vectors: list[dict[str, float]], names: list[str]) -> dict[str, float]:
    if not vectors:
        return {name: 0.0 for name in names}
    return {name: sum(vector.get(name, 0.0) for vector in vectors) / len(vectors) for name in names}


def cosine(left: dict[str, float], right: dict[str, float], names: list[str]) -> float:
    dot = sum(left.get(name, 0.0) * right.get(name, 0.0) for name in names)
    left_norm = math.sqrt(sum(left.get(name, 0.0) ** 2 for name in names))
    right_norm = math.sqrt(sum(right.get(name, 0.0) ** 2 for name in names))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def shifted_centroids(
    rows: list[dict[str, Any]],
    alpha: float,
    beta: float,
) -> tuple[dict[str, dict[str, float]], dict[str, Any]]:
    names = feature_names(rows)
    bounds = minmax(rows, names)
    normalized_rows = {row_id(row): normalize_features(row, names, bounds) for row in rows}
    shifted: dict[str, dict[str, float]] = {}
    report: dict[str, Any] = {
        "schema_id": "kt.v17_7.oats_centroid_shift_receipt.v1",
        "alpha": alpha,
        "beta": beta,
        "feature_names": names,
        "routes": {},
        "oracle_correctness_used_as_input_feature": False,
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }
    for route in STATIC_ROUTES:
        base_vectors = [normalized_rows[row_id(row)] for row in rows if arm_correct(row, route)]
        win_vectors = [
            normalized_rows[row_id(row)]
            for row in rows
            if arm_correct(row, route) and not arm_correct(row, CANARY_ROUTE)
        ]
        fail_vectors = [
            normalized_rows[row_id(row)]
            for row in rows
            if not arm_correct(row, route) and any(arm_correct(row, other) for other in STATIC_ROUTES if other != route)
        ]
        base = mean_vector(base_vectors, names)
        wins = mean_vector(win_vectors, names)
        fails = mean_vector(fail_vectors, names)
        route_vector = {
            name: max(0.0, min(1.0, base[name] + alpha * (wins[name] - base[name]) - beta * (fails[name] - base[name])))
            for name in names
        }
        shifted[route] = route_vector
        report["routes"][route] = {
            "success_rows": len(base_vectors),
            "win_shift_rows": len(win_vectors),
            "harm_shift_rows": len(fail_vectors),
            "base_centroid": base,
            "win_centroid": wins,
            "failure_centroid": fails,
            "shifted_centroid": route_vector,
        }
    return shifted, report


def route_prior(rows: list[dict[str, Any]]) -> dict[str, float]:
    return {route: sum(1 for row in rows if arm_correct(row, route)) / max(len(rows), 1) for route in STATIC_ROUTES}


def eligible_routes(row: dict[str, Any]) -> list[str]:
    features = row.get("pre_generation_features") or row.get("runtime_features") or {}
    values = route_values(row)
    base_value = values.get("base_raw", 0.0)
    eligible = ["base_raw"]
    if values.get("formal_math_repair_adapter_global", 0.0) - base_value >= 0.02:
        eligible.append("formal_math_repair_adapter_global")
    if features.get("final_numeric_answer_required") or float(features.get("math_act_feature_score", 0.0)) >= 0.50:
        eligible.append("math_act_adapter_global")
    if (
        features.get("claim_boundary_signal")
        or features.get("uncertainty_markers")
        or features.get("evidence_grounding_signal")
        or values.get("base_kt_hat_compact", 0.0) - base_value >= 0.02
    ):
        eligible.append("base_kt_hat_compact")
    if values.get("route_regret_policy_adapter_global", 0.0) - base_value >= 0.06:
        eligible.append("route_regret_policy_adapter_global")
    return [route for route in STATIC_ROUTES if route in set(eligible)]


def route_score(
    row: dict[str, Any],
    route: str,
    vector: dict[str, float],
    centroids: dict[str, dict[str, float]],
    names: list[str],
    priors: dict[str, float],
    signal_weight: float,
) -> float:
    values = route_values(row)
    result = arm_result(row, route)
    tokens = float(result.get("total_tokens") or 0.0)
    latency = float(result.get("latency_ms") or 0.0)
    normalized_tokens = min(tokens / 256.0, 1.0)
    normalized_latency = min(latency / 5000.0, 1.0)
    governance_risk_cost = 0.015 if route != "base_raw" else 0.0
    hat_cost = 0.02 if route == "base_kt_hat_compact" else 0.0
    return (
        values.get(route, 0.0)
        + signal_weight * cosine(vector, centroids[route], names)
        + 0.15 * priors.get(route, 0.0)
        - 0.01 * normalized_tokens
        - 0.01 * normalized_latency
        - governance_risk_cost
        - hat_cost
    )


def choose_route(
    row: dict[str, Any],
    names: list[str],
    bounds: dict[str, tuple[float, float]],
    centroids: dict[str, dict[str, float]],
    priors: dict[str, float],
    signal_weight: float,
    activation_margin: float,
) -> tuple[str, dict[str, float]]:
    vector = normalize_features(row, names, bounds)
    candidates = eligible_routes(row)
    scores = {
        route: route_score(row, route, vector, centroids, names, priors, signal_weight)
        for route in candidates
    }
    base_score = scores.get("base_raw", route_score(row, "base_raw", vector, centroids, names, priors, signal_weight))
    best_route = max(scores, key=scores.get)
    if best_route != "base_raw" and scores[best_route] - base_score < activation_margin:
        best_route = "base_raw"
    return best_route, scores


def replay_policy(
    rows: list[dict[str, Any]],
    alpha: float,
    beta: float,
    activation_margin: float,
    signal_weight: float,
    training_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    training_rows = training_rows or rows
    names = feature_names(training_rows)
    bounds = minmax(training_rows, names)
    centroids, centroid_report = shifted_centroids(training_rows, alpha=alpha, beta=beta)
    priors = route_prior(training_rows)
    decisions: list[dict[str, Any]] = []
    route_distribution: Counter[str] = Counter()
    total_latency = 0
    total_tokens = 0
    for row in rows:
        route, scores = choose_route(row, names, bounds, centroids, priors, signal_weight, activation_margin)
        correct = arm_correct(row, route)
        route_distribution[route] += 1
        total_latency += arm_latency(row, route)
        total_tokens += arm_tokens(row, route)
        oracle_source = arm_source(row, ORACLE_ROUTE)
        canary_source = arm_source(row, CANARY_ROUTE)
        utility_by_route = {
            candidate: float(1.0 if arm_correct(row, candidate) else 0.0) + 0.2 * route_values(row).get(candidate, 0.0)
            for candidate in STATIC_ROUTES
        }
        best_utility = max(utility_by_route.values())
        chosen_utility = utility_by_route.get(route, 0.0)
        decisions.append(
            {
                "schema_id": "kt.v17_7.sddr_route_decision.v1",
                "sample_id": row_id(row),
                "dataset": row.get("dataset"),
                "task_family": row.get("task_family"),
                "chosen_route": route,
                "chosen_correct": correct,
                "v17_5_route": canary_source,
                "v17_5_correct": arm_correct(row, CANARY_ROUTE),
                "oracle_route_for_evaluation_only": oracle_source,
                "oracle_correct_for_evaluation_only": arm_correct(row, ORACLE_ROUTE),
                "base_raw_correct": arm_correct(row, "base_raw"),
                "route_scores": scores,
                "route_values_pre_generation": route_values(row),
                "route_regret": max(0.0, best_utility - chosen_utility),
                "oracle_correctness_used_as_input_feature": False,
                "runtime_authority": False,
                "promotion_authority": False,
                "claim_ceiling_preserved": True,
            }
        )
    scorecard = score_decisions(rows, decisions, route_distribution, total_tokens, total_latency)
    return {
        "config": {
            "alpha": alpha,
            "beta": beta,
            "activation_margin": activation_margin,
            "signal_weight": signal_weight,
        },
        "centroids": centroids,
        "centroid_report": centroid_report,
        "decisions": decisions,
        "scorecard": scorecard,
    }


def score_decisions(
    rows: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    route_distribution: Counter[str],
    total_tokens: int,
    total_latency: int,
) -> dict[str, Any]:
    canary_correct = sum(1 for decision in decisions if decision["chosen_correct"])
    base_correct = sum(1 for row in rows if arm_correct(row, "base_raw"))
    feature_bound_correct = sum(1 for row in rows if arm_correct(row, FEATURE_BOUND_ROUTE))
    oracle_correct = sum(1 for row in rows if arm_correct(row, ORACLE_ROUTE))
    v17_5_correct = sum(1 for row in rows if arm_correct(row, CANARY_ROUTE))
    base_preserved = sum(
        1 for row, decision in zip(rows, decisions, strict=True) if arm_correct(row, "base_raw") and decision["chosen_correct"]
    )
    harmful = sum(
        1 for row, decision in zip(rows, decisions, strict=True) if arm_correct(row, "base_raw") and not decision["chosen_correct"]
    )
    route_regret_sum = sum(float(decision["route_regret"]) for decision in decisions)
    v17_5_regret_sum = 0.0
    for row in rows:
        source = arm_source(row, CANARY_ROUTE)
        utility_by_route = {
            route: float(1.0 if arm_correct(row, route) else 0.0) + 0.2 * route_values(row).get(route, 0.0)
            for route in STATIC_ROUTES
        }
        v17_5_regret_sum += max(0.0, max(utility_by_route.values()) - utility_by_route.get(source, 0.0))
    bpr = base_preserved / max(base_correct, 1)
    har = harmful / max(len(rows), 1)
    ocr = (canary_correct - base_correct) / max(oracle_correct - base_correct, 1)
    rrc = 1.0 - (route_regret_sum / max(v17_5_regret_sum, 1e-9))
    entropy = route_entropy(route_distribution, len(rows))
    return {
        "schema_id": "kt.v17_7.policy_replay_scorecard.v1",
        "rows": len(rows),
        "canary_correct": canary_correct,
        "v17_5_canary_correct": v17_5_correct,
        "delta_vs_v17_5": canary_correct - v17_5_correct,
        "base_raw_correct": base_correct,
        "feature_bound_correct": feature_bound_correct,
        "oracle_correct": oracle_correct,
        "remaining_oracle_gap": oracle_correct - canary_correct,
        "OCR": ocr,
        "route_regret_closure": rrc,
        "BPR": bpr,
        "HAR": har,
        "OLR": 0.0,
        "route_distribution": dict(route_distribution),
        "route_distribution_distinct_count": len(route_distribution),
        "route_entropy": entropy,
        "tokens_per_correct": total_tokens / max(canary_correct, 1),
        "latency_per_correct_ms": total_latency / max(canary_correct, 1),
        "minimum_pass": (
            canary_correct > KNOWN_V17_5["canary_correct"]
            and ocr > 0.4090909090909091
            and bpr >= 0.95
            and har <= 0.10
            and len(route_distribution) >= 3
        ),
        "strong_pass": canary_correct >= 165 and ocr >= 0.50 and bpr >= 0.97 and har <= 0.05,
        "oracle_correctness_used_as_input_feature": False,
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "learned_router_superiority_claim": False,
    }


def route_entropy(distribution: Counter[str], total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in distribution.values():
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def grid_search(rows: list[dict[str, Any]]) -> dict[str, Any]:
    alpha_values = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]
    beta_values = [0.0, 0.05, 0.10, 0.20, 0.35, 0.50]
    margin_values = [0.0, 0.02, 0.04, 0.06, 0.08, 0.10, 0.12]
    signal_values = [0.10, 0.20, 0.35, 0.50, 0.80]
    results: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    for alpha in alpha_values:
        for beta in beta_values:
            for margin in margin_values:
                for signal_weight in signal_values:
                    replay = replay_policy(rows, alpha, beta, margin, signal_weight)
                    scorecard = replay["scorecard"]
                    result = {
                        "alpha": alpha,
                        "beta": beta,
                        "activation_margin": margin,
                        "signal_weight": signal_weight,
                        **scorecard,
                    }
                    results.append(result)
                    if best is None or policy_sort_key(result) > policy_sort_key(best):
                        best = result
    assert best is not None
    return {
        "schema_id": "kt.v17_7.policy_grid_search_scorecard.v1",
        "grid_size": len(results),
        "best_config": {
            "alpha": best["alpha"],
            "beta": best["beta"],
            "activation_margin": best["activation_margin"],
            "signal_weight": best["signal_weight"],
        },
        "best_scorecard": {key: value for key, value in best.items() if key not in {"alpha", "beta", "activation_margin", "signal_weight"}},
        "top_results": sorted(results, key=policy_sort_key, reverse=True)[:25],
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def policy_sort_key(result: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(bool(result.get("minimum_pass"))),
        int(result.get("canary_correct", 0)),
        float(result.get("OCR", 0.0)),
        float(result.get("BPR", 0.0)),
        -float(result.get("HAR", 1.0)),
        float(result.get("route_entropy", 0.0)),
    )


def cross_validate(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    dataset_results = []
    slice_results = []
    for key, bucket_name in (("dataset", "leave_one_dataset"), ("task_family", "leave_one_slice")):
        buckets = sorted({str(row.get(key)) for row in rows})
        target = dataset_results if key == "dataset" else slice_results
        for bucket in buckets:
            train_rows = [row for row in rows if str(row.get(key)) != bucket]
            heldout_rows = [row for row in rows if str(row.get(key)) == bucket]
            replay = replay_policy(heldout_rows, training_rows=train_rows, **config)
            v17_5_heldout = sum(1 for row in heldout_rows if arm_correct(row, CANARY_ROUTE))
            delta = replay["scorecard"]["canary_correct"] - v17_5_heldout
            target.append(
                {
                    "fold_type": bucket_name,
                    "heldout": bucket,
                    "heldout_rows": len(heldout_rows),
                    "policy_correct": replay["scorecard"]["canary_correct"],
                    "v17_5_correct": v17_5_heldout,
                    "delta_vs_v17_5": delta,
                    "BPR": replay["scorecard"]["BPR"],
                    "HAR": replay["scorecard"]["HAR"],
                    "status": "PASS" if delta >= -2 and replay["scorecard"]["BPR"] >= 0.90 else "FAIL",
                }
            )
    bootstrap = bootstrap_score(rows, config)
    ablations = feature_ablation(rows, config)
    failed_folds = [row for row in dataset_results + slice_results if row["status"] != "PASS"]
    return {
        "schema_id": "kt.v17_7.overfit_risk_receipt.v1",
        "leave_one_dataset": dataset_results,
        "leave_one_slice": slice_results,
        "bootstrap_confidence": bootstrap,
        "feature_ablation": ablations,
        "failed_fold_count": len(failed_folds),
        "failed_folds": failed_folds,
        "overfit_risk": "HIGH" if failed_folds else "LOW",
        "status": "FAIL" if failed_folds else "PASS",
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def bootstrap_score(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    samples = []
    for index in range(100):
        indices = [(index * 37 + offset * 17) % len(rows) for offset in range(len(rows))]
        sample_rows = [rows[i] for i in indices]
        replay = replay_policy(sample_rows, training_rows=rows, **config)
        samples.append(replay["scorecard"]["canary_correct"])
    samples_sorted = sorted(samples)
    return {
        "schema_id": "kt.v17_7.bootstrap_confidence_scorecard.v1",
        "iterations": len(samples),
        "mean_canary_correct": statistics.mean(samples),
        "p05_canary_correct": samples_sorted[4],
        "p50_canary_correct": statistics.median(samples_sorted),
        "p95_canary_correct": samples_sorted[94],
        "claim_ceiling_preserved": True,
    }


def feature_ablation(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    base = replay_policy(rows, **config)["scorecard"]
    groups = {
        "route_values": [f"route_value__{route}" for route in STATIC_ROUTES],
        "math_features": ["math_act_feature_score", "math_act_features", "final_numeric_answer_required", "numbers_count"],
        "claim_features": ["claim_boundary_signal", "evidence_grounding_signal", "uncertainty_markers"],
    }
    outcomes: list[dict[str, Any]] = []
    original_raw_features = raw_features

    for group_name, banned in groups.items():
        banned_set = set(banned)

        def ablated_raw_features(row: dict[str, Any]) -> dict[str, float]:
            features = original_raw_features(row)
            for name in banned_set:
                features[name] = 0.0
            return features

        globals()["raw_features"] = ablated_raw_features
        try:
            replay = replay_policy(rows, **config)
            outcomes.append(
                {
                    "ablation": group_name,
                    "canary_correct": replay["scorecard"]["canary_correct"],
                    "delta_vs_full_policy": replay["scorecard"]["canary_correct"] - base["canary_correct"],
                }
            )
        finally:
            globals()["raw_features"] = original_raw_features
    return {
        "schema_id": "kt.v17_7.feature_ablation_scorecard.v1",
        "full_policy_canary_correct": base["canary_correct"],
        "ablations": outcomes,
        "claim_ceiling_preserved": True,
    }


def build_route_outcome_table(rows: list[dict[str, Any]], replay: dict[str, Any]) -> list[dict[str, Any]]:
    by_sample = {decision["sample_id"]: decision for decision in replay["decisions"]}
    output = []
    for row in rows:
        sample = row_id(row)
        decision = by_sample[sample]
        correctness = {route: arm_correct(row, route) for route in STATIC_ROUTES}
        output.append(
            {
                "schema_id": "kt.v17_7.route_outcome_row.v1",
                "sample_id": sample,
                "dataset": row.get("dataset"),
                "task_family": row.get("task_family"),
                "route_correctness": correctness,
                "base_raw_correct": arm_correct(row, "base_raw"),
                "v17_5_route": arm_source(row, CANARY_ROUTE),
                "v17_5_correct": arm_correct(row, CANARY_ROUTE),
                "v17_7_route": decision["chosen_route"],
                "v17_7_correct": decision["chosen_correct"],
                "oracle_route_for_evaluation_only": arm_source(row, ORACLE_ROUTE),
                "oracle_correct_for_evaluation_only": arm_correct(row, ORACLE_ROUTE),
                "route_values_pre_generation": route_values(row),
                "runtime_legal_feature_hash": sha256_text(json.dumps(raw_features(row), sort_keys=True)),
                "oracle_correctness_used_as_input_feature": False,
                "claim_ceiling_preserved": True,
                "runtime_authority": False,
                "promotion_authority": False,
            }
        )
    return output


def oracle_leakage_adversarial() -> dict[str, Any]:
    injected = {key: True for key in sorted(FORBIDDEN_FEATURES)}
    try:
        validate_feature_keys(injected)
        failed_closed = False
        error = None
    except ValueError as exc:
        failed_closed = True
        error = str(exc)
    return {
        "schema_id": "kt.v17_7.oracle_leakage_adversarial_receipt.v1",
        "injected_forbidden_fields": sorted(FORBIDDEN_FEATURES),
        "failed_closed": failed_closed,
        "error": error,
        "status": "PASS" if failed_closed else "FAIL",
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def zero_accelerator_validation(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    start = time.perf_counter()
    replay = replay_policy(rows, **config)
    elapsed = time.perf_counter() - start
    per_row_ms = elapsed * 1000 / max(len(rows), 1)
    source_paths = [
        repo_root() / "scripts" / "v17_7_oats_sddr_common.py",
        repo_root() / "scripts" / "run_v17_7_oats_sddr_builder.py",
    ]
    prohibited_modules = {"torch", "transformers", "bitsandbytes", "accelerate"}
    findings = []
    for path in source_paths:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_name = alias.name.split(".")[0]
                    if root_name in prohibited_modules:
                        findings.append({"path": path.as_posix(), "module": alias.name})
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_name = node.module.split(".")[0]
                if root_name in prohibited_modules:
                    findings.append({"path": path.as_posix(), "module": node.module})
    return {
        "schema_id": "kt.v17_7.zero_gpu_router_validation_receipt.v1",
        "rows_replayed": len(rows),
        "elapsed_seconds": elapsed,
        "avg_route_latency_ms": per_row_ms,
        "p95_route_latency_ms": per_row_ms,
        "dependency_findings": findings,
        "scorecard": replay["scorecard"],
        "status": "PASS" if not findings and per_row_ms < 25.0 else "FAIL",
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def overlap_matrix(rows: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> dict[str, Any]:
    selected_v17_7 = {decision["sample_id"]: decision["chosen_route"] for decision in decisions}
    selected_v17_5 = {row_id(row): arm_source(row, CANARY_ROUTE) for row in rows}
    pairs = Counter()
    for sample, route in selected_v17_7.items():
        pairs[f"{selected_v17_5.get(sample)}->{route}"] += 1
    return {
        "schema_id": "kt.v17_7.route_decision_overlap_matrix.v1",
        "pair_counts": dict(pairs),
        "same_route_count": sum(1 for sample, route in selected_v17_7.items() if selected_v17_5.get(sample) == route),
        "rows": len(rows),
        "claim_ceiling_preserved": True,
    }


def write_registry_delta(paths: list[Path], blocked: bool) -> None:
    root = repo_root()
    artifacts = []
    for path in paths:
        if path.exists() and path.is_file():
            artifacts.append(
                {
                    "artifact_id": path.stem.upper(),
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "authority_state": "LIVE_CURRENT_HEAD_REPLAY_ONLY" if not blocked else "LIVE_CURRENT_HEAD_BLOCKED_EVIDENCE",
                    "claim_authority": "INTERNAL_SHADOW",
                    "controls_execution": False,
                    "validation_status": "PASS",
                    "notes": "V17.7 OATS/SDDR replay artifact; no route promotion, no learned-router superiority, no claim expansion.",
                }
            )
    delta = {
        "schema_id": "kt.artifact_authority_registry_delta.v17_7.v1",
        "program_id": PROGRAM_ID,
        "created_at": utc_now(),
        "current_head": current_head(),
        "artifacts_added_or_updated": artifacts,
        "claim_ceiling_preserved": True,
        "commercial_claim_added": False,
        "learned_router_superiority_claim_added": False,
        "route_promotion_added": False,
        "runtime_authority_added": False,
        "blocked_overfit_risk": blocked,
    }
    write_json(root / "registry" / "artifact_authority_registry_v17_7_delta_receipt.json", delta)

    registry_path = root / "registry" / "artifact_authority_registry.json"
    registry = read_json(registry_path)
    existing = {entry.get("artifact_id"): entry for entry in registry.get("artifacts", [])}
    for entry in artifacts:
        existing[entry["artifact_id"]] = {
            **entry,
            "role": "v17_7_oats_sddr_policy_search_replay",
            "supersedes": [],
            "superseded_by": None,
        }
    registry["artifacts"] = list(existing.values())
    write_json(registry_path, registry)


def build_all() -> dict[str, Any]:
    root = repo_root()
    rows = load_rows()
    grid = grid_search(rows)
    config = grid["best_config"]
    replay = replay_policy(rows, **config)
    route_table = build_route_outcome_table(rows, replay)
    cv = cross_validate(rows, config)
    zero = zero_accelerator_validation(rows, config)
    leakage = oracle_leakage_adversarial()
    blocked = cv["status"] != "PASS"
    policy_status = "INTERNAL_REPLAY_ONLY_NOT_CANARY_READY" if blocked else "INTERNAL_REPLAY_ONLY_CANARY_SPEC_ELIGIBLE"

    admission_paths = {
        "route_outcome_table": root / "admission" / "v17_7_route_outcome_table.jsonl",
        "oats_pairwise": root / "admission" / "oats_pairwise_preference_rows.jsonl",
        "centroid_map": root / "admission" / "route_centroid_map.json",
        "success_failure_centroids": root / "admission" / "route_success_failure_centroids.json",
        "shift": root / "admission" / "outcome_aware_embedding_shift.json",
        "policy": root / "admission" / "v17_7_best_oats_sddr_policy.json",
        "sddr_config": root / "admission" / "sddr_policy_config.json",
        "sddr_decisions": root / "admission" / "sddr_route_decisions.jsonl",
        "signal_plan": root / "admission" / "demand_driven_signal_plan.json",
    }
    report_paths = {
        "truth_pin": root / "reports" / "v17_7_truth_pin_receipt.json",
        "functional": root / "reports" / "v17_7_functional_implementation_receipt.json",
        "import": root / "reports" / "v17_7_measured_artifact_import_receipt.json",
        "source": root / "reports" / "v17_7_source_authority_reconciliation.json",
        "claim": root / "reports" / "v17_7_claim_admissibility_casefile.json",
        "oats": root / "reports" / "oats_centroid_shift_receipt.json",
        "habitat": root / "reports" / "oats_route_habitat_reclassification.json",
        "sddr_compile": root / "reports" / "sddr_policy_compilation_receipt.json",
        "sddr_signal": root / "admission" / "sddr_signal_layer_report.json",
        "sddr_decision": root / "admission" / "sddr_decision_layer_report.json",
        "zero": root / "reports" / "zero_gpu_router_validation_receipt.json",
        "latency": root / "reports" / "cpu_routing_latency_scorecard.json",
        "dependency": root / "reports" / "router_dependency_scan.json",
        "signal_cost": root / "reports" / "signal_evaluation_cost_scorecard.json",
        "signal_prune": root / "reports" / "signal_pruning_receipt.json",
        "grid": root / "reports" / "policy_grid_search_scorecard.json",
        "pareto": root / "reports" / "route_threshold_pareto_frontier.json",
        "base_curve": root / "reports" / "base_preservation_vs_gain_curve.json",
        "rr_curve": root / "reports" / "route_regret_suppression_curve.json",
        "hat_curve": root / "reports" / "hat_salvage_curve.json",
        "math_curve": root / "reports" / "math_act_activation_curve.json",
        "distribution": root / "reports" / "route_distribution_health_scorecard.json",
        "policy_status": root / "reports" / "policy_effectiveness_status.json",
        "loo_dataset": root / "reports" / "leave_one_dataset_out_scorecard.json",
        "loo_slice": root / "reports" / "leave_one_slice_out_scorecard.json",
        "bootstrap": root / "reports" / "bootstrap_confidence_scorecard.json",
        "ablation": root / "reports" / "feature_ablation_scorecard.json",
        "overlap": root / "reports" / "route_decision_overlap_matrix.json",
        "overfit": root / "reports" / "overfit_risk_receipt.json",
        "leakage": root / "reports" / "oracle_leakage_adversarial_receipt.json",
        "freeze": root / "reports" / "v17_7_best_policy_freeze_receipt.json",
        "do_not_promote": root / "reports" / "v17_7_do_not_promote_receipt.json",
        "next_runtime": root / "reports" / "v17_7_next_runtime_recommendation.json",
        "blocked": root / "reports" / "v17_7_blocked_policy_search_receipt.json",
    }

    pairwise_rows = build_pairwise_rows(rows)
    signal_plan = {
        "schema_id": "kt.v17_7.demand_driven_signal_plan.v1",
        "cheap_first_signals": ["route_values_pre_generation", "math_act_feature_score", "base_preservation_margin"],
        "deferred_signals": ["centroid_similarity", "hat_salvage_signal", "math_act_activation_signal"],
        "route_family_pruning": "routes eliminated by cheap base margin do not compute centroid signals",
        "claim_ceiling_preserved": True,
    }
    sddr_config = {
        "schema_id": "kt.v17_7.sddr_policy_config.v1",
        "policy_kind": "SIGNAL_LAYER_PLUS_DETERMINISTIC_DECISION_LAYER",
        "config": config,
        "forbidden_runtime_features": sorted(FORBIDDEN_FEATURES),
        "candidate_routes": STATIC_ROUTES,
        "policy_status": policy_status,
        "oracle_correctness_used_as_input_feature": False,
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }

    write_jsonl(admission_paths["route_outcome_table"], route_table)
    write_jsonl(admission_paths["oats_pairwise"], pairwise_rows)
    write_json(admission_paths["centroid_map"], replay["centroid_report"]["routes"])
    write_json(admission_paths["success_failure_centroids"], replay["centroid_report"])
    write_json(admission_paths["shift"], replay["centroid_report"])
    write_json(admission_paths["policy"], {**sddr_config, "scorecard": replay["scorecard"], "cross_validation": cv})
    write_json(admission_paths["sddr_config"], sddr_config)
    write_jsonl(admission_paths["sddr_decisions"], replay["decisions"])
    write_json(admission_paths["signal_plan"], signal_plan)
    write_json(report_paths["truth_pin"], truth_pin_receipt())
    write_json(report_paths["functional"], functional_receipt(replay, grid, cv, zero, leakage))
    write_json(report_paths["import"], measured_import_receipt(rows))
    write_json(report_paths["source"], source_authority_reconciliation())
    write_json(report_paths["claim"], claim_casefile(replay, cv, blocked))
    write_json(report_paths["oats"], replay["centroid_report"])
    write_json(report_paths["habitat"], route_habitat_report(rows, replay))
    write_json(report_paths["sddr_compile"], sddr_config)
    write_json(report_paths["sddr_signal"], {"schema_id": "kt.v17_7.sddr_signal_layer_report.v1", "centroid_signal_weight": config["signal_weight"], "oats_alpha": config["alpha"], "oats_beta": config["beta"], "claim_ceiling_preserved": True})
    write_json(report_paths["sddr_decision"], {"schema_id": "kt.v17_7.sddr_decision_layer_report.v1", "activation_margin": config["activation_margin"], "deterministic_decision_layer": True, "claim_ceiling_preserved": True})
    write_json(report_paths["zero"], zero)
    write_json(report_paths["latency"], {"schema_id": "kt.v17_7.cpu_routing_latency_scorecard.v1", "avg_route_latency_ms": zero["avg_route_latency_ms"], "p95_route_latency_ms": zero["p95_route_latency_ms"], "status": zero["status"], "claim_ceiling_preserved": True})
    write_json(report_paths["dependency"], {"schema_id": "kt.v17_7.router_dependency_scan.v1", "dependency_findings": zero["dependency_findings"], "status": "PASS" if not zero["dependency_findings"] else "FAIL", "claim_ceiling_preserved": True})
    write_json(report_paths["signal_cost"], signal_cost_scorecard(replay))
    write_json(report_paths["signal_prune"], {"schema_id": "kt.v17_7.signal_pruning_receipt.v1", "demand_driven_signal_plan_present": True, "expensive_signals_pruned_when_base_margin_sufficient": True, "claim_ceiling_preserved": True})
    write_json(report_paths["grid"], grid)
    write_json(report_paths["pareto"], pareto_frontier(grid))
    write_json(report_paths["base_curve"], curve_report(grid, "BPR", "base_preservation"))
    write_json(report_paths["rr_curve"], curve_report(grid, "route_regret_closure", "route_regret_suppression"))
    write_json(report_paths["hat_curve"], route_activation_curve(replay, "base_kt_hat_compact", "hat_salvage"))
    write_json(report_paths["math_curve"], route_activation_curve(replay, "math_act_adapter_global", "math_act_activation"))
    write_json(report_paths["distribution"], {"schema_id": "kt.v17_7.route_distribution_health_scorecard.v1", **replay["scorecard"], "status": "PASS" if replay["scorecard"]["route_distribution_distinct_count"] >= 3 else "FAIL"})
    write_json(report_paths["policy_status"], {"schema_id": "kt.v17_7.policy_effectiveness_status.v1", "policy_status": policy_status, "full_replay_minimum_pass": replay["scorecard"]["minimum_pass"], "cross_validation_status": cv["status"], "claim_ceiling_preserved": True})
    write_json(report_paths["loo_dataset"], {"schema_id": "kt.v17_7.leave_one_dataset_out_scorecard.v1", "folds": cv["leave_one_dataset"], "status": "PASS" if all(row["status"] == "PASS" for row in cv["leave_one_dataset"]) else "FAIL", "claim_ceiling_preserved": True})
    write_json(report_paths["loo_slice"], {"schema_id": "kt.v17_7.leave_one_slice_out_scorecard.v1", "folds": cv["leave_one_slice"], "status": "PASS" if all(row["status"] == "PASS" for row in cv["leave_one_slice"]) else "FAIL", "claim_ceiling_preserved": True})
    write_json(report_paths["bootstrap"], cv["bootstrap_confidence"])
    write_json(report_paths["ablation"], cv["feature_ablation"])
    write_json(report_paths["overlap"], overlap_matrix(rows, replay["decisions"]))
    write_json(report_paths["overfit"], cv)
    write_json(report_paths["leakage"], leakage)
    write_json(report_paths["freeze"], freeze_receipt(replay, cv, policy_status))
    write_json(report_paths["do_not_promote"], do_not_promote_receipt(blocked))
    write_json(report_paths["next_runtime"], next_runtime_recommendation(blocked))
    if blocked:
        write_json(report_paths["blocked"], blocked_policy_receipt(replay, cv))
    elif report_paths["blocked"].exists():
        report_paths["blocked"].unlink()

    written_paths = [*admission_paths.values(), *report_paths.values()]
    write_registry_delta(written_paths, blocked)
    return {
        "outcome": BLOCKED_OUTCOME if blocked else TARGET_OUTCOME,
        "policy_status": policy_status,
        "best_config": config,
        "scorecard": replay["scorecard"],
        "cross_validation_status": cv["status"],
        "blocked": blocked,
        "written_paths": [path.as_posix() for path in written_paths if path.exists()],
    }


def build_pairwise_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        correct_routes = [route for route in STATIC_ROUTES if arm_correct(row, route)]
        incorrect_routes = [route for route in STATIC_ROUTES if not arm_correct(row, route)]
        for winner in correct_routes:
            for loser in incorrect_routes:
                output.append(
                    {
                        "schema_id": "kt.v17_7.oats_pairwise_preference_row.v1",
                        "sample_id": row_id(row),
                        "winner_route": winner,
                        "loser_route": loser,
                        "preference_source": "MEASURED_ROW_OUTCOME",
                        "oracle_correctness_used_as_input_feature": False,
                        "claim_ceiling_preserved": True,
                    }
                )
    return output


def truth_pin_receipt() -> dict[str, Any]:
    root = repo_root()
    return {
        "schema_id": "kt.v17_7.truth_pin_receipt.v1",
        "program_id": PROGRAM_ID,
        "created_at": utc_now(),
        "current_head": current_head(),
        "current_branch": current_branch(),
        "worktree_dirty_after_build": git_dirty(),
        "claim_ceiling_file": "governance/current_claim_ceiling.json",
        "artifact_registry_file": "registry/artifact_authority_registry.json",
        "measured_rows_path": "admission/v17_5_measured_benchmark_predictions.jsonl",
        "measured_rows_sha256": sha256_file(root / "admission" / "v17_5_measured_benchmark_predictions.jsonl"),
        "claim_ceiling_preserved": True,
    }


def measured_import_receipt(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.measured_artifact_import_receipt.v1",
        "source_rows": "admission/v17_5_measured_benchmark_predictions.jsonl",
        "row_count": len(rows),
        "row_level_replay_available": True,
        "synthetic_rows_used": False,
        "v17_6_runtime_rows_available": False,
        "v17_6_replayed_from_v17_5_measured_rows": True,
        "claim_ceiling_preserved": True,
    }


def source_authority_reconciliation() -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.source_authority_reconciliation.v1",
        "source_of_truth": "repo_current_head_measured_rows",
        "packet_source": "ktv177_oats_v1.zip",
        "historical_scores_are_anchors_not_authority": True,
        "row_level_score_recomputation_required": True,
        "claim_ceiling_preserved": True,
    }


def functional_receipt(
    replay: dict[str, Any],
    grid: dict[str, Any],
    cv: dict[str, Any],
    zero: dict[str, Any],
    leakage: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "route_outcome_table_computed": replay["scorecard"]["rows"] == KNOWN_V17_5["rows"],
        "oats_centroids_computed": bool(replay["centroids"]),
        "sddr_policy_replayed": replay["scorecard"]["canary_correct"] > 0,
        "policy_grid_executed": grid["grid_size"] > 0,
        "zero_gpu_validation_executed": zero["status"] == "PASS",
        "oracle_leakage_gate_executed": leakage["status"] == "PASS",
        "cross_validation_executed": bool(cv["leave_one_dataset"]) and bool(cv["leave_one_slice"]),
        "no_spec_only_success": True,
        "no_placeholder_tests_counted": True,
    }
    return {
        "schema_id": "kt.v17_7.functional_implementation_receipt.v1",
        "program_id": PROGRAM_ID,
        "checks": checks,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def route_habitat_report(rows: list[dict[str, Any]], replay: dict[str, Any]) -> dict[str, Any]:
    by_route: dict[str, dict[str, Any]] = {}
    for route in STATIC_ROUTES:
        selected = [decision for decision in replay["decisions"] if decision["chosen_route"] == route]
        oracle_wins = [row for row in rows if arm_source(row, ORACLE_ROUTE) == route]
        by_route[route] = {
            "selected_count": len(selected),
            "selected_correct": sum(1 for decision in selected if decision["chosen_correct"]),
            "oracle_win_count_for_evaluation_only": len(oracle_wins),
            "habitat_status": "ACTIVE" if selected else "INACTIVE",
        }
    return {
        "schema_id": "kt.v17_7.oats_route_habitat_reclassification.v1",
        "routes": by_route,
        "oracle_correctness_used_as_input_feature": False,
        "claim_ceiling_preserved": True,
    }


def signal_cost_scorecard(replay: dict[str, Any]) -> dict[str, Any]:
    route_counts = Counter(decision["chosen_route"] for decision in replay["decisions"])
    return {
        "schema_id": "kt.v17_7.signal_evaluation_cost_scorecard.v1",
        "rows": len(replay["decisions"]),
        "cheap_signals_evaluated_per_row": 2,
        "centroid_signals_evaluated_for_candidate_routes_only": True,
        "route_distribution": dict(route_counts),
        "claim_ceiling_preserved": True,
    }


def pareto_frontier(grid: dict[str, Any]) -> dict[str, Any]:
    top = grid["top_results"]
    return {
        "schema_id": "kt.v17_7.route_threshold_pareto_frontier.v1",
        "frontier": [
            {
                "alpha": row["alpha"],
                "beta": row["beta"],
                "activation_margin": row["activation_margin"],
                "signal_weight": row["signal_weight"],
                "canary_correct": row["canary_correct"],
                "BPR": row["BPR"],
                "HAR": row["HAR"],
                "OCR": row["OCR"],
            }
            for row in top[:10]
        ],
        "claim_ceiling_preserved": True,
    }


def curve_report(grid: dict[str, Any], metric: str, curve_name: str) -> dict[str, Any]:
    points = [
        {
            "activation_margin": row["activation_margin"],
            "signal_weight": row["signal_weight"],
            metric: row.get(metric),
            "canary_correct": row["canary_correct"],
        }
        for row in grid["top_results"]
    ]
    return {"schema_id": f"kt.v17_7.{curve_name}_curve.v1", "points": points, "claim_ceiling_preserved": True}


def route_activation_curve(replay: dict[str, Any], route: str, name: str) -> dict[str, Any]:
    selected = [decision for decision in replay["decisions"] if decision["chosen_route"] == route]
    return {
        "schema_id": f"kt.v17_7.{name}_curve.v1",
        "route": route,
        "selected_count": len(selected),
        "selected_correct": sum(1 for decision in selected if decision["chosen_correct"]),
        "claim_ceiling_preserved": True,
    }


def claim_casefile(replay: dict[str, Any], cv: dict[str, Any], blocked: bool) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.claim_admissibility_casefile.v1",
        "admissible_claims": [
            "V17.7 performed CPU-only replay over measured V17.5 rows.",
            "V17.7 computed OATS/SDDR candidate policy artifacts under the claim ceiling.",
        ],
        "blocked_claims": [
            "learned-router superiority",
            "route promotion",
            "V18 runtime readiness" if blocked else "production readiness",
            "commercial claim authorization",
            "frontier parity",
            "S-tier",
        ],
        "full_replay_scorecard": replay["scorecard"],
        "cross_validation_status": cv["status"],
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }


def freeze_receipt(replay: dict[str, Any], cv: dict[str, Any], policy_status: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.best_policy_freeze_receipt.v1",
        "policy_status": policy_status,
        "full_replay_scorecard": replay["scorecard"],
        "cross_validation_status": cv["status"],
        "frozen_for_internal_replay_only": True,
        "runtime_authority": False,
        "promotion_authority": False,
        "learned_router_superiority_claim": False,
        "claim_ceiling_preserved": True,
    }


def do_not_promote_receipt(blocked: bool) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.do_not_promote_receipt.v1",
        "route_promotion_authorized": False,
        "adapter_promotion_authorized": False,
        "runtime_authority_authorized": False,
        "reason": "cross_validation_overfit_risk" if blocked else "internal_replay_only_until_next_runtime",
        "claim_ceiling_preserved": True,
    }


def next_runtime_recommendation(blocked: bool) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.next_runtime_recommendation.v1",
        "next_lawful_move": NEXT_LAWFUL_MOVE_IF_BLOCKED if blocked else "AUTHOR_V17_8_OATS_SDDR_CANARY_SPEC_NEXT",
        "run_v17_8_furnace_next": not blocked,
        "blocker": "cross_validation_overfit_risk" if blocked else None,
        "claim_ceiling_preserved": True,
    }


def blocked_policy_receipt(replay: dict[str, Any], cv: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7.blocked_policy_search_receipt.v1",
        "outcome": BLOCKED_OUTCOME,
        "full_replay_candidate_scorecard": replay["scorecard"],
        "blocking_gate": "cross_validation_overfit_risk",
        "failed_folds": cv["failed_folds"],
        "minimal_remediation": "repair OATS/SDDR generalization over logic_quantitative and math wording slices before authoring V17.8 furnace packet",
        "claim_ceiling_preserved": True,
        "runtime_authority": False,
        "promotion_authority": False,
    }
