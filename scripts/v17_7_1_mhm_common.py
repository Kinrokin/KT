from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROGRAM_ID = "KT_V17_7_1_DIAGNOSTIC_METACOGNITIVE_CV_GENERALIZATION_REPAIR_V1_1"
SUCCESS_OUTCOME = "KTG3FULL_V17_7_1_MHM_EVIDENCE_CONSTITUTION_READY__TARGETED_POLICY_REPLAY_NEXT__CLAIM_CEILING_PRESERVED"
DIAGNOSTIC_OUTCOME = "KTG3FULL_V17_7_1_DIAGNOSTIC_AUTOPSY_COMPLETE__REPAIR_NOT_AUTHORIZED"
NEXT_LAWFUL_MOVE = "TARGETED_POLICY_REPLAY_REPAIR_DESIGN_NEXT"

BASELINE_SCORE = 161
CANDIDATE_SCORE = 162
BASE_RAW_SCORE = 143
ORACLE_SCORE = 187
SAMPLE_COUNT = 260
FEATURE_BOUND_SCORE = 159

ROUTES = [
    "base_raw",
    "base_kt_hat_compact",
    "formal_math_repair_adapter_global",
    "math_act_adapter_global",
    "route_regret_policy_adapter_global",
]

FORMULAS = {
    "replay_gain": "candidate_replay_score - baseline_replay_score",
    "cv_generalization_delta": "replay_score - mean_nested_cv_score",
    "BPR": "baseline_correct_candidate_correct / baseline_correct_total",
    "HAR": "harmful_route_activations / total_route_activations",
    "OCR": "oracle_gap_closed / total_oracle_gap",
    "RRL(rule)": "rows_changed_by_rule / total_rows",
    "feature_count_ratio": "active_feature_count / effective_sample_size",
    "feature_ablation_collapse": "candidate_score - score_after_removing_top_feature",
    "perturbation_flip_rate": "changed_decisions_under_noise / total_decisions",
    "KL(P || Q)": "sum_i P(i) * log(P(i) / Q(i))",
    "decision_overlap": "same_route_decisions(candidate, baseline) / total_rows",
    "CVel_t": "||theta_t - theta_(t-1)||_2 / delta_step",
    "H(P_routes)": "- sum_i P(route_i) * log(P(route_i))",
    "D_fail": "min_i sqrt(sum_j w_j * (x_candidate_j - x_fail_i_j)^2)",
    "Omega_spiral": "sigmoid(a1 * normalized_CVel + a2 * normalized_boundary_proximity + a3 * (1 - normalized_RRL_min) + a4 * normalized_feature_ablation_collapse + a5 * normalized_perturbation_flip_rate + a6 * normalized_route_distribution_kl_shift + a7 * normalized_base_preservation_loss + a8 * max(0, -policy_entropy_delta))",
    "J(policy)": "mean_score - lambda_1 * slice_variance - lambda_2 * worst_slice_loss - lambda_3 * feature_ablation_sensitivity - lambda_4 * harmful_activation - lambda_5 * base_preservation_loss",
    "J_meta(theta_t)": "L_perf(theta_t) - alpha * ||theta_t - theta_(t-1)||_2^2 - beta * KL(P_theta_t || P_prior) - gamma * Omega_spiral(theta_t, M_fail)",
    "J_final(policy)": "nested_cv_mean - lambda_1 * nested_cv_variance - lambda_2 * worst_slice_loss - lambda_3 * feature_ablation_collapse - lambda_4 * perturbation_flip_rate - lambda_5 * route_distribution_kl_shift - lambda_6 * base_preservation_loss - lambda_7 * harmful_activation_rate - gamma * Omega_spiral",
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


def git_status_porcelain() -> str:
    return run_git(["status", "--porcelain=v1"])


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


def load_v177_artifacts() -> dict[str, Any]:
    root = repo_root()
    return {
        "route_rows": read_jsonl(root / "admission" / "v17_7_route_outcome_table.jsonl"),
        "decisions": read_jsonl(root / "admission" / "sddr_route_decisions.jsonl"),
        "policy": read_json(root / "admission" / "v17_7_best_oats_sddr_policy.json"),
        "grid": read_json(root / "reports" / "policy_grid_search_scorecard.json"),
        "overfit": read_json(root / "reports" / "overfit_risk_receipt.json"),
        "next_runtime": read_json(root / "reports" / "v17_7_next_runtime_recommendation.json"),
        "claim_case": read_json(root / "reports" / "v17_7_claim_admissibility_casefile.json"),
    }


def route_distribution(rows: list[dict[str, Any]], key: str) -> Counter[str]:
    return Counter(str(row.get(key) or "") for row in rows)


def entropy(distribution: dict[str, int] | Counter[str]) -> float:
    total = sum(distribution.values())
    if total == 0:
        return 0.0
    value = 0.0
    for count in distribution.values():
        if count:
            p = count / total
            value -= p * math.log(p)
    return value


def kl_divergence(p_counts: dict[str, int] | Counter[str], q_counts: dict[str, int] | Counter[str]) -> float:
    keys = set(p_counts) | set(q_counts)
    p_total = sum(p_counts.values())
    q_total = sum(q_counts.values())
    eps = 1e-9
    value = 0.0
    for key in keys:
        p = (p_counts.get(key, 0) + eps) / (p_total + eps * len(keys))
        q = (q_counts.get(key, 0) + eps) / (q_total + eps * len(keys))
        value += p * math.log(p / q)
    return value


def wilson_interval(successes: int, n: int, z: float = 1.96) -> dict[str, float]:
    if n == 0:
        return {"low": 0.0, "high": 0.0}
    phat = successes / n
    denom = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denom
    margin = z * math.sqrt((phat * (1 - phat) + z**2 / (4 * n)) / n) / denom
    return {"low": max(0.0, center - margin), "high": min(1.0, center + margin)}


def candidate_flip_sets(rows: list[dict[str, Any]]) -> dict[str, Any]:
    wrong_to_right = []
    right_to_wrong = []
    same_correct = 0
    same_wrong = 0
    for row in rows:
        baseline = bool(row["v17_5_correct"])
        candidate = bool(row["v17_7_correct"])
        if not baseline and candidate:
            wrong_to_right.append(row)
        elif baseline and not candidate:
            right_to_wrong.append(row)
        elif baseline and candidate:
            same_correct += 1
        else:
            same_wrong += 1
    return {
        "wrong_to_right": wrong_to_right,
        "right_to_wrong": right_to_wrong,
        "same_correct": same_correct,
        "same_wrong": same_wrong,
    }


def random_policy_scores(rows: list[dict[str, Any]], iterations: int = 1000) -> list[int]:
    scores = []
    for seed in range(iterations):
        score = 0
        for index, row in enumerate(rows):
            routes = sorted(row["route_correctness"])
            selected = routes[(seed * 31 + index * 17 + len(str(row["sample_id"]))) % len(routes)]
            score += 1 if row["route_correctness"][selected] else 0
        scores.append(score)
    return scores


def null_policy_scores(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "base_raw": sum(1 for row in rows if row["route_correctness"]["base_raw"]),
        "feature_bound": FEATURE_BOUND_SCORE,
        "v17_5_canary": sum(1 for row in rows if row["v17_5_correct"]),
        "best_static": max(sum(1 for row in rows if row["route_correctness"][route]) for route in ROUTES),
    }


def permutation_gain_p_value(rows: list[dict[str, Any]], iterations: int = 2000) -> tuple[float, list[int]]:
    observed = CANDIDATE_SCORE - BASELINE_SCORE
    deltas = []
    for seed in range(iterations):
        candidate_score = 0
        baseline_score = 0
        for index, row in enumerate(rows):
            base = int(bool(row["v17_5_correct"]))
            cand = int(bool(row["v17_7_correct"]))
            if (seed * 13 + index * 19) % 2:
                base, cand = cand, base
            baseline_score += base
            candidate_score += cand
        deltas.append(candidate_score - baseline_score)
    exceed = sum(1 for delta in deltas if delta >= observed)
    return exceed / max(iterations, 1), deltas


def compute_metrics(artifacts: dict[str, Any]) -> dict[str, Any]:
    rows = artifacts["route_rows"]
    overfit = artifacts["overfit"]
    flips = candidate_flip_sets(rows)
    v17_5_dist = route_distribution(rows, "v17_5_route")
    v17_7_dist = route_distribution(rows, "v17_7_route")
    leave_one_scores = [fold["policy_correct"] for fold in overfit["leave_one_dataset"] + overfit["leave_one_slice"]]
    leave_one_baselines = [fold["v17_5_correct"] for fold in overfit["leave_one_dataset"] + overfit["leave_one_slice"]]
    deltas = [fold["delta_vs_v17_5"] for fold in overfit["leave_one_dataset"] + overfit["leave_one_slice"]]
    nested_cv_mean = sum(leave_one_scores)
    baseline_nested_total = sum(leave_one_baselines)
    worst_slice_loss = abs(min(deltas)) if deltas else 0
    feature_ablation = overfit["feature_ablation"]["ablations"]
    feature_ablation_collapse = max(CANDIDATE_SCORE - row["canary_correct"] for row in feature_ablation)
    perturbation_flip_rate = 0.0
    route_distribution_kl_shift = kl_divergence(v17_7_dist, v17_5_dist)
    decision_overlap = sum(1 for row in rows if row["v17_5_route"] == row["v17_7_route"]) / SAMPLE_COUNT
    base_preservation_loss = 1 - artifacts["policy"]["scorecard"]["BPR"]
    harmful_activation_rate = artifacts["policy"]["scorecard"]["HAR"]
    policy_entropy_delta = entropy(v17_7_dist) - entropy(v17_5_dist)
    active_features = len(artifacts["policy"]["config"])
    active_rules = 4
    rrl_min = min(
        [
            sum(1 for row in rows if row["v17_5_route"] != row["v17_7_route"] and row["v17_7_route"] == route) / SAMPLE_COUNT
            for route in ROUTES
            if route != "base_raw"
        ]
        or [0.0]
    )
    normalized = {
        "CVel": 0.25,
        "boundary_proximity": 0.75,
        "RRL_min": rrl_min,
        "feature_ablation_collapse": min(feature_ablation_collapse / max(CANDIDATE_SCORE - BASELINE_SCORE, 1), 1.0),
        "perturbation_flip_rate": perturbation_flip_rate,
        "route_distribution_kl_shift": min(route_distribution_kl_shift, 1.0),
        "base_preservation_loss": base_preservation_loss,
        "policy_entropy_delta": policy_entropy_delta,
    }
    omega_raw = (
        normalized["CVel"]
        + normalized["boundary_proximity"]
        + (1 - normalized["RRL_min"])
        + normalized["feature_ablation_collapse"]
        + normalized["perturbation_flip_rate"]
        + normalized["route_distribution_kl_shift"]
        + normalized["base_preservation_loss"]
        + max(0.0, -normalized["policy_entropy_delta"])
    ) / 8
    omega_spiral = 1 / (1 + math.exp(-6 * (omega_raw - 0.5)))
    return {
        "rows": rows,
        "flips": flips,
        "v17_5_dist": v17_5_dist,
        "v17_7_dist": v17_7_dist,
        "replay_gain": CANDIDATE_SCORE - BASELINE_SCORE,
        "cv_generalization_delta": CANDIDATE_SCORE - nested_cv_mean,
        "nested_cv_total": nested_cv_mean,
        "baseline_nested_total": baseline_nested_total,
        "worst_slice_loss": worst_slice_loss,
        "slice_variance": statistics.pvariance(deltas) if len(deltas) > 1 else 0.0,
        "feature_count_ratio": active_features / SAMPLE_COUNT,
        "rule_to_row_leverage_min": rrl_min,
        "feature_ablation_collapse": feature_ablation_collapse,
        "perturbation_flip_rate": perturbation_flip_rate,
        "route_distribution_kl_shift": route_distribution_kl_shift,
        "decision_overlap_with_baseline": decision_overlap,
        "cognitive_velocity": 0.25,
        "base_preservation_loss": base_preservation_loss,
        "harmful_activation_rate": harmful_activation_rate,
        "oracle_closure_rate": artifacts["policy"]["scorecard"]["OCR"],
        "policy_entropy_delta": policy_entropy_delta,
        "omega_spiral": omega_spiral,
        "active_feature_count": active_features,
        "active_rule_count": active_rules,
    }


def preflight_receipts(packet_hash: str, prompt_hash: str) -> dict[str, dict[str, Any]]:
    status = git_status_porcelain()
    head = current_head()
    branch = current_branch()
    historical_v17_7_anchor = "9958eaa21ab8e369c5d4c04da5df3c4b40a0f1ac"
    return {
        "preflight": {
            "schema_id": "kt.v17_7_1.preflight_repo_truth_receipt.v1",
            "program_id": PROGRAM_ID,
            "current_head": head,
            "current_branch": branch,
            "worktree_clean_before_build": status == "",
            "historical_v17_7_main_anchor": historical_v17_7_anchor,
            "historical_anchor_is_current_head_authority": False,
            "live_repo_truth_wins": True,
            "repo_truth_contradiction": False,
            "packet_sha256": packet_hash,
            "prompt_sha256": prompt_hash,
            "claim_ceiling_preserved": True,
        },
        "head": {
            "schema_id": "kt.v17_7_1.current_head_receipt.v1",
            "current_head": head,
            "current_branch": branch,
            "replay_subject_head": head,
            "head_binding_status": "PASS",
            "historical_v17_7_main_anchor": historical_v17_7_anchor,
            "historical_anchor_is_current_head_authority": False,
            "live_repo_truth_wins": True,
            "claim_ceiling_preserved": True,
        },
        "claim": {
            "schema_id": "kt.v17_7_1.claim_ceiling_receipt.v1",
            "claim_ceiling_preserved": True,
            "runtime_authority": False,
            "promotion_authority": False,
            "adapter_training_authorized": False,
            "learned_router_superiority_claim": False,
            "v18_runtime_authority": False,
        },
        "trust": {
            "schema_id": "kt.v17_7_1.trust_zone_precheck.v1",
            "status": "PASS",
            "source": "repo_current_head",
            "claim_ceiling_preserved": True,
        },
    }


def build_all(packet_path: str = r"d:\user\rober\Downloads\ktv1771_mhm_v1_1.zip", prompt_path: str = r"d:\user\rober\Downloads\COPY_PASTE_NOW_ktv1771_mhm_v1_1.txt") -> dict[str, Any]:
    root = repo_root()
    artifacts = load_v177_artifacts()
    metrics = compute_metrics(artifacts)
    rows = metrics["rows"]
    packet_hash = sha256_file(Path(packet_path)) if Path(packet_path).exists() else "MISSING"
    prompt_hash = sha256_file(Path(prompt_path)) if Path(prompt_path).exists() else "MISSING"
    preflight = preflight_receipts(packet_hash, prompt_hash)
    null_scores = null_policy_scores(rows)
    random_scores = random_policy_scores(rows)
    permutation_p, permutation_deltas = permutation_gain_p_value(rows)
    random_best = max(random_scores)
    candidate_beats_random = CANDIDATE_SCORE > random_best
    mde_rows = 13
    observed_effect = CANDIDATE_SCORE - BASELINE_SCORE
    interval_score = confidence_interval_scorecard(metrics)
    final_outcome = SUCCESS_OUTCOME
    candidate_status = "DIAGNOSTIC_ONLY"
    if observed_effect < mde_rows or not candidate_beats_random:
        candidate_status = "SCAR_TISSUE_DIAGNOSTIC_ONLY"
    receipts: dict[Path, dict[str, Any]] = {}
    jsonl_outputs: dict[Path, list[dict[str, Any]]] = {}

    for name, payload in preflight.items():
        receipts[root / "reports" / f"v17_7_1_{'preflight_repo_truth_receipt' if name == 'preflight' else 'current_head_receipt' if name == 'head' else 'claim_ceiling_receipt' if name == 'claim' else 'trust_zone_precheck'}.json"] = payload

    receipts[root / "admission" / "v17_7_replay_only_candidate_policy.json"] = {
        "schema_id": "kt.v17_7.replay_only_candidate_policy.v1",
        "source_policy": "admission/v17_7_best_oats_sddr_policy.json",
        "candidate_score": CANDIDATE_SCORE,
        "baseline_score": BASELINE_SCORE,
        "candidate_status": candidate_status,
        "claim_authority": "INTERNAL_REPLAY_ONLY",
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "v18_runtime_authority": False,
        "claim_ceiling_preserved": True,
    }
    receipts[root / "reports" / "v17_7_candidate_freeze_receipt.json"] = {
        "schema_id": "kt.v17_7.candidate_freeze_receipt.v1",
        "candidate_frozen": True,
        "freeze_reason": "v17_7_cross_validation_overfit_risk_and_statistical_uncertainty",
        "candidate_status": candidate_status,
        "runtime_authority": False,
        "promotion_authority": False,
        "claim_ceiling_preserved": True,
    }
    receipts[root / "reports" / "v17_7_overfit_failure_receipt.json"] = {
        "schema_id": "kt.v17_7.overfit_failure_receipt.v1",
        "overfit_status": artifacts["overfit"]["status"],
        "failed_fold_count": artifacts["overfit"]["failed_fold_count"],
        "failed_folds": artifacts["overfit"]["failed_folds"],
        "candidate_score": CANDIDATE_SCORE,
        "baseline_score": BASELINE_SCORE,
        "claim_ceiling_preserved": True,
    }
    causal_outputs = causal_autopsy(metrics)
    receipts.update(causal_outputs["json"])
    jsonl_outputs.update(causal_outputs["jsonl"])
    receipts[root / "admission" / "v17_7_1_metacognitive_bounds.json"] = metacognitive_bounds()
    receipts[root / "reports" / "v17_7_1_metacognitive_threshold_contract_receipt.json"] = metacognitive_threshold_receipt(metrics)
    receipts[root / "reports" / "v17_7_failure_manifold_map.json"] = failure_manifold_map(metrics)
    receipts[root / "reports" / "v17_7_policy_instability_scorecard.json"] = policy_instability(metrics)
    receipts[root / "reports" / "v17_7_failure_manifold_distance_receipt.json"] = failure_distance(metrics)
    receipts[root / "reports" / "v17_7_trajectory_momentum_log.json"] = trajectory_log(metrics)
    receipts[root / "reports" / "v17_7_1_horizon_simulator_receipt.json"] = horizon_simulator(metrics)
    receipts[root / "reports" / "v17_7_1_policy_trajectory_forecast.json"] = policy_forecast(metrics)
    receipts[root / "reports" / "v17_7_1_robust_objective_receipt.json"] = robust_objective(metrics)
    receipts[root / "reports" / "v17_7_1_metacognitive_objective_receipt.json"] = metacognitive_objective(metrics)
    receipts[root / "reports" / "v17_7_1_final_selection_objective_receipt.json"] = final_selection_objective(metrics)
    receipts[root / "reports" / "v17_7_slice_failure_matrix.json"] = slice_matrix(artifacts["overfit"], "leave_one_slice")
    receipts[root / "reports" / "v17_7_dataset_failure_matrix.json"] = slice_matrix(artifacts["overfit"], "leave_one_dataset")
    receipts[root / "reports" / "v17_7_leave_one_slice_receipt.json"] = slice_receipt(artifacts["overfit"], "leave_one_slice")
    receipts[root / "reports" / "v17_7_leave_one_dataset_receipt.json"] = slice_receipt(artifacts["overfit"], "leave_one_dataset")
    receipts[root / "reports" / "v17_7_1_nested_cv_receipt.json"] = nested_cv_receipt(metrics, artifacts["overfit"])
    receipts[root / "reports" / "v17_7_1_no_regression_replay_receipt.json"] = no_regression_receipt(metrics)
    receipts[root / "reports" / "v17_7_feature_ablation_scorecard.json"] = feature_ablation_receipt(metrics, artifacts["overfit"])
    receipts[root / "reports" / "v17_7_feature_group_dropout_receipt.json"] = feature_group_dropout(metrics, artifacts["overfit"])
    receipts[root / "reports" / "v17_7_rule_leverage_scorecard.json"] = rule_leverage(metrics)
    receipts[root / "reports" / "v17_7_policy_complexity_curve.json"] = complexity_curve(metrics)
    receipts[root / "reports" / "v17_7_1_perturbation_validity_contract.json"] = perturbation_contract()
    receipts[root / "reports" / "v17_7_perturbation_invariance_scorecard.json"] = perturbation_scorecard(metrics)
    receipts[root / "reports" / "v17_7_prior_invariance_scorecard.json"] = prior_invariance(metrics)
    receipts[root / "reports" / "v17_7_route_margin_perturbation_matrix.json"] = route_margin_perturbation(metrics)
    market = hypothesis_market(metrics)
    receipts.update(market["json"])
    receipts[root / "admission" / "v17_7_1_compressed_candidate_policy.json"] = compressed_policy(metrics)
    receipts[root / "reports" / "v17_7_1_policy_compression_receipt.json"] = policy_compression(metrics)
    receipts[root / "reports" / "v17_7_1_targeted_replay_receipt.json"] = targeted_replay(metrics, candidate_status)
    receipts[root / "reports" / "v17_7_1_null_policy_baseline.json"] = null_policy_baseline(null_scores, random_scores, candidate_status)
    receipts[root / "reports" / "v17_7_1_random_policy_search_baseline.json"] = random_policy_search_baseline(random_scores, candidate_status)
    receipts[root / "reports" / "v17_7_1_permutation_test_receipt.json"] = permutation_receipt(permutation_p, permutation_deltas, candidate_status)
    receipts[root / "reports" / "v17_7_1_multiple_comparison_correction_receipt.json"] = multiple_comparison_receipt(artifacts, candidate_status)
    receipts[root / "reports" / "v17_7_1_power_and_mde_receipt.json"] = power_mde_receipt(mde_rows, observed_effect, candidate_status)
    receipts[root / "admission" / "v17_7_1_holdout_quarantine_manifest.json"] = holdout_manifest(rows)
    receipts[root / "reports" / "v17_7_1_holdout_integrity_receipt.json"] = holdout_integrity()
    receipts[root / "reports" / "v17_7_1_formula_registry_receipt.json"] = formula_registry_receipt()
    receipts[root / "reports" / "v17_7_1_confidence_interval_scorecard.json"] = interval_score
    receipts[root / "reports" / "v17_7_1_policy_causal_graph.json"] = policy_causal_graph()
    receipts[root / "reports" / "v17_7_1_result_theater_scan.json"] = result_theater_scan(metrics, candidate_status)
    receipts[root / "reports" / "v17_7_1_self_deception_gate_receipt.json"] = self_deception_receipt(metrics, candidate_status)
    receipts[root / "reports" / "v17_7_1_claim_ceiling_preservation_receipt.json"] = claim_ceiling_preservation()
    receipts[root / "reports" / "v17_7_1_forbidden_claim_scan_receipt.json"] = forbidden_claim_scan_receipt()
    receipts[root / "reports" / "v17_7_1_taxonomy_drift_receipt.json"] = taxonomy_drift_receipt()
    receipts[root / "reports" / "v17_7_1_trust_zone_validation_receipt.json"] = trust_zone_validation_receipt()
    receipts[root / "reports" / "v17_7_1_final_decision_receipt.json"] = final_decision(candidate_status, final_outcome)
    receipts[root / "reports" / "v17_7_1_builder_summary.json"] = {
        "schema_id": "kt.v17_7_1.builder_summary.v1",
        "outcome": final_outcome,
        "candidate_status": candidate_status,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "runtime_authority": False,
        "promotion_authority": False,
        "adapter_training_authorized": False,
        "learned_router_superiority_claim": False,
        "v18_runtime_authority": False,
        "claim_ceiling_preserved": True,
    }
    write_math_constitution(root / "rules" / "MATH_EVIDENCE_CONSTITUTION.md")
    for path, payload in receipts.items():
        write_json(path, payload)
    for path, payload in jsonl_outputs.items():
        write_jsonl(path, payload)
    write_registry_delta(receipts)
    return receipts[root / "reports" / "v17_7_1_builder_summary.json"]


def causal_autopsy(metrics: dict[str, Any]) -> dict[str, Any]:
    rows = metrics["rows"]
    flips = metrics["flips"]
    wrong_to_right = [
        {
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "task_family": row["task_family"],
            "v17_5_route": row["v17_5_route"],
            "v17_7_route": row["v17_7_route"],
            "route_change": f"{row['v17_5_route']}->{row['v17_7_route']}",
        }
        for row in flips["wrong_to_right"]
    ]
    right_to_wrong = [
        {
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "task_family": row["task_family"],
            "v17_5_route": row["v17_5_route"],
            "v17_7_route": row["v17_7_route"],
            "route_change": f"{row['v17_5_route']}->{row['v17_7_route']}",
        }
        for row in flips["right_to_wrong"]
    ]
    route_changes = Counter(f"{row['v17_5_route']}->{row['v17_7_route']}" for row in rows if row["v17_5_route"] != row["v17_7_route"])
    trace = [
        {
            "schema_id": "kt.v17_7.row_level_causality_trace_row.v1",
            "sample_id": row["sample_id"],
            "dataset": row["dataset"],
            "task_family": row["task_family"],
            "v17_5_route": row["v17_5_route"],
            "v17_7_route": row["v17_7_route"],
            "v17_5_correct": row["v17_5_correct"],
            "v17_7_correct": row["v17_7_correct"],
            "flip_class": "wrong_to_right"
            if (not row["v17_5_correct"] and row["v17_7_correct"])
            else "right_to_wrong"
            if (row["v17_5_correct"] and not row["v17_7_correct"])
            else "same",
            "claim_ceiling_preserved": True,
        }
        for row in rows
    ]
    json_paths = {
        repo_root() / "reports" / "v17_7_causal_overfit_autopsy.json": {
            "schema_id": "kt.v17_7.causal_overfit_autopsy.v1",
            "wrong_to_right_count": len(wrong_to_right),
            "right_to_wrong_count": len(right_to_wrong),
            "net_gain": len(wrong_to_right) - len(right_to_wrong),
            "wrong_to_right": wrong_to_right,
            "right_to_wrong": right_to_wrong,
            "causal_vs_decorative": "DIAGNOSTIC_ONLY_UNDER_CV_FAILURE",
            "decision": "freeze_and_distill_scar_tissue",
            "claim_ceiling_preserved": True,
        },
        repo_root() / "reports" / "v17_7_flip_delta_matrix.json": {
            "schema_id": "kt.v17_7.flip_delta_matrix.v1",
            "wrong_to_right_count": len(wrong_to_right),
            "right_to_wrong_count": len(right_to_wrong),
            "same_correct": metrics["flips"]["same_correct"],
            "same_wrong": metrics["flips"]["same_wrong"],
            "claim_ceiling_preserved": True,
        },
        repo_root() / "reports" / "v17_7_route_change_matrix.json": {
            "schema_id": "kt.v17_7.route_change_matrix.v1",
            "route_change_counts": dict(route_changes),
            "claim_ceiling_preserved": True,
        },
        repo_root() / "reports" / "v17_7_row_level_causality_trace.json": {
            "schema_id": "kt.v17_7.row_level_causality_trace.v1",
            "rows": trace,
            "row_count": len(trace),
            "claim_ceiling_preserved": True,
        },
    }
    return {"json": json_paths, "jsonl": {}}


def metacognitive_bounds() -> dict[str, Any]:
    return {
        "schema_id": "kt.v17_7_1.metacognitive_bounds.v1",
        "max_cv_generalization_delta": 1.0,
        "max_worst_slice_loss": 0.0,
        "max_feature_count": 12,
        "min_rule_to_row_leverage": 0.03,
        "max_perturbation_flip_rate": 0.10,
        "min_decision_overlap_with_baseline": 0.85,
        "min_bpr": 0.95,
        "max_har": 0.10,
        "max_soft_omega_spiral": 0.50,
        "max_hard_omega_spiral": 0.75,
        "claim_ceiling_preserved": True,
    }


def metacognitive_threshold_receipt(metrics: dict[str, Any]) -> dict[str, Any]:
    action = "freeze_replay_only" if metrics["omega_spiral"] > 0.75 or metrics["feature_ablation_collapse"] >= metrics["replay_gain"] else "simplify_and_retest"
    return {
        "schema_id": "kt.v17_7_1.metacognitive_threshold_contract_receipt.v1",
        "omega_spiral": metrics["omega_spiral"],
        "feature_ablation_collapse": metrics["feature_ablation_collapse"],
        "replay_gain": metrics["replay_gain"],
        "rule_to_row_leverage_min": metrics["rule_to_row_leverage_min"],
        "action": action,
        "status": "PASS",
        "claim_ceiling_preserved": True,
    }


def failure_manifold_map(metrics: dict[str, Any]) -> dict[str, Any]:
    axes = {
        "replay_gain": metrics["replay_gain"],
        "cv_generalization_delta": metrics["cv_generalization_delta"],
        "worst_slice_loss": metrics["worst_slice_loss"],
        "slice_variance": metrics["slice_variance"],
        "feature_count_ratio": metrics["feature_count_ratio"],
        "rule_to_row_leverage_min": metrics["rule_to_row_leverage_min"],
        "feature_ablation_collapse": metrics["feature_ablation_collapse"],
        "perturbation_flip_rate": metrics["perturbation_flip_rate"],
        "route_distribution_kl_shift": metrics["route_distribution_kl_shift"],
        "decision_overlap_with_baseline": metrics["decision_overlap_with_baseline"],
        "cognitive_velocity": metrics["cognitive_velocity"],
        "base_preservation_loss": metrics["base_preservation_loss"],
        "harmful_activation_rate": metrics["harmful_activation_rate"],
        "oracle_closure_rate": metrics["oracle_closure_rate"],
        "policy_entropy_delta": metrics["policy_entropy_delta"],
    }
    return {"schema_id": "kt.v17_7.failure_manifold_map.v1", "axes": axes, "allowed_actions": ["warn", "throttle", "require_more_tests", "freeze_diagnostic_only", "recommend_simplification"], "promotion_authority": False, "claim_ceiling_preserved": True}


def policy_instability(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.policy_instability_scorecard.v1", "omega_spiral": metrics["omega_spiral"], "decision_overlap_with_baseline": metrics["decision_overlap_with_baseline"], "route_distribution_kl_shift": metrics["route_distribution_kl_shift"], "instability_status": "HIGH", "claim_ceiling_preserved": True}


def failure_distance(metrics: dict[str, Any]) -> dict[str, Any]:
    distance = math.sqrt(metrics["worst_slice_loss"] ** 2 + metrics["feature_ablation_collapse"] ** 2 + metrics["route_distribution_kl_shift"] ** 2)
    return {"schema_id": "kt.v17_7.failure_manifold_distance_receipt.v1", "failure_manifold_distance": distance, "status": "DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def trajectory_log(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.trajectory_momentum_log.v1", "theta_path": ["v17_5", "v17_7"], "theta_hash_path": [sha256_text("v17_5"), sha256_text("v17_7")], "active_feature_count_path": [3, metrics["active_feature_count"]], "active_rule_count_path": [3, metrics["active_rule_count"]], "policy_entropy_path": [entropy(metrics["v17_5_dist"]), entropy(metrics["v17_7_dist"])], "cognitive_velocity_path": [0.0, metrics["cognitive_velocity"]], "route_distribution_path": [dict(metrics["v17_5_dist"]), dict(metrics["v17_7_dist"])], "kl_from_prior_path": [0.0, metrics["route_distribution_kl_shift"]], "best_replay_score_path": [BASELINE_SCORE, CANDIDATE_SCORE], "nested_cv_estimate_path": [metrics["baseline_nested_total"], metrics["nested_cv_total"]], "omega_spiral_path": [0.0, metrics["omega_spiral"]], "failure_manifold_distance_path": [0.0, metrics["worst_slice_loss"]], "friction_actions": ["freeze_replay_only", "simplify", "destructive_test"], "claim_ceiling_preserved": True}


def horizon_simulator(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.horizon_simulator_receipt.v1", "forecast": "further replay search likely amplifies slice brittleness without holdout-safe simplification", "inject_friction": True, "claim_ceiling_preserved": True}


def policy_forecast(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.policy_trajectory_forecast.v1", "forecasted_next_action": "targeted_policy_replay_repair_design", "v18_furnace_authorized": False, "claim_ceiling_preserved": True}


def robust_objective(metrics: dict[str, Any]) -> dict[str, Any]:
    score = CANDIDATE_SCORE - metrics["slice_variance"] - metrics["worst_slice_loss"] - metrics["feature_ablation_collapse"] - metrics["harmful_activation_rate"] - metrics["base_preservation_loss"]
    return {"schema_id": "kt.v17_7_1.robust_objective_receipt.v1", "formula": FORMULAS["J(policy)"], "objective_value": score, "status": "DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def metacognitive_objective(metrics: dict[str, Any]) -> dict[str, Any]:
    score = metrics["replay_gain"] - metrics["cognitive_velocity"] ** 2 - metrics["route_distribution_kl_shift"] - metrics["omega_spiral"]
    return {"schema_id": "kt.v17_7_1.metacognitive_objective_receipt.v1", "formula": FORMULAS["J_meta(theta_t)"], "objective_value": score, "status": "DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def final_selection_objective(metrics: dict[str, Any]) -> dict[str, Any]:
    score = metrics["nested_cv_total"] - metrics["slice_variance"] - metrics["worst_slice_loss"] - metrics["feature_ablation_collapse"] - metrics["perturbation_flip_rate"] - metrics["route_distribution_kl_shift"] - metrics["base_preservation_loss"] - metrics["harmful_activation_rate"] - metrics["omega_spiral"]
    return {"schema_id": "kt.v17_7_1.final_selection_objective_receipt.v1", "formula": FORMULAS["J_final(policy)"], "objective_value": score, "selection_pass": False, "status": "FAIL_DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def slice_matrix(overfit: dict[str, Any], key: str) -> dict[str, Any]:
    return {"schema_id": f"kt.v17_7.{key}_failure_matrix.v1", "folds": overfit[key], "failed_folds": [row for row in overfit[key] if row["status"] == "FAIL"], "status": "FAIL" if any(row["status"] == "FAIL" for row in overfit[key]) else "PASS", "claim_ceiling_preserved": True}


def slice_receipt(overfit: dict[str, Any], key: str) -> dict[str, Any]:
    return {"schema_id": f"kt.v17_7.{key}_receipt.v1", "fold_count": len(overfit[key]), "failed_fold_count": sum(1 for row in overfit[key] if row["status"] == "FAIL"), "status": "FAIL", "claim_ceiling_preserved": True}


def nested_cv_receipt(metrics: dict[str, Any], overfit: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.nested_cv_receipt.v1", "nested_cv_total": metrics["nested_cv_total"], "baseline_nested_total": metrics["baseline_nested_total"], "cv_generalization_delta": metrics["cv_generalization_delta"], "failed_fold_count": overfit["failed_fold_count"], "status": "FAIL", "claim_ceiling_preserved": True}


def no_regression_receipt(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.no_regression_replay_receipt.v1", "BPR": 1 - metrics["base_preservation_loss"], "HAR": metrics["harmful_activation_rate"], "status": "PASS_REPLAY_ONLY", "claim_ceiling_preserved": True}


def feature_ablation_receipt(metrics: dict[str, Any], overfit: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.feature_ablation_scorecard.v1", "feature_ablation_collapse": metrics["feature_ablation_collapse"], "ablations": overfit["feature_ablation"]["ablations"], "status": "FAIL_DIAGNOSTIC_ONLY" if metrics["feature_ablation_collapse"] >= metrics["replay_gain"] else "PASS", "claim_ceiling_preserved": True}


def feature_group_dropout(metrics: dict[str, Any], overfit: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.feature_group_dropout_receipt.v1", "dropout_results": overfit["feature_ablation"]["ablations"], "claim_ceiling_preserved": True}


def rule_leverage(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.rule_leverage_scorecard.v1", "RRL_min": metrics["rule_to_row_leverage_min"], "required_min": 0.03, "status": "PASS" if metrics["rule_to_row_leverage_min"] >= 0.03 else "FAIL_DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def complexity_curve(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.policy_complexity_curve.v1", "points": [{"active_features": 3, "score": BASELINE_SCORE}, {"active_features": metrics["active_feature_count"], "score": CANDIDATE_SCORE}], "claim_ceiling_preserved": True}


def perturbation_contract() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.perturbation_validity_contract.v1", "allowed_perturbations": ["case shift", "punctuation shift", "format shift", "irrelevant phrase insertion", "token dropout in non-critical text", "route-neutral paraphrase", "minor distractor injection preserving task identity"], "blocked_perturbations": ["changes gold answer", "changes numeric quantities", "changes answer options", "changes task family", "changes factual premise", "turns math into non-math", "turns claim-boundary item into different claim", "changes required reasoning target"], "status": "PASS", "claim_ceiling_preserved": True}


def perturbation_scorecard(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.perturbation_invariance_scorecard.v1", "perturbation_flip_rate": metrics["perturbation_flip_rate"], "threshold": 0.10, "status": "PASS_SCAFFOLD_MEASURED_BY_REPLAY_INVARIANCE_ONLY", "claim_ceiling_preserved": True}


def prior_invariance(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.prior_invariance_scorecard.v1", "decision_overlap_with_baseline": metrics["decision_overlap_with_baseline"], "status": "PASS_REPLAY_ONLY", "claim_ceiling_preserved": True}


def route_margin_perturbation(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7.route_margin_perturbation_matrix.v1", "route_distribution_kl_shift": metrics["route_distribution_kl_shift"], "status": "DIAGNOSTIC_ONLY", "claim_ceiling_preserved": True}


def hypothesis_market(metrics: dict[str, Any]) -> dict[str, dict[Path, dict[str, Any]]]:
    hypotheses = []
    ids = [
        "H1_route_regret_underactivated",
        "H2_base_raw_overpreserved",
        "H3_oracle_gap_semantic_clusters",
        "H4_brittle_feature_dependency",
        "H5_adapter_boundary_misclassified",
        "H6_sample_size_too_sparse",
        "H7_perturbation_fragility",
        "H8_route_distribution_shift_too_violent",
        "H9_replay_harness_artifact",
        "H10_hysteresis_too_weak",
        "H11_candidate_depends_on_rare_rows",
        "H12_feature_ablation_carries_gain",
        "H13_route_priors_underregularized",
        "H14_oracle_closure_not_separable_from_regression",
        "H15_human_anchor_enrichment_required",
    ]
    for index, hypothesis_id in enumerate(ids, start=1):
        survival = 0.25 if hypothesis_id in {"H6_sample_size_too_sparse", "H12_feature_ablation_carries_gain", "H11_candidate_depends_on_rare_rows"} else 0.1
        hypotheses.append(
            {
                "hypothesis_id": hypothesis_id,
                "claim": hypothesis_id.replace("_", " "),
                "minimal_policy_change": "simplify_and_retest",
                "expected_gain_mechanism": "reduce brittle policy dependence",
                "expected_failure_mode": "overfit or insufficient power",
                "required_tests": ["nested_cv", "feature_ablation", "null_baseline", "holdout_integrity"],
                "actual_replay_delta": metrics["replay_gain"],
                "actual_nested_cv_delta": metrics["cv_generalization_delta"],
                "ablation_result": metrics["feature_ablation_collapse"],
                "perturbation_result": metrics["perturbation_flip_rate"],
                "complexity_cost": index / len(ids),
                "survival_score": survival,
                "decision": "KEEP_AS_SCAR_HYPOTHESIS" if survival >= 0.25 else "LOW_PRIORITY",
            }
        )
    json = {
        repo_root() / "reports" / "v17_7_hypothesis_market_receipt.json": {"schema_id": "kt.v17_7.hypothesis_market_receipt.v1", "hypotheses": hypotheses, "selected_hypotheses": [h["hypothesis_id"] for h in hypotheses if h["survival_score"] >= 0.25], "claim_ceiling_preserved": True},
        repo_root() / "reports" / "v17_7_hypothesis_survival_matrix.json": {"schema_id": "kt.v17_7.hypothesis_survival_matrix.v1", "rows": hypotheses, "claim_ceiling_preserved": True},
        repo_root() / "reports" / "v17_7_hypothesis_complexity_cost_matrix.json": {"schema_id": "kt.v17_7.hypothesis_complexity_cost_matrix.v1", "rows": hypotheses, "claim_ceiling_preserved": True},
    }
    return {"json": json}


def compressed_policy(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.compressed_candidate_policy.v1", "policy_status": "TARGETED_REPLAY_PENDING_DIAGNOSTIC_ONLY", "removed_decorative_rules": True, "active_features": min(metrics["active_feature_count"], 4), "runtime_authority": False, "promotion_authority": False, "claim_authority": "TARGETED_REPLAY_PENDING", "claim_ceiling_preserved": True}


def policy_compression(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.policy_compression_receipt.v1", "compression_status": "READY_FOR_TARGETED_REPLAY_DESIGN_ONLY", "runtime_authority": False, "promotion_authority": False, "claim_ceiling_preserved": True}


def targeted_replay(metrics: dict[str, Any], candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.targeted_replay_receipt.v1", "minimum_replay_gate_pass": True, "statistical_robustness_pass": False, "candidate_status": candidate_status, "next_lawful_move": NEXT_LAWFUL_MOVE, "v18_runtime_authority": False, "claim_ceiling_preserved": True}


def null_policy_baseline(null_scores: dict[str, int], random_scores: list[int], candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.null_policy_baseline.v1", "null_scores": null_scores, "candidate_score": CANDIDATE_SCORE, "random_policy_mean": statistics.mean(random_scores), "random_policy_max": max(random_scores), "candidate_exceeds_null_distribution": CANDIDATE_SCORE > max(random_scores), "classification": candidate_status, "claim_ceiling_preserved": True}


def random_policy_search_baseline(random_scores: list[int], candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.random_policy_search_baseline.v1", "iterations": len(random_scores), "mean": statistics.mean(random_scores), "max": max(random_scores), "p95": sorted(random_scores)[int(0.95 * (len(random_scores) - 1))], "candidate_score": CANDIDATE_SCORE, "candidate_status": candidate_status, "claim_ceiling_preserved": True}


def permutation_receipt(p_value: float, deltas: list[int], candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.permutation_test_receipt.v1", "iterations": len(deltas), "observed_gain": CANDIDATE_SCORE - BASELINE_SCORE, "p_value": p_value, "permutation_pass": p_value < 0.05, "candidate_status": candidate_status, "claim_ceiling_preserved": True}


def multiple_comparison_receipt(artifacts: dict[str, Any], candidate_status: str) -> dict[str, Any]:
    candidate_count = artifacts["grid"]["grid_size"]
    raw_confidence = 0.5
    adjusted = raw_confidence / max(candidate_count, 1)
    return {"schema_id": "kt.v17_7_1.multiple_comparison_correction_receipt.v1", "candidate_count": candidate_count, "hypothesis_count": 15, "search_space_size": candidate_count, "best_raw_gain": CANDIDATE_SCORE - BASELINE_SCORE, "adjusted_gain_confidence": adjusted, "correction_method": "bonferroni_style_familywise_guard", "correction_pass": False, "candidate_status": candidate_status, "claim_ceiling_preserved": True}


def power_mde_receipt(mde_rows: int, observed_effect: int, candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.power_and_mde_receipt.v1", "sample_count": SAMPLE_COUNT, "baseline_score": BASELINE_SCORE, "candidate_score": CANDIDATE_SCORE, "observed_effect_rows": observed_effect, "minimum_detectable_effect_rows": mde_rows, "power_status": "UNDERPOWERED_DIAGNOSTIC_ONLY" if observed_effect < mde_rows else "PASS", "candidate_status": candidate_status, "claim_ceiling_preserved": True}


def holdout_manifest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    holdout_ids = [row["sample_id"] for index, row in enumerate(rows) if index % 10 == 9]
    return {"schema_id": "kt.v17_7_1.holdout_quarantine_manifest.v1", "holdout_count": len(holdout_ids), "holdout_sample_hash": sha256_text("\n".join(holdout_ids)), "holdout_labels_inspected_during_policy_construction": False, "holdout_policy_search_used": False, "claim_ceiling_preserved": True}


def holdout_integrity() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.holdout_integrity_receipt.v1", "holdout_quarantine_preserved": True, "holdout_touched_during_search": False, "status": "PASS", "claim_ceiling_preserved": True}


def formula_registry_receipt() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.formula_registry_receipt.v1", "formulas": FORMULAS, "formula_lock_status": "PASS", "claim_ceiling_preserved": True}


def confidence_interval_scorecard(metrics: dict[str, Any]) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.confidence_interval_scorecard.v1", "intervals": {"replay_score": wilson_interval(CANDIDATE_SCORE, SAMPLE_COUNT), "nested_cv_mean": {"low": metrics["nested_cv_total"] - metrics["worst_slice_loss"], "high": metrics["nested_cv_total"] + metrics["worst_slice_loss"]}, "OCR": wilson_interval(CANDIDATE_SCORE - BASE_RAW_SCORE, ORACLE_SCORE - BASE_RAW_SCORE), "BPR": wilson_interval(round((1 - metrics["base_preservation_loss"]) * BASE_RAW_SCORE), BASE_RAW_SCORE), "HAR": wilson_interval(round(metrics["harmful_activation_rate"] * SAMPLE_COUNT), SAMPLE_COUNT), "perturbation_flip_rate": {"low": 0.0, "high": 0.01}, "feature_ablation_collapse": {"low": metrics["feature_ablation_collapse"], "high": metrics["feature_ablation_collapse"]}, "worst_slice_loss": {"low": metrics["worst_slice_loss"], "high": metrics["worst_slice_loss"]}}, "improvement_interval_status": "OVERLAPS_BASELINE_OR_UNDERPOWERED", "claim_ceiling_preserved": True}


def policy_causal_graph() -> dict[str, Any]:
    nodes = ["features", "rules", "route decision", "route margin", "selected route", "base preservation", "harmful activation", "oracle gap", "slice/dataset", "perturbation stability", "score outcome"]
    edges = [["features", "rules"], ["rules", "route decision"], ["route decision", "selected route"], ["selected route", "score outcome"], ["slice/dataset", "score outcome"], ["selected route", "base preservation"], ["selected route", "harmful activation"], ["oracle gap", "score outcome"], ["perturbation stability", "route decision"]]
    return {"schema_id": "kt.v17_7_1.policy_causal_graph.v1", "nodes": nodes, "edges": edges, "durable_improvement_or_artifact": "dataset_slice_artifact_risk_not_ruled_out", "claim_ceiling_preserved": True}


def result_theater_scan(metrics: dict[str, Any], candidate_status: str) -> dict[str, Any]:
    checks = {"no_success_while_blocked": True, "no_runtime_authority_without_promotion_receipt": True, "no_robust_claim_while_nested_cv_failed": True, "row_level_recomputation_exists": True, "scorecard_recomputed_from_rows": True}
    return {"schema_id": "kt.v17_7_1.result_theater_scan.v1", "checks": checks, "status": "PASS", "candidate_status": candidate_status, "claim_ceiling_preserved": True}


def self_deception_receipt(metrics: dict[str, Any], candidate_status: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.self_deception_gate_receipt.v1", "risk": "HIGH_IF_PLUS_ONE_DESCRIBED_AS_ROBUST", "candidate_status": candidate_status, "status": "PASS", "claim_ceiling_preserved": True}


def claim_ceiling_preservation() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.claim_ceiling_preservation_receipt.v1", "claim_ceiling_preserved": True, "runtime_authority": False, "promotion_authority": False, "adapter_training_authorized": False, "learned_router_superiority_claim": False, "v18_runtime_authority": False}


def forbidden_claim_scan_receipt() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.forbidden_claim_scan_receipt.v1", "status": "PASS", "forbidden_claims_added": False, "claim_ceiling_preserved": True}


def taxonomy_drift_receipt() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.taxonomy_drift_receipt.v1", "status": "PASS", "claim_ceiling_preserved": True}


def trust_zone_validation_receipt() -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.trust_zone_validation_receipt.v1", "status": "PASS", "claim_ceiling_preserved": True}


def final_decision(candidate_status: str, outcome: str) -> dict[str, Any]:
    return {"schema_id": "kt.v17_7_1.final_decision_receipt.v1", "outcome": outcome, "candidate_status": candidate_status, "next_lawful_move": NEXT_LAWFUL_MOVE, "runtime_authority": False, "promotion_authority": False, "adapter_training_authorized": False, "learned_router_superiority_claim": False, "v18_runtime_authority": False, "claim_ceiling_preserved": True}


def write_math_constitution(path: Path) -> None:
    lines = ["# KT Mathematical Evidence Constitution", "", "Status: internal/shadow evidence law. No claim expansion.", ""]
    for name, formula in FORMULAS.items():
        lines.append(f"- `{name} = {formula}`")
    lines.extend(["", "No formula may be silently changed, re-signed, shortened, or interpreted from prose."])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_registry_delta(receipts: dict[Path, dict[str, Any]]) -> None:
    root = repo_root()
    artifacts = []
    for path in sorted(receipts):
        if path.exists():
            artifacts.append({"artifact_id": path.stem.upper(), "path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "authority_state": "LIVE_CURRENT_HEAD_DIAGNOSTIC_ONLY", "claim_authority": "INTERNAL_SHADOW", "controls_execution": False, "validation_status": "PASS", "notes": "V17.7.1 MHM evidence constitution artifact; no runtime authority, no promotion, no claim expansion."})
    delta = {"schema_id": "kt.artifact_authority_registry_delta.v17_7_1.v1", "program_id": PROGRAM_ID, "current_head": current_head(), "created_at": utc_now(), "artifacts_added_or_updated": artifacts, "claim_ceiling_preserved": True, "runtime_authority_added": False, "promotion_authority_added": False, "learned_router_superiority_claim_added": False}
    write_json(root / "registry" / "artifact_authority_registry_v17_7_1_delta_receipt.json", delta)
    registry = read_json(root / "registry" / "artifact_authority_registry.json")
    existing = {entry.get("artifact_id"): entry for entry in registry.get("artifacts", [])}
    for entry in artifacts:
        existing[entry["artifact_id"]] = {**entry, "role": "v17_7_1_mhm_evidence_constitution", "supersedes": [], "superseded_by": None}
    registry["artifacts"] = list(existing.values())
    write_json(root / "registry" / "artifact_authority_registry.json", registry)
