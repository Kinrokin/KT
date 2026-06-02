# KT Mathematical Evidence Constitution

Status: internal/shadow evidence law. No claim expansion.

- `replay_gain = candidate_replay_score - baseline_replay_score`
- `cv_generalization_delta = replay_score - mean_nested_cv_score`
- `BPR = baseline_correct_candidate_correct / baseline_correct_total`
- `HAR = harmful_route_activations / total_route_activations`
- `OCR = oracle_gap_closed / total_oracle_gap`
- `RRL(rule) = rows_changed_by_rule / total_rows`
- `feature_count_ratio = active_feature_count / effective_sample_size`
- `feature_ablation_collapse = candidate_score - score_after_removing_top_feature`
- `perturbation_flip_rate = changed_decisions_under_noise / total_decisions`
- `KL(P || Q) = sum_i P(i) * log(P(i) / Q(i))`
- `decision_overlap = same_route_decisions(candidate, baseline) / total_rows`
- `CVel_t = ||theta_t - theta_(t-1)||_2 / delta_step`
- `H(P_routes) = - sum_i P(route_i) * log(P(route_i))`
- `D_fail = min_i sqrt(sum_j w_j * (x_candidate_j - x_fail_i_j)^2)`
- `Omega_spiral = sigmoid(a1 * normalized_CVel + a2 * normalized_boundary_proximity + a3 * (1 - normalized_RRL_min) + a4 * normalized_feature_ablation_collapse + a5 * normalized_perturbation_flip_rate + a6 * normalized_route_distribution_kl_shift + a7 * normalized_base_preservation_loss + a8 * max(0, -policy_entropy_delta))`
- `J(policy) = mean_score - lambda_1 * slice_variance - lambda_2 * worst_slice_loss - lambda_3 * feature_ablation_sensitivity - lambda_4 * harmful_activation - lambda_5 * base_preservation_loss`
- `J_meta(theta_t) = L_perf(theta_t) - alpha * ||theta_t - theta_(t-1)||_2^2 - beta * KL(P_theta_t || P_prior) - gamma * Omega_spiral(theta_t, M_fail)`
- `J_final(policy) = nested_cv_mean - lambda_1 * nested_cv_variance - lambda_2 * worst_slice_loss - lambda_3 * feature_ablation_collapse - lambda_4 * perturbation_flip_rate - lambda_5 * route_distribution_kl_shift - lambda_6 * base_preservation_loss - lambda_7 * harmful_activation_rate - gamma * Omega_spiral`

No formula may be silently changed, re-signed, shortened, or interpreted from prose.
