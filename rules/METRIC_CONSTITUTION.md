# Metric Constitution

No metric is trusted without its anti-Goodhart pair.

VWPT = W_verified / T_total

Operational VWPT:
VWPT = (correct + 0.35 * verifier_pass + 0.20 * admissible - regression_penalty) / total_output_tokens

TPC = T_total / C_verified
UCR = unsupported_claims / total_claims * 100
HOR_abs = T_hat / max(pre_hat_tokens, 1)
HOR_delta = (T_hat - T_raw) / max(T_raw, 1)
RR(x) = max_{r in R} utility(r,x) - utility(chosen,x)
VRV = delta_VWPT / repair_compute_cost
SY = useful_repair_examples / total_failures
DD = 1 if Hash(delta_repair) != Hash(delta_source) else 0
GAD = delta_VWPT_admissible / (repair_cost + governance_overhead)

Utility:
utility = 1.0*correct + 0.35*verifier_pass + 0.20*admissible - 0.20*normalized_tokens - 0.10*normalized_latency - governance_risk_cost - over_routing_penalty - abstention_degradation_penalty

Anti-Goodhart pairs:
- VWPT -> answer_adequacy_score + external_verifier_agreement
- TPC -> safety_pass_rate
- UCR -> claim_density
- HOR -> answer_adequacy_score + safety_pass_rate + utility_collapse_flag
- RR -> irreducible_uncertainty_score + OOD_route_stability + no_regression_pass
- SY -> human_anchor_agreement
- DD -> target_metric_gain + failure_map_present + semantic_delta_present + no_regression_pass
- GAD -> external_verifier_delta + claim_ceiling_preservation
