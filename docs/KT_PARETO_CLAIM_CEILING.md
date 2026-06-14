# KT Pareto Claim Ceiling

This repo lane only authors an internal Budget Pareto Sweep packet. It does not run Kaggle, train, promote, deploy a selector, mutate adapters, mutate production prompts, or expand the claim ceiling.

Allowed claim: a bounded internal Budget Pareto sweep packet was authored for a clean GSM8K non-overlap slice to measure the cost/correctness frontier under fixed budgets and preserve fixed512 as control pending evidence.

Per-arm bounds:
- `A0_COT_96_FIXED`: `under_evaluation_low_budget_diagnostic_only`
- `A1_COT_192_FIXED`: `under_evaluation_low_budget_diagnostic_only`
- `A2_COT_256_FIXED`: `known_prior_false_economy_risk_not_globally_safe`
- `A3_COT_320_FIXED`: `under_evaluation`
- `A4_COT_384_FIXED`: `under_evaluation`
- `A5_COT_448_FIXED`: `under_evaluation`
- `A6_COT_512_FIXED_CONTROL`: `current_measured_control_must_be_remeasured_on_this_slice`
- `A7_COT_640_FIXED_SENTINEL`: `sentinel_not_deployable_by_default`
- `A8_ANSWER_ONLY_NO_COT`: `weak_simple_row_control_only_not_gsm8k_strategy`
- `A9_ORACLE_DIAGNOSTIC_PER_ARM`: `hindsight_only_non_deployable`
