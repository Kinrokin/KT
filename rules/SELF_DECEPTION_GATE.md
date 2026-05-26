# Self-Deception Gate

Fails if any of these occur:

- PASS without measured evidence.
- Scaffold evidence treated as earned.
- Niche result described globally.
- Adapter promoted without no-regression.
- Metric lacks anti-Goodhart pair.
- Failure lacks causal owner.
- Training occurs without training decision receipt.
- Negative result omitted.
- Claim lacks admissibility tier.
- Commercial/frontier claim appears from internal-only evidence.

## Score

```text
self_deception_risk_score =
  0.20 * unowned_failure_rate
+ 0.20 * scaffold_pass_rate
+ 0.15 * unpaired_metric_rate
+ 0.15 * niche_to_global_claim_rate
+ 0.10 * omitted_negative_result_rate
+ 0.10 * training_without_owner_rate
+ 0.10 * claim_without_admissibility_rate
```

Promotion requires risk score = 0.
