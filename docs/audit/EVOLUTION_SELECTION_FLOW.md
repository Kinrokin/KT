# EVOLUTION_SELECTION_FLOW (forensic)

This document answers: what “selection” exists today, what signals it uses, and whether it is multi-criteria trait learning or primarily mechanical gates.

## 1) Factory lane selection (FL4 MRT-0)

### 1.1 Within-job selection (policy bundles)

- Hypotheses: `kt.policy_bundle.v1` (categorical genotype)
- Evaluation: `kt.factory.eval_report.v2` (utility floor score + probes)
- Judgement: `kt.factory.judgement.v1` (rule-based; produced in `judge.py`)
- Derived gates: `kt.signal_quality.v1` + `kt.fitness_region.v1`

Selection trigger:
- `KT_PROD_CLEANROOM/tools/training/fl3_factory/promote.py::decide_promotion(...)`
  - requires:
    - `eval_report.final_verdict == PASS`
    - `job.mode == SOVEREIGN` (canonical promotable lane)
    - valid reasoning trace present and verified
    - `fitness_region == A`

### 1.2 Atomic promotion

If `decision == PROMOTE`:
- `tools/verification/fl4_promote.py` materializes a content-addressed promoted package
- updates `promoted_index.json` atomically

This is selection in the “publish / do not publish” sense.

## 2) Growth lane selection (pressure)

Growth lane selection is not “pick the best adapter”:
- it is “prove the growth system passes required crucibles + coverage.”

Signals:
- crucible outcomes (PASS/FAIL/FAIL_CLOSED)
- required coverage evidence (`crucible_coverage.json`)
- epoch verdict (OPERATIONAL vs not)

## 3) Trait learning vs mechanical gating — current truth

What exists as *numeric or multi-field signals*:
- `utility_floor_score` (single scalar) + independent probe delta
- `risk_estimate` / `governance_strikes` (simple numeric gates)
- crucible coverage report (multi-field evidence, but used as PASS/FAIL gating)
- policy-c pressure tensor axes exist as a schema/type, but are not clearly used here as a learned trait vector.

What does not exist (based on current code paths):
- a stable, multi-axis “cognitive trait embedding” used for selection
- a learned trait inheritance mechanism beyond hash lineage

