# KT_LEARNING_SYSTEM_MASTER_MAP (forensic)

This is the synthesis view: what “learning” exists today in the repo, what signals are produced, and whether it is cognitive trait learning or primarily mechanical contract-based selection.

## 1) Mechanical learning signals (PASS/FAIL / gates)

What exists and is used:
- Growth lane: crucible outcomes (PASS/FAIL/FAIL_CLOSED) plus mandatory coverage evidence (`crucible_coverage.json`) under governance kernels.
- Factory lane promotion: hard gates on:
  - `eval_report.final_verdict == PASS`
  - trace existence + verification
  - derived `fitness_region == A`

These are strong, fail-closed governance triggers.

## 2) Numerical metrics used for gating

What exists and is used:
- `utility_floor_score` (single scalar in [0,1]) + `utility_floor_pass`
- independent probe delta + agreement checks
- `risk_estimate` and `governance_strikes`

This is numeric scoring, but not a multi-axis cognitive trait system.

## 3) Multi-axis / trait structures

What exists as types/schemas:
- Policy-C pressure tensor: `KT_PROD_CLEANROOM/policy_c/pressure_tensor.py` defines 7 axes (`time/universe/language/hop/step/paradox/puzzle`).
- FL3.2 cognitive fitness lane: schemas/tools for multi-axis cognitive fitness receipts.

What is *not* established as the canonical selection surface in FL4 MRT-0:
- a learned multi-axis trait vector used to compare candidates for promotion.

In the current repo, “traits” are mostly categorical (policy-bundle genotype enums, fitness region A/B/C) and single-scalar utility floor scoring.

## 4) Adapter routing vs factory selection

- Runtime adapter routing (Council router) is a separate system concerned with runtime invocation, providers, and logging discipline.
- Factory selection is an offline, receipt-bound lane producing promoted packages into `exports/adapters` and updating `promoted_index.json`.

## 5) What is real vs what is only designed

Real (implemented and wired):
- Deterministic hypothesis generation for AdapterType A (policy bundles)
- Utility floor metric + independent probes
- Signal quality + derived fitness region gating
- Promotion decision + atomic promotion packaging
- Growth crucible execution with coverage artifacts and fail-closed aggregation

Designed / present as schema or scaffolding but not proven as canonical behavior without executing those lanes:
- deeper “trait inheritance” beyond parent_hash chains
- breeding/VRR being metabolic rather than structural
- multi-axis cognitive fitness receipts being required for promotion in the FL4 MRT-0 lane

