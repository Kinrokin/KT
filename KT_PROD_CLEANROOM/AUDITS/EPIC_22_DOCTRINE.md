# EPIC_22 — AXIOM PROTOCOL SUITE (APF / IADS / PFM / POG / RISK MATH)

Status: **BINDING (measurement artifact)**  
Mode: **ADD-ONLY · FAIL-CLOSED · DETERMINISTIC**

## Intent

EPIC_22 makes a small set of “axiom protocol” behaviors mechanically measurable as a **deterministic, machine-checkable** evaluation suite.

This closes a subtle gap that survives EPIC_15/16/17/18/19/20/21:

- you can be procedurally governed and deterministic, yet still drift epistemically if “what we measure” is underspecified.

EPIC_22 therefore adds a **tight, contract-grade micro-suite** that encodes core epistemic invariants as JSON-exact decisions:

- **APF (Paradox)** — absorb contradiction into a 4-valued state (`BOTH`) instead of crashing.
- **POG (Generative)** — paradox (`BOTH`) triggers teacher/repair behavior (`TRIGGER_TEACHER`).
- **IADS (Truth)** — when minority evidence authenticates better than majority, protect the minority (`PROTECT_MINORITY`).
- **PFM (Fatigue)** — correlated human error above threshold rejects quorum (`REJECT_QUORUM`).
- **Risk Math (Tail Risk)** — CVaR reasoning is treated as an auditable numeric contract.

## What EPIC_22 adds (measurement-only)

- `KT_PROD_CLEANROOM/AUDITS/VALIDATOR_CATALOG_FL3_V3.json`
- `KT_PROD_CLEANROOM/AUDITS/AXIS_SCORING_POLICY_AXIOM_PROTOCOLS_V1.json`
- `KT_PROD_CLEANROOM/AUDITS/SUITES/SUITE_AXIOM_PROTOCOLS.v1.json`

## Invariants

- **JSON-only outputs** for all cases (no markdown, no code fences, no extra text).
- **Schema-bound evaluation** via `tools.eval.run_suite_eval` using a pinned validator catalog and axis scoring policy.
- **Strict verdict semantics**: all axes must pass to promote.

## Use

1. Add `SUITE_AXIOM_PROTOCOLS` to `KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json` with **HMAC signoffs** (2-of-2).
2. Run suite eval (factory or offline harness) and retain:
   - `suite_eval_report.json`
   - `axis_fitness_report.json`
3. Generate an auditor report via:
   - `tools.verification.generate_audit_eval_report`

## Non-goals

- No changes to runtime routing or canonical enforcement spines.
- No automatic adoption into tournament gates until explicitly referenced by governed plans.

