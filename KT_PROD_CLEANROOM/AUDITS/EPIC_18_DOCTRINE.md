# EPIC_18 — Auditor-Grade Consolidated Eval Report (BINDING DOCTRINE)

## Purpose

EPIC_18 produces a single, schema-bound, deterministic summary artifact that an auditor can ingest without reverse-engineering tool logs.

This EPIC **does not** introduce new enforcement gates. It is an **evidence packaging** EPIC:

- Inputs: schema-valid `kt.suite_definition.v1`, `kt.suite_eval_report.v1`, and `kt.axis_fitness_report.v1`.
- Output: schema-valid `kt.audit_eval_report.v1` plus a grep-safe one-line verdict string.

## Invariants (Fail-Closed)

- **Schema-first:** `kt.audit_eval_report.v1` must be registered and validated via the FL3 schema registry.
- **Deterministic:** no wall-clock values may influence any **ID** or any **hash surface**.
- **WORM outputs:** report files are create-once with byte-identical no-op semantics.
- **Canonical lane truthfulness:** if `KT_CANONICAL_LANE=1`, the report must record `attestation_mode=HMAC` (otherwise fail-closed).
- **Sorted artifacts:** the report `artifacts[]` list is sorted by `path` and contains unique paths.

## Composition Rules

- Consolidated `decision` is conservative:
  - any component `decision=QUARANTINE` OR `hard_gate_pass=false` ⇒ `decision=QUARANTINE`
  - else any component `decision=HOLD` ⇒ `decision=HOLD`
  - else ⇒ `decision=PROMOTE`
- Consolidated `axis_scores` is the union of axis IDs across component fitness reports.
  - Duplicate `axis_id` across components is **illegal** (fail-closed).

## One-line Verdict

The report contains a grep-safe one-line verdict string:

`KT_AUDIT_EVAL_VERDICT_V1 | decision=... | canon=0|1 | attestation=... | run_id=... | law=... | suite_registry=... | <axis>=<score> ...`

This line is also emitted to stdout by the generator tool.

