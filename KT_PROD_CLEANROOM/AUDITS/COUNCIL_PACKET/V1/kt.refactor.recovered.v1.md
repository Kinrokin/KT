# kt.refactor.recovered.v1.md

Generated at: 2026-02-17T03:53:00Z

## Scope and provenance

This recovered plan is reconstructed from the files present in the ChatGPT sandbox (see `kt.audit.index.v1.json`).
No Google Drive crawl was performed because `drive_manifest.json` was not provided.

Where the recovered plan proposes new artifacts, they are labeled **PROPOSED** and must be implemented by engineering.
Where the plan asserts constraints, it ties back to user-provided constraint files or extracted documents.

## Executive reconstruction of KT from scanned documents

### KT system intent (document-derived)

Based on the scanned PDFs, KT is framed as a governed, adversarially-hardened methodology for AI oversight and evolution under a formal doctrine emphasizing anti-fragility and disciplined engineering practice.

**Provenance (extracted text pointers):**
- `kt_intent_anti_fragile_ai_paradox.pdf` and `aape.pdf` are the only scanned narrative sources in this sandbox; see `kt.audit.index.v1.json` for SHA256.

## KT V1+ canonical-safe execution plan (final integrated order)

This plan is **PROPOSED** as the canonical-safe ordering that aligns with the constraints and failure-modes surfaced in the audit.

### Phase 0 — Clean ground (repo hygiene)
**Objective:** No contaminated receipts or partial writes can exist before admission, evaluation, or sealing.

**Deliverables (PROPOSED):**
- `exports/_runs/<run_id>/phase0_pre.json`
- `exports/_runs/<run_id>/phase0_post.json`
- `exports/_runs/<run_id>/COMPLETENESS_SCAN.txt`
- `exports/_runs/<run_id>/STUB_SCAN.txt`

**Hard checks (PROPOSED):**
- `git status --porcelain` is empty
- secret scan passes
- canonicalizer singleton invariant holds
- meta-evaluator passes

### Phase 1 — Law before cognition
**Objective:** Define the law and failure taxonomy before implementing enforcement.

**Deliverables (PROPOSED):**
- `KT_PROD_CLEANROOM/AUDITS/EPIC_15_DOCTRINE.md`
- `KT_PROD_CLEANROOM/AUDITS/LAW_AMENDMENT_EPIC15_PROPOSED.json`
- `KT_PROD_CLEANROOM/AUDITS/FAILURE_TAXONOMY_FL3.json` (updated)

### Phase 2 — Schemas before tools
**Objective:** Every runtime artifact and receipt must be schema-bound and hashable.

**Deliverables (PROPOSED schemas):**
- `kt.eval_suite_manifest.v1`
- `kt.suite_case.v1`
- `kt.match_receipt.v1`
- `kt.tournament_result.v1`
- `kt.dominance_report.v1`
- `kt.audit_eval_report.v1`
- `kt.fractal_expansion.v1`
- `kt.shard_plan.v1`

### Phase 3 — Master valve (admission gate)
**Objective:** Training/evaluation cannot proceed without deterministic admission under law.

**Deliverables (PROPOSED):**
- `tools/verification/training_admission.py`
- admission receipts with closed reason codes
- determinism replay validator

### Phase 4 — Fractal suite compiler, with redpack split
**Objective:** Expand to 1250 cases without illegal runtime generation or unsafe prompt leakage.

**Key correction:** The suite should be **compiled once** and then treated as sealed static input.

**Deliverables (PROPOSED):**
- `AUDITS/FRAC/kt.fractal_expansion.v1.json` (declares expansion algebra)
- `AUDITS/SUITES/SUITE_GOV_FRACTAL_1250.v1.json` (compiled manifest, no raw payloads)
- `AUDITS/REDPACKS/REDPACK_GOV_FRACTAL_1250.v1.jsonl.enc` (sealed payload pack, stored outside repo if policy requires)
- `.hash` + registry entries for suite + redpack

### Phase 5 — Sharding below evaluation
**Objective:** Increase throughput without breaking provenance or determinism.

**Deliverables (PROPOSED):**
- `AUDITS/SHARDS/SHARD_PLAN_1250x10.v1.json` (static partition of case_ids)
- `tools/eval/run_suite_eval_shard.py`
- `tools/eval/reduce_suite_eval_shards.py` (completeness + overlap checks, canonical merge)

### Phase 6 — Tournament and dominance
**Objective:** Deterministic tournament with byte-identical reruns.

**Deliverables (PROPOSED):**
- `tools/tournament/run_tournament.py` (deterministic ordering)
- `kt.match_receipt.v1` receipts
- `kt.tournament_result.v1` output
- `kt.dominance_report.v1`
- `kt.champion_set.v1`

### Phase 7 — Merge admissibility and rollback
**Objective:** Promotion is gated; rollback always available.

**Deliverables (PROPOSED):**
- `tools/merge/merge_evaluator.py`
- `kt.merge_manifest.v1`
- `kt.merge_eval_receipt.v1`
- `rollback_plan.v1.json`

### Phase 8 — Detection axis (soft axis)
**Objective:** Measure detection of adversarial intent in addition to refusal.

**Deliverables (PROPOSED):**
- detection validators
- axis scoring policy updates

### Phase 9 — Audit report and one-line verdict
**Objective:** Machine-first; visualization second.

**Deliverables (PROPOSED):**
- `kt.audit_eval_report.v1.json`
- `audit_eval_verdict.txt`
- `God Report` (NON-CANONICAL watermark)

### Phase 10 — CI, meta, and law application
**Objective:** Bind everything with automated gates and human-signed law seals.

**Deliverables (PROPOSED):**
- CI jobs for: repo clean, schema registry, admission, determinism, secret scan, audit report generation
- law application receipts

### Phase 11 — Kaggle certification notebooks
**Objective:** Reproducible productization surfaces.

### Phase 12 — Final hardening checklist
**Objective:** Eliminate every reintroduction of drift/mutation/nondeterminism.

## Formal recontextualization: Wisdom Invariant

The following is a **PROPOSED** formalization (because no scanned file defines W/I/δ).

LaTeX:

\[
W(t) \ge I(t) + \delta
\]

With measurable definitions (see `kt.telemetry.wisdom_definitions.v1.json`):

- \( I(t) := \texttt{capability_score} \)
- \( S(t) := \min(\texttt{safety_score},\texttt{governance_integrity},\texttt{determinism_score}) \)
- \( W(t) := I(t) + S(t) \)
- \( \delta := \texttt{configured_safety_margin} \)

Therefore:

\[
W(t) \ge I(t) + \delta \iff S(t) \ge \delta
\]

## Limitations

- Drive crawl not performed (no manifest).
- Repo files (e.g., `KT_PROD_CLEANROOM/...`) were not available in this sandbox, so referenced paths are PROPOSED unless present in scanned text.
