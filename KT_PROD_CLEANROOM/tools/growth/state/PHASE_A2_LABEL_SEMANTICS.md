# KT PHASE A.2 — Label Semantics Repair (FAIL-CLOSED · Diagnostic)

This document defines the **Phase A.2** lane labels and the deterministic rules for producing a **new dataset** without modifying governance/router/crucibles.

## Safety & Scope

- This phase is **dataset + labeling only**.
- All epoch artifacts are **read-only** inputs.
- All outputs must be **additive**, **reversible**, and **auditable**.
- Any ambiguous/insufficient evidence case must be **skipped** (fail-closed).

## Labels (Phase A.2)

Phase A.2 introduces exactly one new lane label: `hold_coverage_lane`.

### `coverage_lane` (existing)
Semantic: proceed with coverage/exploration next.

### `reanchor_lane` (existing)
Semantic: re-anchor next (constraint damping) to prevent compounding failure.

### `stabilize_lane` (existing)
Semantic: hard stabilizer next (last resort).

### `hold_coverage_lane` (NEW, restraint lane)
Semantic: **risk is elevated / motion is high**, but **evidence indicates continued coverage is preferable to re-anchor**.

Operational note: in execution (shadow-only), `hold_coverage_lane` is treated as **non-authoritative** and would map to the same coverage plan as `coverage_lane` if you ever decide to actuate later. Phase A.2 does **not** grant authority.

## Deterministic Relabeling Rule (Option A)

We produce training rows where:

- Inputs come from **epoch i** (the most recently completed epoch).
- The *base* label is the lane that was actually executed in **epoch i+1** (the next epoch), inferred from `epoch_id` prefix.
- We refine a subset of `coverage_lane` into `hold_coverage_lane` using evidence-based criteria.

### Entropy-high (deterministic)
`entropy_high = (entropy_domains >= 0.80 and unique_domains >= 2)`

### Clean micro-step state (deterministic)
From `micro_steps.json` (per-crucible), aggregate:

- `forced_resolve_count = count(resolve_mode in {forced, partial, unresolved, refuse})`
- `low_coherence_count = count(coherence_bucket == LOW)`

`clean = (forced_resolve_count == 0 and low_coherence_count == 0)`

### “Recovery did not require re-anchor” (observed, not inferred)
We only assign `hold_coverage_lane` when all are true:

1. The next executed lane is `coverage_lane`.
2. The current epoch is `entropy_high` **and** `clean`.
3. The next epoch’s micro-step state is also `clean`.

If any evidence is missing, the row is **not relabeled**.

## Provenance Requirements (per row)

Every Phase A.2 dataset row must include:

- `epoch_id` (source epoch)
- `next_epoch_id` (observed next epoch)
- `phaseA_label` (the next executed lane label before refinement)
- `phaseA2_label` (final label after applying restraint rule)
- `relabel_reason` (explicit string; `null` if unchanged)
- All structural signals used to justify the label

## Outputs

The builder script must emit:

- `kt_phaseA2_dataset.jsonl` (new dataset; never overwrite Phase A)
- `kt_phaseA2_label_map.json` (label mapping used for training)
- `kt_phaseA2_build_report.json` (counts, skips, and fail-closed reasons)

