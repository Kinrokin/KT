---
title: "Cross-Axis Conflict Metabolism"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Chapter 7"
author_role: "KT Operator Automation Agent"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs:
  - "SRC:KT:LAW_BUNDLE_FL3"
  - "SRC:KT:SUITE_REGISTRY_FL3"
  - "SRC:NEEDS_VERIFICATION"
status: "draft"
---

## Purpose
This chapter defines **cross-axis conflict metabolism** as a governed, admissible, non-silent process. It makes disagreement, override, and dominance detectable and auditable. It blocks promotion and blocks activation of any learning loop until conflicts are resolved under governance.

## Definitions (Normative)
- **Axis**: A named evaluation dimension (e.g., Safety, Compliance, Determinism, Performance, Cost). Identified by stable `axis_id` strings.
- **Conflict**: A measurable disagreement between axes that exceeds a threshold under a declared measurement basis.
- **Measurement Basis**: The declared contract for how a claim is measured (suite id, metric ids, scoring direction, thresholds, and evidence rules). Identified by `measurement_basis_id`.
- **Counter Pressure**: A suite, probe, or evaluation intended to stress the disputed claim(s). Referenced only by hash + path (no raw payload requirement).
- **Determinism Fingerprint**: A 64-hex identifier binding the record to its evaluation context (pins, seeds, suite set, evaluator surface). Stored as `determinism_fingerprint`.
- **Law Citation**: A structured reference to an authoritative governance surface (identified by bundle hash and clause reference). Stored as `law_citations[]`.

## Artifacts (First-Class, Admissible)
All artifacts below are evidence objects and must be written WORM.

### ConflictEvent
A `ConflictEvent` records that two or more axes disagree above threshold and must not resolve silently.

Mandatory fields (minimum):
- `axes` (aka axis_ids)
- `trigger_context`
- `suite_id`
- `measurement_basis_id`
- `measurements`
- `disputed_claims`
- `counter_pressure_refs`
- `timestamp`
- `determinism_fingerprint`

Canonical schema reference:
- `KT-Codex/schemas/conflict_event.schema.json`

### OverrideDecision
An override is an explicit decision that selects a winning axis and blocks the losing axis claims for a defined decision scope. Overrides are never implicit.

Mandatory fields (minimum):
- `winning_axis`
- `override_reason_code` (bounded enum)
- `law_citations[]` (bundle hash + clause reference)
- `determinism_fingerprint`

Hard rule:
- If a conflict is resolved, it must be resolved by an explicit override decision (or the downstream action must be blocked).

## Logging Rules (Fail-Closed)
### When a conflict must be logged
A conflict must be logged when any of the following is true:
- Two or more axes produce contradictory `PASS/FAIL/INCONCLUSIVE` states under the same `measurement_basis_id`.
- The absolute delta between axis scores exceeds the threshold declared by the measurement basis.
- Any disputed claim is declared `severity=critical`.

### When override is mandatory
An override is mandatory when:
- The system would otherwise proceed to a promotion decision, or proceed to activate a learning loop, and
- The conflict impacts a gating axis (e.g., Safety, Compliance, Determinism), and
- The evidence set is complete and deterministic for the governing measurement basis.

### When override is prohibited
Override is prohibited when:
- The measurement basis is invalid, missing, or lacks required evidence refs (block instead).
- Determinism is not established for the disputed measurement set (block instead).
- `law_citations[]` are absent or do not bind to the current law bundle hash (block instead).

## Prohibitions (Non-Negotiable)
- **No silent averaging**: You may not average conflicting metrics or “blend” scores to avoid producing a conflict record.
- **No implicit precedence**: “Axis X always wins” is inadmissible unless that precedence is cited and recorded for the decision scope.
- **No conflict erasure**: A conflict record may not be deleted or overwritten; supersession must be a new record referencing the prior one by hash.

## Conflict Metabolism Workflow (Operator-Grade)
1. **Detect**: evaluator identifies disagreement above threshold and opens a `ConflictEvent` with `resolution_status=OPEN`.
2. **Freeze**: any promotion/learning action is blocked until the conflict is resolved.
3. **Measure**: compute measurements under the declared measurement basis; write measurement evidence WORM.
4. **Counter-pressure**: run declared counter-pressure suites/probes; reference evidence by sha256.
5. **Decide or Block**:
   - If resolvable: emit `OverrideDecision`, cite law, bind determinism fingerprint, set `resolution_status=RESOLVED_WITH_OVERRIDE`.
   - If not resolvable: set `resolution_status=BLOCKED_PENDING_EVIDENCE` and block all downstream actions.
6. **Dominance audit**: compute dominance signals (override win frequency per axis) and require governance review if dominance thresholds are exceeded.

## Admissible vs Inadmissible Handling (Examples)
### Admissible
- Conflict logged with structured claim refs and measurement evidence.
- Promotion blocked until an override decision is issued with bounded reason code, `law_citations[]`, and `determinism_fingerprint`.
- Counter-pressure evidence referenced by sha256 (not by mutable path alone).

### Inadmissible
- “We averaged the scores and proceeded.”
- “The conflict resolved itself; no record was produced.”
- “Safety won because it usually does” (no citation, no bounded reason code, no fingerprint).

## Promotion Gate
Hard rule:
- **Unresolved conflict blocks promotion**. If any promotion-affecting `ConflictEvent` is `OPEN` or `BLOCKED_PENDING_EVIDENCE`, promotion and learning activation must fail-closed.

## Integration Hooks (Non-Executable)
This chapter defines governance artifacts and schemas. Activation requires a separate governed work order to:
- emit ConflictEvents from evaluator and tournament surfaces,
- store conflict/override artifacts under WORM run roots,
- enforce promotion/learning blocks based on conflict status.

