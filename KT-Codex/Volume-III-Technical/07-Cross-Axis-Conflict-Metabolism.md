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
- `admission`
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

## Conflict Admission Gate (Governed)
Conflict admission is governed. Conflict is rejected at admission if any of the following is true:
- Measurement basis is unauthorized.
- Counter-pressure is missing.
- Any axis involved is not registered.
- Suite is not admissible.

Admission outputs (non-silent):
- `admission_status=ADMITTED` (conflict may proceed), or
- `admission_status=REJECTED` with one or more bounded `rejection_reason_codes`.

Fail-closed rule:
- If admission is rejected, the system must record the rejection (WORM) and must not treat the rejected conflict as a promotion-valid gating artifact.
- Any attempt to use an unauthorized measurement basis for downstream decisions must fail-closed and escalate to governance.

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

### Terminal: Escalated Stalemate (Law-Preserving Halt)
Some conflicts are non-resolvable under law:
- No override is allowed.
- No synthesis is allowed.
- The system must refuse or escalate while preserving law and evidence.

In this state, the conflict must be recorded as a terminal outcome:
- `resolution_status=ESCALATED_STALEMATE`
- `stalemate_reason_code` (bounded enum)
- `law_citations[]` binding the non-resolvability

## Prohibitions (Non-Negotiable)
- **No silent averaging**: You may not average conflicting metrics or “blend” scores to avoid producing a conflict record.
- **No implicit precedence**: “Axis X always wins” is inadmissible unless that precedence is cited and recorded for the decision scope.
- **No conflict erasure**: A conflict record may not be deleted or overwritten; supersession must be a new record referencing the prior one by hash.
- **No narrative override**: Overrides may not be justified by user preference, coherence, eloquence, majority-axis agreement, or “seems reasonable.” Only law, evidence, and counter-pressure survival are admissible bases.

## Conflict Metabolism Workflow (Operator-Grade)
1. **Detect**: evaluator identifies disagreement above threshold.
2. **Admit or Reject**: run the Conflict Admission Gate.
   - If rejected: record rejection WORM and stop.
   - If admitted: open a `ConflictEvent` with `resolution_status=OPEN`.
3. **Freeze**: any promotion/learning action is blocked until the conflict is resolved or escalated.
4. **Measure**: compute measurements under the declared measurement basis; write measurement evidence WORM.
5. **Counter-pressure**: run declared counter-pressure suites/probes; reference evidence by sha256.
6. **Decide, Block, or Escalate**:
   - If resolvable: emit `OverrideDecision`, cite law, bind determinism fingerprint, set `resolution_status=RESOLVED_WITH_OVERRIDE`.
   - If evidence missing: set `resolution_status=BLOCKED_PENDING_EVIDENCE` and block all downstream actions.
   - If non-resolvable under law: set `resolution_status=ESCALATED_STALEMATE` and escalate.
7. **Dominance audit**: compute dominance signals (override win frequency per axis) and require governance review if dominance thresholds are exceeded.

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
- **Unresolved conflict blocks promotion**. If any promotion-affecting `ConflictEvent` is `OPEN`, `BLOCKED_PENDING_EVIDENCE`, or `ESCALATED_STALEMATE`, promotion and learning activation must fail-closed.

## Integration Hooks (Non-Executable)
This chapter defines governance artifacts and schemas. Activation requires a separate governed work order to:
- emit ConflictEvents from evaluator and tournament surfaces,
- store conflict/override artifacts under WORM run roots,
- enforce promotion/learning blocks based on conflict status.
