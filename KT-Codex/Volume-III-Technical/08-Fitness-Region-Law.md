---
title: "Fitness Regions A/B/C (Constitutional Binding)"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Chapter 8"
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
This chapter binds **Fitness Regions** as non-optional selection pressure. Fitness Regions determine what actions are allowed on an adapter or candidate. Region rules are non-discretionary and must be enforced before any learning activation is allowed.

## Fitness Regions (Binding Definitions)
Fitness Regions are categorical and law-backed.

### Region A — Eligible
Region A indicates the candidate is admissible for promotion consideration.

Minimum admissibility criteria (must be evidenced):
- Required suites pass under the governing suite registry set.
- Determinism requirements are satisfied for the governing evaluation surfaces.
- No open cross-axis conflicts that impact promotion eligibility.

### Region B — Restricted
Region B indicates the candidate may be evaluated and iterated but is not eligible for promotion.

Triggers (examples; must be evidenced):
- Non-critical regressions or incomplete evidence bundles.
- Discrepancies requiring additional counter-pressure runs.
- Conflicts present that do not yet meet quarantine criteria but do block promotion.

### Region C — Quarantine
Region C indicates the candidate is prohibited from promotion and must be quarantined or demoted.

Mandatory triggers (must be evidenced):
- Critical safety or compliance failures.
- Determinism failure in required governing surfaces.
- Evidence integrity failure (missing required evidence or non-WORM evidence for required gates).

## Non-Discretionary Rules (Law Binding)
- **Promotion is forbidden without Region A eligibility.**
- **Demotion/quarantine is mandatory on Region C conditions.**
- **Discretionary override of region rules is forbidden.** Any attempt to bypass region rules must fail-closed.

## Region Lock (Anti-Self-Promotion)
Region Lock is mandatory:
- An adapter/candidate cannot self-promote.
- An adapter/candidate cannot self-evaluate for promotion eligibility.
- Region transitions must be authored by an independent governed surface and must cite law and evidence.

## Region Transitions (Governed Acts)
All region transitions must be represented by a Fitness Transition artifact:
- Required fields include `from_region`, `to_region`, `evidence_refs`, `law_citations`, and `conflict_refs`.
- Silent transitions are rejected: a region change without an admissible transition artifact is invalid.

Canonical schema reference:
- `KT-Codex/schemas/fitness_transition.schema.json`

## Interaction With Cross-Axis Conflict Outcomes
Fitness regions and conflict metabolism are coupled:
- Any promotion-affecting unresolved conflict forces Region A ineligibility (at most Region B).
- Any unresolved conflict involving critical safety/compliance disputed claims forces Region C until resolved with explicit override and evidence.

## Allowed Actions by Region (Table)
| Region | Evaluate (non-promo) | Counter-pressure runs | Propose changes | Promote | Deploy | Activate learning |
| --- | --- | --- | --- | --- | --- | --- |
| A | Allowed | Allowed | Allowed | Allowed (only if no open conflicts) | Allowed (governed) | Prohibited (separate work order) |
| B | Allowed | Allowed | Allowed | Forbidden | Forbidden | Prohibited |
| C | Allowed (diagnostic only) | Allowed (mandatory if needed) | Allowed (quarantine remediation only) | Forbidden | Forbidden | Prohibited |

## Integration Hooks (Non-Executable)
This chapter defines binding policy and schema. Activation requires a separate governed work order to:
- emit Fitness Transition artifacts from the promotion pipeline,
- enforce Region Lock at evaluation and promotion surfaces,
- couple conflict outcomes to region eligibility.

