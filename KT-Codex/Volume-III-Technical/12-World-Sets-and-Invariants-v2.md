---
title: "World Sets and Invariants v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "World Sets & Invariants (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
World Sets define the authorized evaluation constitutions KT must execute. Invariants define boundaries that must not change across worlds. Together, they prevent silent dominance, forbidden averaging, and narrative collapse.

## World Set v2 (Definition)
A World Set is a first-class artifact:
- deterministic id and version
- ordered worlds list (arrays only)
- invariants reference
- canonicalization profile id

World ordering is binding: it affects determinism fingerprints and evidence manifests.

## Invariants (Non-Negotiable)
Invariants are boundaries that must hold across all worlds, even when worlds disagree on normative outcomes.

### Required invariant categories (v2 minimum)
- confidentiality (no secret leakage)
- governance integrity (fail-closed, reason codes)
- determinism (artifact + semantic)
- multiversal integrity (conflict preservation; no cross-world averaging)

### Terminal mapping
Any invariant violation triggers a terminal reason code. Minimum mapping:
- confidentiality => `RC_SEC_SECRET_LEAKAGE_SUSPECT_0501`
- forbidden averaging => `RC_MVE_CROSS_WORLD_AVERAGING_ATTEMPT_0402`
- determinism divergence => `RC_DET_ARTIFACT_HASH_DIVERGENCE_0301`

## Multiversal Conflict Emission Requirements
- Any world-to-world disagreement above threshold MUST emit a cross-world conflict artifact.
- Conflicts cannot be silently resolved.
- Conflicts may be escalated to stalemate; collapse is forbidden.

### Terminal boundary conflicts
If a conflict violates an invariant boundary, reject at admission:
- emit `RC_MVE_TERMINAL_BOUNDARY_CONFLICT_0403`
- set `admissible=false`
- set `promotion_blocked=true`

## World Definition Compatibility
World Definitions are defined by `KT-Codex/schemas/world_definition.schema.json`. World Sets may:
- embed world objects (portable), or
- reference worlds by hash/id (catalog mode)

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

