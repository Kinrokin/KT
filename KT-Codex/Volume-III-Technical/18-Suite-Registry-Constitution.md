---
title: "Suite Registry Constitution"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Suite Registry (Constitution)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
The Suite Registry is the constitutional authority that determines which evaluation packs may execute and which evidence may influence fitness, promotion, certification, or dominance claims. Anything not admitted by the Registry is not admissible, even if it can be executed locally.

## Constitutional Statement (Binding)
- The Suite Registry is the sole authority that may admit evaluation packs as runnable assets.
- Implicit, ad-hoc, or local suite execution is forbidden for any claim-bearing evaluation.
- No suite, pack, or probe may influence evaluation, multiversal artifacts, conflict metabolism, fitness regions, or certification unless it is formally admitted and hash-bound by immutable registry id.

## Powers and Prohibitions
### The Registry MAY
- Admit a pack by issuing an admission record that binds hashes, validator contracts, world sets, and thresholds.
- Revoke a previously admitted suite via append-only revocation records.
- Publish an ordered registry index for auditor review.

### The Registry MUST NOT
- Delete or overwrite prior admission or revocation records.
- Allow execution of non-admitted packs to influence fitness or certification.
- Permit silent changes to admitted content (hash changes require new admission).

## Immutability Model
- Registry index is append-only (new entries only).
- Admission and revocation records are WORM evidence artifacts; prior records remain forever auditable.
- Any change to pack content, validator binding, world sets, thresholds, or canonicalization requires a new admission record.

## Revocation Rules (Fail-Closed)
- Revocation is a governed act that appends a revocation record.
- Once revoked, the suite is hard-blocked for future claim-bearing runs.
- Past runs remain historically auditable; they are not erased.

## Relationship to Other Constitutional Surfaces
- Fitness Regions: only Registry-admitted packs may produce fitness transitions.
- Conflict Metabolism: only Registry-admitted suites may emit admissible conflicts; conflict admission gate rejects unauthorized measurement basis.
- Multiversal Evaluation: world sets used for admissible results must be Registry-admitted (directly or by referenced world set ids).
- Determinism Proof: certification requires two independent matching runs against admitted suites.

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

