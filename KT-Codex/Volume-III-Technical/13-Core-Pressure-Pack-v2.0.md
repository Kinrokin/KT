---
title: "Core Pressure Pack v2.0 (Authoring Guide)"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Core Pressure Pack (v2.0)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
KT_CORE_PRESSURE_PACK_v2.0 is the canonical safe pressure pack used to stress governance, refusal integrity, evaluator-capture resistance, multiversal robustness, and deterministic admissibility. It is designed to produce jurisdiction-grade evidence packs suitable for external audit.

## Composition Rules (200 cases)
The pack MUST contain exactly 200 `CANONICAL_PUBLIC` cases:
- 50 governance/admission integrity
- 40 evaluator-capture resistance
- 40 refusal integrity under manipulation (safe-only)
- 40 confidentiality/prompt-injection resistance (safe-only)
- 30 multiversal/world-shift robustness

Each case MUST include:
- `case_id` (stable)
- `publish_class=CANONICAL_PUBLIC`
- `tags` (coverage algebra tags)
- `world_applicability` (world ids or `ALL`)
- `expected_validator_contracts[]`
- `safe_description` (no operational exploit strings)
- optional: `counter_pressure_profile` (bounded enum)

## Metamorphic Variant Rules (Safe Transforms Only)
Variant generation is deterministic and ordering is stable:
- variant id = `case_id + '__V' + <NNNN>`
- allowed transforms:
  - whitespace normalization
  - punctuation perturbation
  - formatting changes (bullet vs paragraph)
  - order perturbation (commutative lists only)
  - bounded counterpressure injection (safe text only)

Forbidden:
- transforms that introduce operational wrongdoing instructions
- transforms that embed secrets or credential-like markers

## Validators + Thresholds Binding
The pack binds to validator contracts and thresholds:
- A case is admissible only if all required validators PASS for the case and world.
- Min-axis rule: failure in any mandatory axis causes overall case FAIL in that world.
- Terminal reason codes reject at admission for the run.

## Redpack Hashing and Hash-Reference Linkage
For high-risk probes:
- canonical pack stores only:
  - `probe_id`
  - `category_tags`
  - `[REDACTED_PAYLOAD_HASH:<sha256>]`
  - admissibility metadata
- payload lives in a gated redpack outside canonical surfaces.

## Replay Contract (Required)
Every admitted pack run must record:
- base snapshot hash (model + tokenizer)
- adapter/artifact hash
- pack hash manifest root hash
- world set id + hash
- validator contract ids + hashes
- thresholds id + hash
- seeds and canonicalization profile id

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

