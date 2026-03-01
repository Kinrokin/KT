---
title: "Sector Overlays v2.0 (Authoring Guides)"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Sector Overlays (v2.0)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Sector overlays extend the Core Pressure Pack with domain-specific constraints, invariants, and thresholds without embedding sensitive payloads. Overlays are additive and must remain capture-resistant and deterministic.

## Directory Structure (per overlay)
`KT_<SECTOR>_OVERLAY_v2.0/`
- `overlay_manifest.json`
- `cases.jsonl` (safe templates only)
- `world_set_ref.json`
- `validators_ref.json`
- `thresholds_ref.json`
- `hash_manifest.json`
- `README.md`

## Overlay Coverage Accounting
- Overlays do not replace core coverage; they add constraints and world specializations.
- Certification profiles must declare: `core_pack_id` + `overlay_pack_ids[]`.
- Coverage reports must separate: core vs overlay.

## Finance Overlay v2.0
### Break hypotheses (examples, safe)
- Misstated risk claims under pressure
- Inconsistent disclosure requirements across jurisdictions
- Refusal integrity for prohibited financial advice (world-dependent)

### Invariants (examples)
- No fabricated guarantees
- Must emit reason codes for any refusal or gate failure

## Healthcare Overlay v2.0
### Break hypotheses (examples, safe)
- World-specific prohibition on medical advice vs general education
- Stronger ambiguity rejection in strict health worlds

### Invariants (examples)
- Precautionary framing where required by world

## Insurance Overlay v2.0
### Break hypotheses (examples, safe)
- Policy interpretation ambiguity handling
- Refusal integrity for coverage determinations without sufficient evidence

## Security/Compliance Overlay v2.0
### Break hypotheses (examples, safe)
- Confidentiality boundary enforcement
- Prompt injection resistance under administrative pressure (safe-only)

## Public Sector / Chain-of-Custody Overlay v2.0
### Break hypotheses (examples, safe)
- Evidence integrity and chain-of-custody logging
- Non-repudiation and WORM admissibility requirements

## Safety Rule (Canonical)
No overlay may embed dual-use payloads. Use:
- abstract templates
- category tags
- hash references for gated content

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

