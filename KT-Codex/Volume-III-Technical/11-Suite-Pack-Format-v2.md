---
title: "Suite Pack Format v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Suite Packs (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Suite Packs are the only admissible container for evaluation cases, validators, thresholds, transforms, and replay contracts. Packs are designed to be jurisdiction-grade: deterministic, hashed, and governed.

## Publish Classes (Constitutional)
Every pack and pack component MUST declare one publish class:
- `CANONICAL_PUBLIC` — safe to store in canonical repo surfaces
- `HASH_REFERENCE_ONLY` — canonical repo stores only hashes + labels; payload lives outside canonical surfaces
- `GATED_REDPACK` — payload is gated and must never appear in canonical artifacts; only hash refs appear

## Pack Directory Structure (v2)
`<pack_root>/`
- `pack_manifest.json` (required)
- `cases.jsonl` (required for public packs; for gated packs: may be replaced by hash refs)
- `world_set.json` or `world_set_ref.json` (required)
- `validators.json` (required; references validator contracts)
- `thresholds.json` (required)
- `transforms/` (optional; deterministic transform specs only)
- `replay/` (required: seeds, canonicalization profile ids, run recipe)
- `hash_manifest.json` (required; sha256 per file)
- `README.md` (required; operator-grade, offline)

## pack_manifest.json (Required Fields)
- `schema_id`
- `pack_id`
- `pack_version`
- `publish_class`
- `world_set_id`
- `validator_contract_ids[]`
- `thresholds_id`
- `cases_manifest_sha256` (sha256 of cases.jsonl OR hash-ref manifest)
- `hash_manifest_root_hash` (root hash of hash_manifest.json)
- `invariants_ref` (hash ref)
- `reason_code_taxonomy_ref` (hash ref)

## Pack Admission Record (PAR)
A Pack Admission Record is required before execution (see Suite Registry pipeline). It must include:
- `pack_id`, `pack_version`
- `pack_sha256` (root hash)
- `manifest_sha256` (pack_manifest.json)
- `validator_contract_ids[]`, `world_set_ids[]`
- `operator_sig` and `registry_sig` (HMAC or equivalent governed signature)
- `timestamp_utc`

If PAR missing: reject with `RC_GOV_ADMISSION_MISSING_ARTIFACT_0001`.

## Coverage Algebra Tags
Each case MUST include a stable tag set:
- `channel`: text, tool, file, policy, memory
- `constraint`: refusal, disclosure, integrity, determinism, governance
- `pressure`: urgency, authority, ambiguity, counterpressure, multiversal_shift
- `evasion`: obfuscation, formatting, partial_truth
- `impact`: safety, legal, financial, reputational

### Minimum coverage targets (program defaults)
- Each `channel` must have >= 10 cases per pack (unless pack is an overlay).
- `pressure=counterpressure` must exist in every admitted red-assault program pack.
- `pressure=multiversal_shift` must exist in every MVE-enabled pack.

## Safety / Dual-Use Rule
Canonical pack artifacts must not contain sensitive payloads. High-risk probes are represented as:
- stable `case_id`
- category tags
- bounded safe description
- optional `[REDACTED_PAYLOAD_HASH:<sha256>]` placeholder

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

