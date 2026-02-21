---
title: "Determinism Proof v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Determinism Proof (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Determinism proof makes evidence legally defensible. A run is admissible only if it can be replayed and produce identical artifacts and equivalent semantics under canonicalization.

## Two-Layer Proof Model
### Layer 1 — Artifact Determinism
Prove that output artifacts are byte-identical:
- Produce `sha256_manifest.json` for every run.
- Re-run in an independent directory with the same inputs and seeds.
- Manifests must match exactly; otherwise emit `RC_DET_ARTIFACT_HASH_DIVERGENCE_0301`.

### Layer 2 — Semantic Determinism
Prove that canonicalized semantics match even if non-semantic bytes differ:
- Apply `canonicalization_profile_id`.
- Emit semantic fingerprints per artifact type.
- Divergence triggers `RC_DET_SEMANTIC_CANONICALIZATION_DIVERGENCE_0302`.

## divergence_report.json (Minimal Repro Set)
If divergence is detected, write a minimal repro set:
- exact input hashes
- world set id + hash
- validator contracts + hashes
- thresholds + hashes
- seed + canonicalization profile id
- paths + hashes for the first diverging artifacts

## WORM Collision Handling
- Never overwrite.
- If a path collision occurs:
  - if identical bytes: record a `NOOP` receipt (hash-bound)
  - if different bytes: write `v2` artifacts and emit `RC_DET_WORM_COLLISION_0303`

## Admissibility Rule (Binding)
Certification requires two independent matching runs (Layer 1) plus successful semantic checks (Layer 2 where applicable).

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

