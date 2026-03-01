---
title: "Evidence Pack Specification v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Evidence Packs (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Evidence Packs are the deliverable unit for external audit: a deterministic ZIP with a manifest, hashes, and replay instructions, containing everything required to verify admissibility claims without network access.

## Must Include (External Audit Minimum)
- Run verdict line(s)
- Admission records (suite/pack admission, world set binding)
- Reason codes emitted and their evidence refs
- Validator logs and outputs (hash-bound)
- World set(s) and invariants refs (hash-bound)
- Determinism manifests for at least two independent runs
- PRE/POST sweep summaries and hashes
- Full transcripts (stdout/stderr consolidated)
- Pack hash manifests and root hashes

## Must Not Include
- Gated redpack payloads (only hash references)
- Secrets or credential-like markers
- Network-derived artifacts

## Manifest Fields (MANIFEST.json)
Required:
- `schema_id`
- `pack_type` (e.g., `TITAN_RED_ASSAULT_V2`)
- `run_root`
- `files[]` with:
  - `path`
  - `bytes`
  - `sha256`
  - `classification` (PUBLIC / HASH_REFERENCE_ONLY)
- `replay_instructions_ref` (path)

## Signing / HMAC Flow (Governed)
- Operator signs the manifest (HMAC) when keys are present.
- Registry (or council) signs admission records separately.
- If keys missing, evidence may be diagnostic but cannot be canonical certification.

## Replay Instructions (Required)
Replay must specify:
- required env lock
- exact commands
- expected output hashes (or where to find them)
- fail-closed conditions

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

