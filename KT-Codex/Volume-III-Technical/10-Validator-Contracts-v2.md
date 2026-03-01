---
title: "Validator Contracts v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Validator Contracts (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Validator Contracts define how KT measures, gates, and admits evidence without evaluator capture. A validator is a deterministic contract that takes bounded inputs and emits bounded outputs, reason codes, and hash-bound receipts.

## Design Goals
- Determinism: identical inputs produce byte-identical outputs after canonicalization.
- Capture resistance: validators must not be model-based self-judges for admissibility.
- Auditability: every decision is traceable to a contract id and WORM evidence.
- Fail-closed: ambiguity, missing artifacts, schema drift, or contract mismatch causes rejection.

## Contract Model (v2)
A validator contract is a stable specification:
- `contract_id` (stable identifier)
- `version` (append-only evolution; old versions remain valid for replay)
- `canonicalization_profile_id` (stable reference)
- `inputs[]` (schema-bound, bounded)
- `outputs` (schema-bound, bounded)
- `deterministic_rules[]` (enumerated; no free-text scoring)
- `reason_codes_emitted[]` (subset of `RC_*`)
- `hash_basis.includes[]` (what artifacts/hashes bind this measurement)

## Forbidden: Self-Judging for Admissibility
Validators MUST NOT:
- Use the evaluated model/adapter to grade itself for admission.
- Use external network calls.
- Use unconstrained free text as the grading basis.

Allowed:
- Rule-based checks over canonicalized artifacts.
- Deterministic parsers and finite-state checks.
- Multi-validator ladders where each validator is deterministic and contract-bound.

## Measurement Basis Receipt (MBR) (Required)
Every admissible measurement MUST emit a Measurement Basis Receipt as WORM evidence.

### Required fields
- `suite_id`
- `validator_contract_id`
- `thresholds_id`
- `world_set_id`
- `canonicalization_profile_id`
- `determinism_fingerprint.inputs` (hashes of: pack manifest, cases, world set, validator contracts, thresholds)

### MBR rule
If any required MBR field is missing or mismatched, admission MUST fail with terminal governance reason codes (e.g., `RC_GOV_MEASUREMENT_BASIS_UNAUTHORIZED_0003`).

## Canonicalization Profiles
Canonicalization profiles define stable rules for:
- JSON canonicalization (ordering, whitespace, unicode normalization)
- Text normalization (line endings, trimming)
- Numeric rendering (rounding rules where applicable)

Profiles are referenced by id; if a profile changes, the id must change.

## UFV and CVDG (First-Class Validators)
### UFV — Utility Floor Validator
Plain-English: verifies the artifact clears a minimum usable bar in the relevant world(s) without cheating or evasion.

Contract obligations:
- Inputs: canonicalized outputs, world id, thresholds id
- Outputs: `verdict`, `score_components`, `reason_codes[]`
- Emits: `RC_VAL_UFV_VIOLATION_0104` on failure

### CVDG — Cross-Validator Disagreement Gate
Plain-English: blocks admissibility if independent validators disagree beyond a threshold.

Contract obligations:
- Inputs: hash-referenced validator outputs
- Outputs: `disagreement_detected`, `disagreement_basis`, `reason_codes[]`
- Emits: `RC_VAL_CVDG_TRIGGERED_0103` when triggered (terminal)

## Deterministic Validator Ladder (Recommended)
1. Schema validation (strict JSON; duplicate-key reject)
2. Canonicalization
3. UFV checks (world-local)
4. Boundary/invariant checks (multiversal)
5. CVDG gate
6. Admission verdict + receipts

## Output Shape (Minimum)
Each validator MUST emit a JSON object:
- `schema_id`
- `contract_id`
- `inputs_sha256[]` (hash references)
- `outputs_sha256[]`
- `verdict` (PASS/FAIL/TERMINAL)
- `reason_codes[]`
- `timestamp_utc`

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

