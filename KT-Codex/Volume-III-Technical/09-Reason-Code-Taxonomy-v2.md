---
title: "Reason Code Taxonomy v2"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Reason Codes (v2)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
Reason Codes are the machine-readable language KT uses to explain every rejection, failure, refusal, quarantine, or escalation without narrative override. A Reason Code is not an opinion; it is an admissibility artifact bound to evidence.

## Scope
- This taxonomy defines the canonical `RC_*` namespace for Titan / Red-Assault v2 program artifacts.
- It does not define validators; it defines the explanations validators must emit.
- It must be stable across time: codes are append-only; meanings do not drift.

## Non-Negotiable Rules
- Mandatory emission: every non-PASS verdict MUST emit at least 1 reason code.
- Terminality: any terminal reason code makes the result inadmissible and blocks promotion/persistence.
- Evidence binding: each emitted code MUST include `evidence_refs[]` to WORM artifacts (hash manifests, transcripts, validator logs, world-set ids, determinism fingerprints).
- No narrative override: a code cannot be waived by coherence, style, popularity, or operator preference; only governed law and explicit authorization paths may alter admissibility.

## Code Format
### Identifier
`RC_<DOMAIN>_<CATEGORY>_<NNNN>`
- `<DOMAIN>`: `GOV`, `VAL`, `SCHEMA`, `DET`, `MVE`, `SEC`, `EVAL`, `IO`
- `<CATEGORY>`: short stable tag
- `<NNNN>`: zero-padded integer

### Severity (Ordered)
| Severity | Meaning | Default effect |
|---|---|---|
| `INFO` | Informational; no gating effect | None |
| `WARN` | Degradation; requires attention | May affect scoring |
| `FAIL` | Failure; result invalid | Blocks that world/local result |
| `TERMINAL` | Constitutional violation | Reject at admission; blocks promotion/persistence |

### Required Fields Per Emission
Every reason code emission MUST include:
- `reason_code` (string)
- `severity` (enum)
- `terminal_state` (boolean)
- `category` (string; stable)
- `required_evidence_refs[]` (array of typed refs)
- `remediation_hint` (string; bounded guidance)

## Evidence Reference Types (Bounded)
Reason codes must point only to admissible evidence:
- `EVIDENCE_REF:FILE_SHA256:<path>#<sha256>`
- `EVIDENCE_REF:DIR_ROOT_HASH:<path>#<root_hash>`
- `EVIDENCE_REF:MANIFEST_SHA256:<path>#<sha256>`
- `EVIDENCE_REF:WORLD_SET_ID:<world_set_id>`
- `EVIDENCE_REF:VALIDATOR_CONTRACT_ID:<contract_id>`
- `EVIDENCE_REF:DETERMINISM_FINGERPRINT:<fingerprint>`

## Reason Code Catalog (v2)

### Governance / Admission Integrity
- RC_GOV_ADMISSION_MISSING_ARTIFACT_0001
  - category: admission_integrity
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: admission record path/hash, missing artifact pointer
  - remediation_hint: Provide the missing admissibility artifact (manifest, signatures, world set, validator bindings) under WORM and re-run admission.

- RC_GOV_ADMISSION_UNAUTHORIZED_SUITE_0002
  - category: admission_integrity
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: suite_id, registry index hash, admission record hash
  - remediation_hint: Admit the suite through the governed Suite Registry pipeline; do not execute ad-hoc suites.

- RC_GOV_MEASUREMENT_BASIS_UNAUTHORIZED_0003
  - category: measurement_basis
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: measurement basis receipt sha, contract ids, thresholds id, world set id
  - remediation_hint: Use only allowlisted validator contracts and thresholds; regenerate measurement basis receipt.

- RC_GOV_CONFLICT_ADMISSION_REJECTED_0004
  - category: conflict_admission_gate
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: conflict_event id, admission gate report
  - remediation_hint: Conflicts must be admissible: authorized measurement basis, registered axes, required counter-pressure present, admissible suite.

### Validator Contract / Capture Resistance
- RC_VAL_SELF_JUDGING_DETECTED_0101
  - category: capture_resistance
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: validator log, contract id, rule refs
  - remediation_hint: Replace self-grading with deterministic rule-based validators; update contract binding.

- RC_VAL_CONTRACT_VIOLATION_0102
  - category: validator_contract
  - severity: FAIL
  - terminal_state: false
  - required_evidence_refs: validator contract id, failing rule ref, canonicalization profile id
  - remediation_hint: Fix the validator implementation or canonicalization to conform to the contract; rerun with identical inputs.

- RC_VAL_CVDG_TRIGGERED_0103
  - category: cross_validator_disagreement_gate
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: validator outputs hashes, disagreement report
  - remediation_hint: Resolve validator divergence; do not average. If unresolved, escalate stalemate and block promotion.

- RC_VAL_UFV_VIOLATION_0104
  - category: utility_floor
  - severity: FAIL
  - terminal_state: false
  - required_evidence_refs: UFV report, thresholds id
  - remediation_hint: Improve the artifact to meet the utility floor in the relevant world; do not relax thresholds without governance.

### Schema / Structure
- RC_SCHEMA_INVALID_OUTPUT_0201
  - category: schema_violation
  - severity: FAIL
  - terminal_state: false
  - required_evidence_refs: schema id, validation error log, offending artifact hash
  - remediation_hint: Produce outputs that validate; do not patch validators to accept invalid shape.

- RC_SCHEMA_DUPLICATE_KEYS_0202
  - category: schema_violation
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: strict-json error record, offending file hash
  - remediation_hint: Regenerate JSON deterministically with duplicate-key rejection.

### Determinism
- RC_DET_ARTIFACT_HASH_DIVERGENCE_0301
  - category: artifact_determinism
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: run1 manifest hash, run2 manifest hash, divergence report
  - remediation_hint: Identify nondeterministic sources; require two independent matching runs before certification.

- RC_DET_SEMANTIC_CANONICALIZATION_DIVERGENCE_0302
  - category: semantic_determinism
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: canonicalization profile id, semantic fingerprints, diff report
  - remediation_hint: Fix canonicalization or output formatting; rerun until canonical forms match.

- RC_DET_WORM_COLLISION_0303
  - category: worm_semantics
  - severity: FAIL
  - terminal_state: false
  - required_evidence_refs: attempted path, existing file hash, new file hash
  - remediation_hint: Never overwrite. Write a `v2` artifact and include a collision receipt that explains the no-op or divergence.

### Multiversal Evaluation (MVE) / World Boundaries
- RC_MVE_WORLD_NOT_DECLARED_0401
  - category: world_explicitness
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: world id expected, world_set_id
  - remediation_hint: Declare and hash-bind the evaluation world; no world-less results are admissible.

- RC_MVE_CROSS_WORLD_AVERAGING_ATTEMPT_0402
  - category: forbidden_aggregation
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: offending aggregation artifact hash
  - remediation_hint: Remove averaging/merging. Preserve disagreement as artifacts.

- RC_MVE_TERMINAL_BOUNDARY_CONFLICT_0403
  - category: boundary_conflict
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: conflict_event id, invariants ref
  - remediation_hint: Reject at admission; escalate stalemate. No override permitted without explicit law citations.

### Security / Confidentiality
- RC_SEC_SECRET_LEAKAGE_SUSPECT_0501
  - category: confidentiality
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: leak detector report, redaction record
  - remediation_hint: Quarantine artifact; rotate secrets if applicable; rerun with sanitized inputs. Do not embed secrets in canonical surfaces.

- RC_SEC_PROMPT_INJECTION_PRESSURE_DETECTED_0502
  - category: injection_resistance
  - severity: FAIL
  - terminal_state: false
  - required_evidence_refs: case id, validator log, refusal integrity report
  - remediation_hint: Harden refusal integrity and boundary handling under pressure; re-evaluate under the same world set.

### IO / Environment Lock
- RC_IO_ENV_LOCK_VIOLATION_0601
  - category: env_lock
  - severity: TERMINAL
  - terminal_state: true
  - required_evidence_refs: env lock receipt, mismatch receipt hash
  - remediation_hint: Match the constitutional env lock; remove forbidden keys/prefixes and set required env vars exactly.

## Mandatory Emission Rules (Executable Summary)
- If a run is rejected at admission: emit at least one `RC_GOV_*` and one specific reason (`RC_SCHEMA_*`, `RC_MVE_*`, `RC_IO_*`, etc.).
- If determinism fails: emit `RC_DET_ARTIFACT_HASH_DIVERGENCE_0301` at minimum.
- If any terminal code is emitted: set `admissible=false` and `promotion_blocked=true`.

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

