---
title: "Suite Admission Pipeline"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Suite Admission Pipeline (v1)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
The Suite Admission Pipeline is the deterministic, fail-closed procedure that produces admissible Suite Admission Records. It ensures no suite can run (for claims) unless it is admitted, signed, hashed, and referenced by immutable registry id.

## Admission Steps (Deterministic, Fail-Closed)
All steps must PASS; partial admission is forbidden.

1. **Preflight gate**
   - Verify constitutional pins and env lock where applicable.
   - Fail closed on missing pins, dirty tree, or forbidden env keys.

2. **Schema validation gate**
   - Validate pack manifest and all referenced artifacts against schemas.
   - Reject duplicate keys and invalid shapes.

3. **Pack integrity gate**
   - Compute sha256 per file and a root hash for the pack.
   - Verify `hash_manifest.json` matches the computed values.
   - Reject any mismatch as terminal.

4. **Validator binding gate**
   - Verify `validator_contract_ids[]` are present and allowlisted for the profile.
   - Verify `reason_code_taxonomy_ref` exists and matches expected taxonomy.

5. **World-set binding gate**
   - Verify the world set (embedded or referenced) is ordered and schema-valid.
   - Verify invariants ref is present and valid.

6. **Threshold binding gate**
   - Verify thresholds id and schema; bind to admission record.

7. **Signature gate**
   - Operator signature required (`operator_sig`).
   - Registry signature required (`registry_sig`).
   - If signatures missing, admission is invalid (terminal).

## WORM Evidence Locations
All pipeline evidence must be written under:
- `KT_PROD_CLEANROOM/exports/_runs/<ADMISSION_RUN_ID>/...`

No overwrites. If rerun is needed, create a new run root and reference the prior run by hash.

## How Admitted Suites Are Referenced by Future Runs
Every claim-bearing evaluation must include:
- `suite_id` and `suite_version`
- `suite_admission_record_sha256`
- measurement basis receipt with validator/world/threshold bindings

If any reference is missing or mismatched, admission is rejected and the run is inadmissible.

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

