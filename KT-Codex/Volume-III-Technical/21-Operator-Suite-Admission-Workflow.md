---
title: "Operator Workflow: Suite Admission"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Operator Workflow (Suite Admission)"
author_role: "Program Manager"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
This is the step-by-step operator procedure to admit a suite pack into the Suite Registry. The workflow is fail-closed and produces WORM evidence suitable for external audit.

## Inputs Required (Exact)
- `pack_root/` directory (offline)
- `pack_manifest.json`
- `hash_manifest.json` (or ability to compute it deterministically)
- `world_set.json` (or references + hashes)
- `validators.json` referencing validator contracts
- `thresholds.json`
- Operator signature material (if applicable; never paste into logs)

## Sacred vs Allowed Changes
### Sacred (Do Not Change)
- Sealed tag and pinned law bundle hash
- Existing admitted packs and registry history (append-only)
- Canonical schemas for admission artifacts
- Dual-use policy: do not embed gated payloads into canonical artifacts

### Allowed (Within this workflow)
- Create a new WORM run root under `KT_PROD_CLEANROOM/exports/_runs/**`
- Generate new admission artifacts for a new pack version
- Append new entries to a registry index file (if that file is governed and append-only by design)

## Steps (Fail-Closed)
1. Create a new WORM run root
   - Output: `<RUN_ROOT>/reports/run_meta.json`
2. Pins gate + clean worktree gate
   - Output: `<RUN_ROOT>/reports/pins_gate.json`
3. Schema validation
   - Output: `<RUN_ROOT>/reports/schema_validation.json`
4. Pack integrity recompute
   - Output: `<RUN_ROOT>/reports/pack_hashes.json`
5. Validator binding verification
   - Output: `<RUN_ROOT>/reports/validator_binding.json`
6. World-set binding verification
   - Output: `<RUN_ROOT>/reports/world_set_binding.json`
7. Threshold binding verification
   - Output: `<RUN_ROOT>/reports/threshold_binding.json`
8. Create Suite Admission Record
   - Output: `<RUN_ROOT>/admission/suite_admission_record.json`
9. Sign (operator) and submit for registry signature
   - Output: `<RUN_ROOT>/admission/operator_sig.json`
   - Output: `<RUN_ROOT>/admission/registry_sig.json`
10. Append registry index entry (governed)
   - Output: `<RUN_ROOT>/reports/registry_index_append_receipt.json`

## Evidence Produced
Minimum set:
- Admission record + sha256
- Pack manifest sha256 + pack root hash
- World set id + sha256
- Validator contracts referenced + hashes
- Thresholds id + sha256
- Transcripts + sweep summaries (PRE/POST)

## What To Do On Failure
- Do not patch around.
- Record the failure gate and reason code(s).
- Create a new run root after remediations; never overwrite.

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

