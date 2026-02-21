---
title: "Auditor Workflow: Suite Registry Review"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Auditor Workflow (Suite Registry)"
author_role: "Governance & Compliance Lead"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
This workflow explains how an auditor verifies that a suite was properly admitted, signed, and hash-bound, and how to trace an evaluation run back to the admitted suite and its measurement basis.

## Auditor Inputs
- Registry index (ordered) + its sha256
- Suite Admission Record + its sha256
- Pack hash manifest and root hash
- World set(s) and invariants refs
- Validator contract ids and schema docs
- Run evidence pack (verdicts, transcripts, sweeps, manifests)

## Verification Steps (Fail-Closed)
1. Verify sealed anchors (tag -> commit) and pinned law bundle hash.
2. Verify registry index integrity:
   - ordered list
   - each entry references an admission record hash
   - no deletions/rewrites (append-only evidence)
3. Verify Suite Admission Record:
   - schema-valid and duplicate-key free
   - `pack_sha256` and `manifest_sha256` present
   - validator contract ids and world set ids present
   - operator and registry signatures present
4. Verify pack integrity:
   - recompute sha256 per file; compare to hash_manifest.json
   - recompute root hash; compare to admission record
5. Trace run to admitted suite:
   - locate measurement basis receipt in the run
   - confirm it references the admitted suite id/version and contract bindings
6. Determinism proof:
   - require two matching manifests for certification-grade claims

## Red Flags (Mandatory Escalations)
- Missing admission record or missing signatures
- Pack hashes do not match recompute
- World set not declared or ordering lost
- Any terminal reason code present but admission/certification still claimed
- Evidence indicates cross-world averaging or silent dominance
- Any sign of secrets in canonical artifacts (hash-only policy violated)

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

