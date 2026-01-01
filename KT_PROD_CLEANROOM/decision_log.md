# W4 Decision Log (Convenience Mirror)

Canonical W4 decision log:
- `KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/decision_log.md`

This file records high-level decisions for quick access. The canonical audit log remains under `02_PROVENANCE_LEDGER/`.

## 2025-12-27T11:15:14Z — C001 sealed as substrate

Decision:
- C001 sealed as substrate (immutable without reauthorization)

Pointers:
- C001 plan: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C001_PLAN.md`
- C001 verification (lab): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C001_VERIFICATION.md`
- C001 verification (V2 docs): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C001_VERIFICATION.md`
- V2 release manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`
- C001 substrate seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C001_INVARIANTS_SUBSTRATE_SEAL.md`

## 2025-12-27T12:32:42Z - C002 sealed as substrate

Decision:
- C002 Schemas as Bounded Contracts implemented + sealed as substrate (authoritative schema perimeter)

Pointers:
- C002 plan: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C002_PLAN.md`
- C002 verification (lab): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C002_VERIFICATION.md`
- C002 verification (V2 docs): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C002_VERIFICATION.md`
- Schema registry doc: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_REGISTRY.md`
- Schema version lock doc: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_VERSION_LOCK.md`
- V2 release manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`
- C002 substrate seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C002_SCHEMAS_SUBSTRATE_SEAL.md`
- S3 guard report: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md`

## 2025-12-27T13:33:11Z - C008 sealed as substrate

Decision:
- C008 State Vault append-only discipline implemented + sealed as substrate (sole persistence authority)

Pointers:
- C008 plan: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C008_PLAN.md`
- C008 S1 diff rationale: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_DIFF_RATIONALE_C008.md`
- C008 verification (lab): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C008_VERIFICATION.md`
- C008 verification (V2 docs): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md`
- C008 substrate seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C008_STATE_VAULT_SUBSTRATE_SEAL.md`
- V2 release manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`
- S3 guard report (C008): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md`

## 2025-12-28T04:18:55Z - C005 sealed as substrate (manifest alignment)

Decision:
- C005 Governance Event Hashing Logger implemented + sealed as substrate (hash-only governance audit via C008; no raw content)

Pointers:
- C005 plan: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C005_PLAN.md`
- C005 verification (lab): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C005_VERIFICATION.md`
- C005 verification (V2 docs): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C005_VERIFICATION.md`
- C005 substrate seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C005_GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL.md`
- V2 release manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`
- S3 guard report (C005): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C005.md`

Notes:
- Manifest alignment: appended missing C005 seal entry to `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl` (no runtime code changes).

## 2025-12-28T06:51:26Z - C010 implemented + sealed as substrate

Decision:
- C010 Runtime Registry + Substrate Spine + Import-Time Sovereignty implemented and sealed to close V2 execution topology (provider-free, no-network dry-run proof).

Pointers:
- C010 plan: `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_C010_PLAN.md`
- Runtime registry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Canonical entry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py`
- Canonical spine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- Import Truth runtime guard: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/import_truth_guard.py`
- C010 verification (lab): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/05_VERIFICATION/W4_5_C010_VERIFICATION.md`
- C010 verification (V2 docs): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C010_VERIFICATION.md`
- C010 proof artifacts:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/verification/C010_EXECUTION_PATH_PROOF.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/verification/C010_IMPORT_TRUTH_RUNTIME_PROOF.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/verification/C010_NO_NETWORK_DRY_RUN_PROOF.md`
- C010 substrate seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C010_RUNTIME_TOPOLOGY_SUBSTRATE_SEAL.md`
- S3 guard report (C010): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C010.md`
- V2 release manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

## 2025-12-28T07:26:11Z - G9 V2 Freeze (Gold Master artifacts)

Decision:
- Generated V2 Gold Master freeze artifacts (full-tree manifest + stability proof + seal + verification index + immutability attestation).

Pointers:
- Full-tree manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_FULL_RELEASE_MANIFEST.jsonl` (self-excluding)
- Stability proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_MANIFEST_STABILITY_PROOF.md`
- Seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/KT_TEMPLE_V2_SEAL.md`
- Verification bundle index: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_FINAL_VERIFICATION_INDEX.md`
- Immutability attestation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_IMMUTABILITY_ATTESTATION.md`
- Concept-scoped manifest (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

Notes:
- `docs/V2_FULL_RELEASE_MANIFEST.jsonl` intentionally excludes itself from enumeration; this avoids self-referential ambiguity and is explicitly documented.

## 2025-12-28T07:47:03Z - C011 implemented (Paradox Injection Engine)

Decision:
- Implemented C011 Paradox Injection as a governed, bounded, schema-validated runtime capability (no providers, no network, no raw persistence).

Pointers:
- Paradox implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/`
- Runtime registry (allowlist + organ mapping + matrix): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/verification/C011_EXECUTION_PATH_PROOF.md`
- C011 verification: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C011_VERIFICATION.md`
- S3 guard report (C011): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C011.md`
- C011 concept entries (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

## 2025-12-28T08:47:55Z - C012 implemented (Temporal Fork & Deterministic Replay Engine)

Decision:
- Implemented C012 Temporal Fork & Deterministic Replay as a governed, metadata-only runtime capability (no providers, no network, no raw persistence).

Pointers:
- Temporal implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/`
- Runtime registry (allowlist + organ mapping + matrix): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C012_EXECUTION_PATH_PROOF.md`
- C012 verification: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C012_VERIFICATION.md`
- S3 guard report (C012): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C012.md`
- C012 concept entries (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

## 2025-12-28T15:31:45Z - C013 implemented (Multiversal Evaluation Engine)

Decision:
- Implemented C013 Multiversal Evaluation as a pure, read-only, deterministic measurement engine (no providers, no network, no state writes, no governance events).

Pointers:
- Multiverse implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/`
- Runtime registry (allowlist + organ mapping + matrix): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C013_EXECUTION_PATH_PROOF.md`
- C013 verification: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C013_VERIFICATION.md`
- S3 guard report (C013): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C013.md`
- C013 concept entries (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

## 2025-12-28T16:09:29Z - C014 implemented (Council Router Engine)

Decision:
- Implemented C014 Council Router as a bounded, schema-validated routing/orchestration layer with dry-run execution (no network, no provider SDKs, no fabricated outputs).

Pointers:
- Council implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/`
- Runtime registry (allowlist + organ mapping + matrix): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C014_EXECUTION_PATH_PROOF.md`
- C014 verification: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C014_VERIFICATION.md`
- S3 guard report (C014): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C014.md`
- C014 concept entries (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

## 2025-12-28T16:41:27Z - C015 implemented (Cognitive Engine)

Decision:
- Implemented C015 Cognition sandbox (deterministic, bounded, stateless) with schema-validated planning/execution and no chain-of-thought leakage; integrated only via Spine dispatch.

Pointers:
- Cognition implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/`
- Runtime registry (allowlist + organ mapping): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Execution path proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C015_EXECUTION_PATH_PROOF.md`
- C015 verification: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C015_VERIFICATION.md`
- S3 guard report (C015): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C015.md`
- C015 concept entries (append-only): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`

##  - C015 hardening (S3 alignment)

Decision:
- Removed a cross-organ import from the cognition test suite so S3 Import Truth remains fail-closed and PASS.

Pointers:
- Updated test file: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py
- Updated S3 guard report: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C015.md
- Updated verification doc: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C015_VERIFICATION.md
- Manifest append lines: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl

### 2025-12-28T17:01:19Z - Correction: timestamp for prior C015 hardening entry

Note:
- The immediately preceding "C015 hardening (S3 alignment)" heading was appended with an empty timestamp due to a tooling UTC flag error; this line records the canonical timestamp for that event.
- Canonical timestamp (UTC): 2025-12-28T17:01:19Z

## Process Clarifications — Duplicate Artifact Names

Duplicate Artifact Clarification & Rectification Clause

During W4.5–W4.6 execution, references to `decision_log.md` and `W4_PHASE_GATES.md` may appear duplicated in diff summaries or tooling output.

This duplication is non-semantic and results from the presence of canonical files and pointer/mirror references, not from accidental duplicate append operations.

Authoritative sources of truth:
- Decision log (canonical): `KT_PROD_CLEANROOM/02_PROVENANCE_LEDGER/decision_log.md`
- Decision log (mirror): `KT_PROD_CLEANROOM/decision_log.md`
- Phase gates (canonical): `KT_PROD_CLEANROOM/00_README_FIRST/W4_PHASE_GATES.md`
- Phase gates (pointer): `KT_PROD_CLEANROOM/W4_PHASE_GATES.md`

Policy:
- Each concept (C011–C016) has exactly one primary “implemented” decision entry per decision-log file; any later amendments are explicitly labeled (e.g., “hardening” or “correction”) and are not duplicates.

This clause resolves the duplicate-name ambiguity without rewriting history.

## 2025-12-28T17:30:24Z - C016 implemented (Teacher/Student & Curriculum Boundary)

Decision:
- Implemented C016 as a schema-first, fail-closed curriculum ingestion boundary (receipt-only) with explicit refusal taxonomy; no runtime learning, no network, no cross-organ invocation (cognition/council).

Pointers:
- Curriculum implementation: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/
- Runtime registry (allowlist + organ mapping + matrix): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json
- Execution path proof: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C016_EXECUTION_PATH_PROOF.md
- C016 verification: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C016_VERIFICATION.md
- S3 guard report (C016): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C016.md
- C016 concept entries (append-only): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl

## 2025-12-29T01:25:29Z - C017 implemented (Thermodynamics / Budget)

Decision:
- Implemented C017 as a deterministic, fail-closed “physics” layer enforcing per-request-domain ceilings (tokens/steps/branches/bytes + duration safety fuse) via schema-validated allocation + incremental pre-check consumption at the Spine boundary.

Pointers:
- Thermodynamics implementation: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/
- Runtime registry (allowlist + organ mapping + matrix): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json
- Spine wiring + incremental enforcement: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py
- Execution path proof: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C017_EXECUTION_PATH_PROOF.md
- C017 verification: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C017_VERIFICATION.md
- S3 guard report (C017): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C017.md
- C017 concept entries (append-only): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl

## 2025-12-29T11:20:56Z - C022 implemented (Council Provider Adapters, leaf-level, disabled-by-default)

Decision:
- Implemented C022 under the already-legal Council organ root (`src/council/providers/`) as provider adapter scaffolding that is **disabled-by-default**, **no-network**, **hash-only**, and **fail-closed**.

Pointers:
- Providers module root: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/
- System audit: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W5_5_C022_SYSTEM_AUDIT.md
- Execution path proof: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C022_EXECUTION_PATH_PROOF.md
- Verification report: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W5_5_C022_VERIFICATION.md
- S3 guard report (C022): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C022.md
- C022 concept entries (append-only): KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl

## 2025-12-29T12:10:00Z - C023+ implemented (Evaluation Expansion; tooling-only)

Decision:
- Implemented C023+ as a tooling-only eval expansion producing bounded numeric vectors (paradox/drift + golden-zone gating) derived from metadata only (counts/hashes/enums).

Pointers:
- Implementation root: KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/
- System audit: KT_PROD_CLEANROOM/tools/growth/docs/W5_6_C023_PLUS_SYSTEM_AUDIT.md
- Verification: KT_PROD_CLEANROOM/tools/growth/docs/W5_6_C023_PLUS_VERIFICATION.md
- Exec path proof: KT_PROD_CLEANROOM/tools/growth/docs/C023_PLUS_EXECUTION_PATH_PROOF.md
- Guard report: KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C023_PLUS.md

## 2025-12-29T12:10:00Z - C024 implemented (Training Warehouse; tooling-only)

Decision:
- Implemented C024 as an offline, append-only training warehouse with schema-validated exemplars and provenance binding; raw exemplar content is confined to the warehouse artifacts root.

Pointers:
- Implementation root: KT_PROD_CLEANROOM/tools/growth/training_warehouse/
- Warehouse artifacts root: KT_PROD_CLEANROOM/tools/growth/artifacts/training_warehouse/
- System audit: KT_PROD_CLEANROOM/tools/growth/docs/W5_7_C024_SYSTEM_AUDIT.md
- Verification: KT_PROD_CLEANROOM/tools/growth/docs/W5_7_C024_VERIFICATION.md
- Exec path proof: KT_PROD_CLEANROOM/tools/growth/docs/C024_EXECUTION_PATH_PROOF.md
- Guard report: KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C024.md

## 2025-12-29T12:10:00Z - C025 implemented (Distillation Pipeline; tooling-only)

Decision:
- Implemented C025 as an offline deterministic distillation pipeline producing reproducible artifact hashes from warehouse manifests (no kernel invocation; no training execution).

Pointers:
- Implementation root: KT_PROD_CLEANROOM/tools/growth/distillation/
- Distillation artifacts root: KT_PROD_CLEANROOM/tools/growth/artifacts/distillation/
- System audit: KT_PROD_CLEANROOM/tools/growth/docs/W5_8_C025_SYSTEM_AUDIT.md
- Verification: KT_PROD_CLEANROOM/tools/growth/docs/W5_8_C025_VERIFICATION.md
- Exec path proof: KT_PROD_CLEANROOM/tools/growth/docs/C025_EXECUTION_PATH_PROOF.md
- Guard report: KT_PROD_CLEANROOM/tools/growth/docs/CONSTITUTIONAL_GUARD_REPORT_C025.md
[W5.2][C021] Teacher Factory & Curriculum Compiler implemented; tooling-only; package compiled+signed; guard+tests PASS.

[W5.4][C020] Dream Loop implemented (tooling-only). Dream candidates materialize as crucible specs under artifacts; kernel invoked only via C019 subprocess harness; outputs are receipt refs + hash-only curriculum draft (not signed, not registered).
