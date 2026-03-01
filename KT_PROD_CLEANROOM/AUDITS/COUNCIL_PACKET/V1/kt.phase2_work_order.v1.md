# kt.phase2_work_order.v1.md

Generated at: 2026-02-17T03:57:11Z

Manifest SHA256: UNAVAILABLE_NO_DRIVE_MANIFEST

## Contents
- Team 01: Core Invariant Mathematician
- Team 02: Law & Constitution Steward
- Team 03: Schema Registry & Canonicalization Engineer
- Team 04: Determinism & Replay Engineer
- Team 05: Admission Gate Engineer
- Team 06: Suite Compiler & Redpack Engineer
- Team 07: Shard Plan & Map-Reduce Engineer
- Team 08: Tournament & Dominance Engineer
- Team 09: Merge Admissibility & Rollback Engineer
- Team 10: Detection Axis & Validator Engineer
- Team 11: Meta-Evaluator & Seal Verifier Engineer
- Team 12: CI/Preflight & Platform Matrix Engineer
- Team 13: Sovereign OS Kernel & Sandbox Engineer
- Team 14: Telemetry & Observability Lead
- Team 15: Data Lineage & Provenance Lead
- Team 16: Red Team & Adversarial Research Lead
- Team 17: Reporting & God Report Engineer
- Team 18: Kaggle Certification Notebook Engineer
- Team 19: Delivery Pack & Client Handoff Engineer
- Team 20: Integrations & API Contract Lead

---

## Team 01 — Core Invariant Mathematician

**Direct Objective**: Formally verify the Wisdom Invariant and prove that KT update rules preserve W(t) ≥ I(t) + δ under explicit threat models.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Proofs must be constructive and mechanized (Lean4 preferred; Coq acceptable).
- Maximum proof-check time per theorem: 2 hours on a 32-core CI runner.
- All definitions of W, I, and δ must be measurable functions of telemetry vectors (no opaque human-only definitions).

### Inter-Dependency Map
- **consumes** Data Lineage & Provenance Lead via `kt.telemetry.schemas.v1`
- **consumes** Telemetry & Observability Lead via `kt.telemetry.stream.v1`
- **consumes** Sovereign OS Kernel & Sandbox Engineer via `kt.proof_runner.sandbox.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/proofs/core_invariant/wisdom_invariant.lean`
- `KT_PROD_CLEANROOM/specs/telemetry/kt.telemetry.wisdom_definitions.v1.json`
- `KT_PROD_CLEANROOM/tests/vectors/wisdom_invariant_traces.v1.jsonl`
- `KT_PROD_CLEANROOM/ci/jobs/ci_proofs_core_invariant.yml`

**API endpoints / contracts**
- `GET /telemetry/schema/wisdom`
- `POST /proofs/submit`

**Formal requirements**
- \[\forall t.\; W(t)-I(t)\ge \delta \;\wedge\; \delta\ge 0\]
- \[W(t)=I(t)+S(t)\;\wedge\;S(t)=\min(\text{Safety}(t),\text{Gov}(t),\text{Det}(t))\]
- \[\text{PromotionAllowed}(t)\Rightarrow S(t)\ge \delta_{\text{promote}}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/wisdom_invariant_traces.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_wisdom_definitions_schema

**Integration tests**
- test_proof_ci_runner_executes_and_typechecks

**Formal proofs**
- KT_PROD_CLEANROOM/proofs/core_invariant/wisdom_invariant.lean

**Acceptance criteria**
- Lean/Coq proofs type-check on canonical CI runner.
- Telemetry schema validated by schema registry gate.
- Synthetic trace suite includes boundary conditions (S(t)=δ, catastrophic_fail_flag=true, determinism_score=0).

### Seal artifact
- `seal_core_invariant_mathematician_v1.json`

---

## Team 02 — Law & Constitution Steward

**Direct Objective**: Maintain the binding law layer: define amendment process, enforce add-only constraints, and produce signed law_seal artifacts for any constitutional change.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- All law mutations must be add-only unless explicitly authorized by an existing 'immutable change class' process.
- Law bundle hash must be stable across platforms and computed only from canonicalized sources.
- No 'soft' policy interpretation in code; enforcement must be mechanized via validators and CI gates.

### Inter-Dependency Map
- **consumes** Schema Registry & Canonicalization Engineer via `kt.schema_registry.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.law_seal.verify.v1`
- **provides** CI/Preflight & Platform Matrix Engineer via `kt.ci.law_integrity_gate.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/AUDITS/law/LAW_BUNDLE_FL3_CANONICAL.vN.json`
- `KT_PROD_CLEANROOM/AUDITS/law/law_seal.schema.v1.json`
- `KT_PROD_CLEANROOM/AUDITS/law/law_seal.template.v1.json`
- `KT_PROD_CLEANROOM/tools/verification/law_bundle_hash.py`
- `KT_PROD_CLEANROOM/tests/test_law_bundle_hash_stability.py`
- `KT_PROD_CLEANROOM/ci/jobs/ci_law_bundle_integrity.yml`

**API endpoints / contracts**
- `POST /law/submit_amendment`
- `GET /law/bundle/hash`
- `POST /law/seal/verify`

**Formal requirements**
- \[\text{LawBeforeCognition}: \neg \text{AdmissionPass} \Rightarrow \neg \text{TrainEvalJudgeHarvest}\]
- \[\text{NoEpigeneticMutation}: \text{ChangeAffectsLaw}\Rightarrow \exists \text{law\_seal}\wedge \text{Verify(law\_seal)}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/law_seal_positive_negative.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_law_seal_schema
- test_law_bundle_hash_determinism

**Integration tests**
- test_ci_law_integrity_gate

**Formal proofs**
- KT_PROD_CLEANROOM/AUDITS/law/LawBeforeCognition.v1.md

**Acceptance criteria**
- law_seal schema validates and rejects missing/invalid signatures.
- law_bundle hash identical on Linux/macOS/Windows runners.
- CI gate fails on any unsealed law-affecting diff.

### Seal artifact
- `seal_law_constitution_steward_v1.json`

---

## Team 03 — Schema Registry & Canonicalization Engineer

**Direct Objective**: Guarantee that every KT artifact is schema-bound, canonicalized, and hash-stable; provide the single source of truth registry for schemas and canonicalization rules.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Canonicalization must be pure and deterministic; it may not consult environment state.
- Schema registry must support add-only evolution and strict version pinning.
- Canonical JSON must be byte-identical for identical semantic content.

### Inter-Dependency Map
- **consumes** Law & Constitution Steward via `kt.schema.add_only_policy.v1`
- **provides** CI/Preflight & Platform Matrix Engineer via `kt.ci.schema_registry_gate.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/schemas/registry/SCHEMA_REGISTRY.v1.json`
- `KT_PROD_CLEANROOM/schemas/canonicalization/CANON_RULES.v1.json`
- `KT_PROD_CLEANROOM/tools/canonical/canonicalize_json.py`
- `KT_PROD_CLEANROOM/tools/verification/schema_validate.py`
- `KT_PROD_CLEANROOM/tests/test_canonicalization_stability.py`
- `KT_PROD_CLEANROOM/tests/test_schema_registry_add_only.py`

**API endpoints / contracts**
- `GET /schemas/registry`
- `POST /schemas/validate`
- `GET /canonicalize/json`

**Formal requirements**
- \[\forall x.\; \text{sha256}(\text{canon}(x))=\text{sha256}(\text{canon}(\text{canon}(x)))\]
- \[\text{AddOnly}(\text{SCHEMA\_REGISTRY})\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/canonicalization_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_schema_registry_add_only
- test_canonicalization_idempotent

**Integration tests**
- test_schema_validate_cli_on_all_artifacts

**Formal proofs**
- KT_PROD_CLEANROOM/schemas/canonicalization/CANON_RULES.v1.md

**Acceptance criteria**
- Canon idempotence tests pass.
- Schema registry blocks deletion/renaming of existing schema_ids.
- Hash stability proven across platform matrix.

### Seal artifact
- `seal_schema_registry_canonicalization_v1.json`

---

## Team 04 — Determinism & Replay Engineer

**Direct Objective**: Prove and continuously test that canonical lane executions replay byte-identically, producing identical receipts and hashes under the supported platform matrix.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- No non-deterministic sources (time, uuid, random, filesystem ordering) in hashed objects.
- Replay checks must compare canonicalized artifacts and enforce deterministic ordering.
- Support matrix must be explicit (OS, Python, deps, CUDA/CPU).

### Inter-Dependency Map
- **consumes** CI/Preflight & Platform Matrix Engineer via `kt.platform_matrix.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.replay.verdict.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/verification/replay_check.py`
- `KT_PROD_CLEANROOM/specs/replay/replay_manifest.v1.json`
- `KT_PROD_CLEANROOM/tests/test_replay_hash_identical.py`
- `KT_PROD_CLEANROOM/ci/jobs/ci_replay_matrix.yml`

**API endpoints / contracts**
- `POST /replay/submit`
- `GET /replay/verdict`

**Formal requirements**
- \[\text{Replayable}(run)\Rightarrow \forall a\in Artifacts(run).\; sha256(a)=sha256(a')\]
- \[\text{DeterministicOrder}: \text{SortBy}(case\_id, match\_id, file\_path)\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/replay_runs_small.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_no_time_uuid_in_hashed_objects
- test_canonical_ordering

**Integration tests**
- test_replay_matrix_ci_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/replay/Replayable.v1.md

**Acceptance criteria**
- Two independent runs on supported matrix yield identical run receipts.
- Replay tool outputs FAIL_CLOSED with actionable mismatch diffs.

### Seal artifact
- `seal_determinism_replay_v1.json`

---

## Team 05 — Admission Gate Engineer

**Direct Objective**: Implement the single master valve that decides whether training/evolution may proceed, based on law, determinism, environment, and artifact integrity.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Admission must be computed prior to any training/eval step.
- Admission output is a signed receipt with explicit deny reason codes.
- Admission failure must halt; no partial progress allowed.

### Inter-Dependency Map
- **consumes** Law & Constitution Steward via `kt.failure_taxonomy.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.schema_registry.v1`
- **consumes** Determinism & Replay Engineer via `kt.determinism.replay.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.admission.receipt.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/verification/training_admission.py`
- `KT_PROD_CLEANROOM/specs/admission/admission_receipt.v1.json`
- `KT_PROD_CLEANROOM/tests/test_training_admission_fail_closed.py`

**API endpoints / contracts**
- `POST /admission/check`

**Formal requirements**
- \[\neg AdmissionPass \Rightarrow \neg Execute(Train \cup Eval \cup Harvest)\]
- \[\text{AdmissionReceipt} := \langle run\_id, verdict, reason\_codes, inputs\_sha256\rangle\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/admission_negative_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_admission_receipt_schema
- test_admission_reason_codes_total

**Integration tests**
- test_phase2_execute_refuses_without_admission

**Formal proofs**
- KT_PROD_CLEANROOM/specs/admission/AdmissionSoundness.v1.md

**Acceptance criteria**
- Admission receipt emitted for all attempts, including failures.
- Denied admissions cannot progress into any lane.

### Seal artifact
- `seal_admission_gate_v1.json`

---

## Team 06 — Suite Compiler & Redpack Engineer

**Direct Objective**: Produce the 1250-case evaluation surface as sealed, deterministic inputs: a suite manifest plus a separately sealed payload redpack.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Canonical repo must not contain sensitive bypass/harm prompt payload text; store only hashes/labels in manifest.
- Suite compilation must be deterministic and reproducible from declared expansion algebra.
- Redpack must be sealed with hash and optional encryption; access controlled.

### Inter-Dependency Map
- **consumes** Schema Registry & Canonicalization Engineer via `kt.eval_suite_manifest.schema.v1`
- **consumes** Red Team & Adversarial Research Lead via `kt.redpack.payloads.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.suite.seal.verify.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/AUDITS/FRAC/kt.fractal_expansion.v1.json`
- `KT_PROD_CLEANROOM/AUDITS/SUITES/SUITE_GOV_FRACTAL_1250.v1.json`
- `KT_PROD_CLEANROOM/AUDITS/REDPACKS/REDPACK_GOV_FRACTAL_1250.v1.jsonl.enc`
- `KT_PROD_CLEANROOM/tools/suites/compile_suite.py`
- `KT_PROD_CLEANROOM/tools/suites/verify_suite_manifest.py`
- `KT_PROD_CLEANROOM/tests/test_suite_compilation_deterministic.py`

**API endpoints / contracts**
- `POST /suite/compile`
- `POST /suite/verify`
- `GET /suite/manifest/sha256`

**Formal requirements**
- \[\text{SuiteManifest}[i].payload\_sha256 = sha256(\text{RedpackPayload}[i])\]
- \[\text{NoRawPayloadInRepo}: \neg \exists \text{field} \in \text{SuiteManifest}:\text{field}=\text{payload\_text}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/suite_manifest_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_suite_manifest_schema
- test_no_raw_payload_fields

**Integration tests**
- test_suite_compile_and_verify_pipeline

**Formal proofs**
- KT_PROD_CLEANROOM/specs/suites/SuiteSoundness.v1.md

**Acceptance criteria**
- Suite manifest compiles deterministically and produces identical hashes on rerun.
- Suite verifier fails closed on missing/incorrect payload hashes.

### Seal artifact
- `seal_suite_compiler_redpack_v1.json`

---

## Team 07 — Shard Plan & Map-Reduce Engineer

**Direct Objective**: Implement sharding below evaluation and a deterministic reducer that validates completeness, overlap, and canonical ordering.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Sharding must partition by case_id only; no shard-local mutation of suite definitions.
- Reducer must FAIL_CLOSED on overlap, missing cases, or nondeterministic ordering.
- Reducer output must be canonicalized before hashing and sealing.

### Inter-Dependency Map
- **consumes** Suite Compiler & Redpack Engineer via `kt.suite.manifest.v1`
- **consumes** Determinism & Replay Engineer via `kt.reducer.determinism.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.shard_plan.schema.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/AUDITS/SHARDS/SHARD_PLAN_1250x10.v1.json`
- `KT_PROD_CLEANROOM/tools/eval/run_suite_eval_shard.py`
- `KT_PROD_CLEANROOM/tools/eval/reduce_suite_eval_shards.py`
- `KT_PROD_CLEANROOM/specs/shards/shard_plan.v1.json`
- `KT_PROD_CLEANROOM/tests/test_shard_reducer_completeness.py`

**API endpoints / contracts**
- `POST /suite_eval/shard/run`
- `POST /suite_eval/shards/reduce`

**Formal requirements**
- \[\bigsqcup_{k=1}^n Shard_k.case\_ids = Suite.case\_ids \;\wedge\; \forall i\ne j.\; Shard_i\cap Shard_j = \emptyset\]
- \[\text{Reduce}(shards)\Rightarrow \text{SortBy}(case\_id)\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/shard_overlap_missing_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_shard_plan_schema
- test_reducer_overlap_detection

**Integration tests**
- test_end_to_end_shard_eval_reduce_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/shards/ShardCorrectness.v1.md

**Acceptance criteria**
- Reducer rejects any shard set that does not cover suite exactly once.
- Reducer output is byte-identical across runs given identical shard inputs.

### Seal artifact
- `seal_shard_map_reduce_v1.json`

---

## Team 08 — Tournament & Dominance Engineer

**Direct Objective**: Run deterministic tournaments over adapters and produce dominance reports and champion sets with full receipts and replay proofs.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Tournament bracket and ordering must be deterministic and derived solely from sealed inputs.
- Every match produces a receipt including both contestants' hashes and suite evidence hashes.
- Dominance criteria must be explicitly defined (e.g., Pareto across axes, utility floor).

### Inter-Dependency Map
- **consumes** Shard Plan & Map-Reduce Engineer via `kt.suite_eval.merged_result.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.tournament.schemas.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.tournament.seal.verify.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/tournament/run_tournament.py`
- `KT_PROD_CLEANROOM/specs/tournament/match_receipt.v1.json`
- `KT_PROD_CLEANROOM/specs/tournament/tournament_result.v1.json`
- `KT_PROD_CLEANROOM/specs/tournament/dominance_report.v1.json`
- `KT_PROD_CLEANROOM/tests/test_tournament_determinism.py`

**API endpoints / contracts**
- `POST /tournament/run`
- `GET /tournament/result`
- `GET /tournament/dominance`

**Formal requirements**
- \[\text{MatchReceipt} := \langle match\_id, left\_hash, right\_hash, suite\_hash, verdict, axis\_scores\rangle\]
- \[\text{Dominates}(A,B)\Rightarrow \forall axis.\; score_A(axis)\ge score_B(axis)\;\wedge\;\exists axis.\;>\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/tournament_small_bracket.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_match_receipt_schema
- test_dominance_definition_total

**Integration tests**
- test_tournament_end_to_end_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/tournament/Dominance.v1.md

**Acceptance criteria**
- Tournament rerun yields byte-identical result files.
- Dominance report includes supporting match receipts for every claim.

### Seal artifact
- `seal_tournament_dominance_v1.json`

---

## Team 09 — Merge Admissibility & Rollback Engineer

**Direct Objective**: Define and enforce merge admissibility (including TIES merges) with post-merge full evaluation proofs and deterministic rollback plans.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- No merge without a champion set and explicit admissibility proof.
- All merges must be reversible: rollback plan is mandatory artifact.
- Merged artifact must be evaluated on full suite and pass promotion margin δ.

### Inter-Dependency Map
- **consumes** Tournament & Dominance Engineer via `kt.champion_set.v1`
- **consumes** Core Invariant Mathematician via `kt.wisdom_invariant.proof.v1`
- **consumes** Law & Constitution Steward via `kt.promotion_policy.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/merge/merge_evaluator.py`
- `KT_PROD_CLEANROOM/specs/merge/merge_manifest.v1.json`
- `KT_PROD_CLEANROOM/specs/merge/rollback_plan.v1.json`
- `KT_PROD_CLEANROOM/tests/test_merge_requires_full_eval.py`

**API endpoints / contracts**
- `POST /merge/evaluate`
- `POST /merge/rollback_plan/verify`

**Formal requirements**
- \[\text{MergeAllowed}\Rightarrow \text{FullSuitePass}\wedge S(t)\ge \delta_{\text{merge}}\]
- \[\text{RollbackPlan} := \langle from\_hash, to\_hash, steps, verify\_hashes\rangle\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/merge_negative_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_merge_manifest_schema
- test_rollback_plan_schema

**Integration tests**
- test_merge_eval_then_full_suite_proof

**Formal proofs**
- KT_PROD_CLEANROOM/specs/merge/MergeSoundness.v1.md

**Acceptance criteria**
- Merge evaluator refuses any merge without full-suite evidence and invariant checks.
- Rollback plan verified and tested in CI on a synthetic merge.

### Seal artifact
- `seal_merge_admissibility_rollback_v1.json`

---

## Team 10 — Detection Axis & Validator Engineer

**Direct Objective**: Implement the attack detection axis and validators catalog so KT can measure detection sensitivity independently from refusal.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Validators must be pure functions over canonical artifacts (no network, no side effects).
- Validator catalog is versioned and hash-stable; selection uses catalog version pin.
- Detection axis must not store disallowed payloads in repo; operate on labels/hashes.

### Inter-Dependency Map
- **consumes** Schema Registry & Canonicalization Engineer via `kt.validator_catalog.schema.v1`
- **consumes** Suite Compiler & Redpack Engineer via `kt.redpack.payload_hashes.v1`
- **provides** Telemetry & Observability Lead via `kt.axis_scores.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/validators/VALIDATOR_CATALOG_FL3_V4.json`
- `KT_PROD_CLEANROOM/validators/axis_scoring_policy_attack_detection.v1.json`
- `KT_PROD_CLEANROOM/tools/validators/run_validators.py`
- `KT_PROD_CLEANROOM/tests/test_validator_catalog_hash_stable.py`

**API endpoints / contracts**
- `GET /validators/catalog`
- `POST /validators/run`

**Formal requirements**
- \[\text{AttackDetectionScore} := f(\text{model\_outputs}, \text{case\_labels})\in[0,1]\]
- \[\text{CatalogPinned}: sha256(VALIDATOR\_CATALOG)=\text{pinned\_hash}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/detection_axis_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_validator_catalog_schema
- test_attack_detection_scoring_bounds

**Integration tests**
- test_validators_run_on_suite_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/validators/AttackDetectionAxis.v1.md

**Acceptance criteria**
- Catalog hash pinned and verified in meta-evaluator.
- Detection axis computed for every case and included in suite eval output.

### Seal artifact
- `seal_detection_axis_validator_v1.json`

---

## Team 11 — Meta-Evaluator & Seal Verifier Engineer

**Direct Objective**: Own the meta-evaluator that verifies receipts, hashes, seals, and invariants across the full KT pipeline and produces final audit verdicts.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Meta-evaluator must be fail-closed and provide minimal diffs on failure.
- Meta-evaluator must verify law bundle hash, schema registry hash, suite hash, and run receipts.
- Meta-evaluator output is the single source of truth for 'PASS/FAIL' in canonical claims.

### Inter-Dependency Map
- **consumes** Law & Constitution Steward via `kt.law_bundle.hash.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.schema_registry.v1`
- **consumes** Determinism & Replay Engineer via `kt.replay.verdict.v1`
- **provides** CI/Preflight & Platform Matrix Engineer via `kt.ci.meta_evaluator_gate.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py`
- `KT_PROD_CLEANROOM/specs/meta/meta_eval_report.v1.json`
- `KT_PROD_CLEANROOM/tests/test_meta_evaluator_fail_closed.py`

**API endpoints / contracts**
- `POST /meta_evaluator/run`
- `GET /meta_evaluator/report`

**Formal requirements**
- \[\text{MetaEvalPass}\Rightarrow (\text{AllHashesVerified}\wedge \text{AllSchemasValid}\wedge \text{NoForbiddenMutations})\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/meta_eval_negative_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_meta_eval_report_schema
- test_forbidden_mutations_detected

**Integration tests**
- test_full_pipeline_meta_eval_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/meta/MetaEvaluatorSoundness.v1.md

**Acceptance criteria**
- Meta-evaluator fails closed on any missing/invalid hash or schema.
- Meta-evaluator provides deterministic error codes + diff pointers.

### Seal artifact
- `seal_meta_evaluator_seal_verifier_v1.json`

---

## Team 12 — CI/Preflight & Platform Matrix Engineer

**Direct Objective**: Lock the supported platform matrix and ensure all canonical entrypoints run preflight and pass CI gates before any sealing or promotion.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- All canonical runs must execute preflight and growth_e2e_gate and produce seal tarball + sha256.
- Platform matrix must be explicit and versioned (OS, Python, deps, CUDA).
- CI must block merges that reduce coverage, determinism, or seal integrity.

### Inter-Dependency Map
- **consumes** Sovereign OS Kernel & Sandbox Engineer via `kt.canonical_runner.image.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.schema_registry.status.v1`
- **consumes** Meta-Evaluator & Seal Verifier Engineer via `kt.meta_eval_gate.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/verification/preflight_fl4.py`
- `KT_PROD_CLEANROOM/tools/verification/growth_e2e_gate.py`
- `KT_PROD_CLEANROOM/ci/platform_matrix.v1.json`
- `KT_PROD_CLEANROOM/ci/jobs/ci_preflight.yml`
- `KT_PROD_CLEANROOM/tests/test_preflight_requires_out_dir_rules.py`

**API endpoints / contracts**
- `CI:ci_preflight`
- `CI:ci_replay_matrix`
- `CI:ci_seal_export`

**Formal requirements**
- \[\text{CI\_Pass}\Rightarrow \text{PreflightPass}\wedge \text{GrowthGatePass}\wedge \text{SealExportPass}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/preflight_negative_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_preflight_schema_checks
- test_platform_matrix_versioned

**Integration tests**
- test_ci_pipeline_full_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/ci/CIInvariants.v1.md

**Acceptance criteria**
- CI pipeline reproduces PASS results on supported matrix; blocks outside-matrix claims.

### Seal artifact
- `seal_ci_preflight_platform_matrix_v1.json`

---

## Team 13 — Sovereign OS Kernel & Sandbox Engineer

**Direct Objective**: Provide the canonical execution sandbox: IO guard, allowlisted writes, no network, pinned runtime, and proof-check runners.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Network egress denied by default; exceptions require law_seal.
- Filesystem writes restricted to allowlisted output roots (exports/_runs/*).
- Runner images are versioned and addressed by content hash.

### Inter-Dependency Map
- **consumes** Law & Constitution Steward via `kt.io_policy.v1`
- **provides** CI/Preflight & Platform Matrix Engineer via `kt.canonical_runner.image.v1`
- **provides** Determinism & Replay Engineer via `kt.runner.replay_env.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/io_guard/io_guard.py`
- `KT_PROD_CLEANROOM/specs/runtime/runner_image_manifest.v1.json`
- `KT_PROD_CLEANROOM/tests/test_io_guard_no_network.py`

**API endpoints / contracts**
- `RUNTIME:io_guard_enable`
- `RUNTIME:runner_image_resolve`

**Formal requirements**
- \[\text{IOGuardEnabled}\Rightarrow \neg \text{NetworkEgress}\wedge \text{Writes}\subseteq \text{Allowlist}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/io_guard_negative_cases.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_io_guard_blocks_network
- test_write_allowlist_enforced

**Integration tests**
- test_canonical_runner_smoke_with_io_guard

**Formal proofs**
- KT_PROD_CLEANROOM/specs/runtime/IOGuard.v1.md

**Acceptance criteria**
- All canonical entrypoints execute with IO guard active and cannot write outside allowlist.

### Seal artifact
- `seal_sovereign_os_kernel_sandbox_v1.json`

---

## Team 14 — Telemetry & Observability Lead

**Direct Objective**: Define and ship telemetry capture for KT runs, including axis scores, gate outcomes, and provenance integrity signals used to compute W/I/δ.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Telemetry must be schema-bound and written as append-only artifacts under exports/_runs/<run_id>/telemetry/.
- No PII; no raw redpack payload text in telemetry.
- Metrics must be reproducible from stored artifacts.

### Inter-Dependency Map
- **consumes** Schema Registry & Canonicalization Engineer via `kt.telemetry.schemas.v1`
- **consumes** Data Lineage & Provenance Lead via `kt.telemetry.lineage.v1`
- **provides** Reporting & God Report Engineer via `kt.telemetry.query.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/specs/telemetry/kt.telemetry.vector.v1.json`
- `KT_PROD_CLEANROOM/tools/telemetry/emit_telemetry.py`
- `KT_PROD_CLEANROOM/tests/test_telemetry_schema_and_bounds.py`

**API endpoints / contracts**
- `GET /telemetry/run/<run_id>`
- `GET /telemetry/schema`

**Formal requirements**
- \[\text{TelemetryVector}(t)\in \mathbb{R}^n \text{ with declared ranges and nullability}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/telemetry_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_telemetry_vector_schema
- test_axis_scores_in_range

**Integration tests**
- test_telemetry_emitted_for_full_pipeline

**Formal proofs**
- KT_PROD_CLEANROOM/specs/telemetry/TelemetryCompleteness.v1.md

**Acceptance criteria**
- Every run emits telemetry vector per epoch/match with stable schema_id.
- Telemetry can be recomputed from artifacts (replay check).

### Seal artifact
- `seal_telemetry_observability_v1.json`

---

## Team 15 — Data Lineage & Provenance Lead

**Direct Objective**: Ensure end-to-end provenance: every artifact is traceable to inputs, parent_hash chains, and sealed manifests; no output without lineage.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- All artifacts must include parent_hash and input_hash fields where applicable.
- Provenance manifests are WORM and cannot be overwritten.
- Lineage graph must be reconstructable offline from receipts.

### Inter-Dependency Map
- **consumes** Schema Registry & Canonicalization Engineer via `kt.provenance.schemas.v1`
- **provides** Meta-Evaluator & Seal Verifier Engineer via `kt.provenance.verify.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/specs/provenance/provenance_manifest.v1.json`
- `KT_PROD_CLEANROOM/tools/provenance/build_lineage_graph.py`
- `KT_PROD_CLEANROOM/tests/test_parent_hash_chain_integrity.py`

**API endpoints / contracts**
- `GET /provenance/lineage/<artifact_hash>`

**Formal requirements**
- \[\text{ProvenanceBeforeOutput}: \text{Valid}(artifact)\Rightarrow \exists \text{lineage}(artifact)\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/lineage_graph_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_provenance_manifest_schema
- test_parent_hash_chain_no_gaps

**Integration tests**
- test_lineage_graph_build_for_run

**Formal proofs**
- KT_PROD_CLEANROOM/specs/provenance/LineageSoundness.v1.md

**Acceptance criteria**
- Meta-evaluator can verify lineage for every sealed run.
- Missing parent links fail closed.

### Seal artifact
- `seal_data_lineage_provenance_v1.json`

---

## Team 16 — Red Team & Adversarial Research Lead

**Direct Objective**: Define threat models and produce safely-handled adversarial case payloads for the redpack, with governance controls and leakage prevention.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- No disallowed payloads stored in canonical repo; payloads live only in sealed redpacks with access control.
- Threat models must be explicit and mapped to mitigations and measurable validators.
- All payload creation must obey law scope policy and audit logging.

### Inter-Dependency Map
- **consumes** Law & Constitution Steward via `kt.red_team.scope_policy.v1`
- **provides** Suite Compiler & Redpack Engineer via `kt.redpack.payloads.v1`
- **consumes** Detection Axis & Validator Engineer via `kt.attack_detection_axis.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/AUDITS/threat_models/THREAT_MODEL_CATALOG.v1.json`
- `KT_PROD_CLEANROOM/AUDITS/red_team/REDPACK_PAYLOAD_POLICY.v1.md`
- `KT_PROD_CLEANROOM/tests/test_redpack_policy_no_repo_leakage.py`

**API endpoints / contracts**
- `POST /red_team/redpack/submit`
- `POST /red_team/threat_model/submit`

**Formal requirements**
- \[\text{ThreatModel} := \langle id, actor, capability, goal, mitigations, measurable\_signals\rangle\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/threat_model_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_threat_model_catalog_schema
- test_redpack_no_repo_payload_text

**Integration tests**
- test_redpack_submission_audit_logged

**Formal proofs**
- KT_PROD_CLEANROOM/AUDITS/threat_models/ThreatModelCompleteness.v1.md

**Acceptance criteria**
- Threat model catalog covers poisoning, byzantine nodes, prompt injection, compute starvation.
- Redpack pipeline produces sealed payload pack with sha256 and audit log.

### Seal artifact
- `seal_red_team_adversarial_research_v1.json`

---

## Team 17 — Reporting & God Report Engineer

**Direct Objective**: Generate the machine-first audit report and the non-canonical God Report for human inspection, both derived from sealed artifacts.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- God Report must be explicitly watermarked NON-CANONICAL and may not be used for acceptance without the machine report.
- Reports must be reproducible from run artifacts (no manual edits).
- Reports must include pointers to receipts/hashes for every claim.

### Inter-Dependency Map
- **consumes** Meta-Evaluator & Seal Verifier Engineer via `kt.audit_eval_report.v1`
- **consumes** Telemetry & Observability Lead via `kt.telemetry.query.v1`
- **provides** Integrations & API Contract Lead via `kt.reporting.api.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/reporting/generate_audit_report.py`
- `KT_PROD_CLEANROOM/specs/reporting/audit_eval_report.v1.json`
- `KT_PROD_CLEANROOM/specs/reporting/god_report_template.v1.md`
- `KT_PROD_CLEANROOM/tests/test_report_reproducible_from_artifacts.py`

**API endpoints / contracts**
- `POST /reporting/audit_report`
- `GET /reporting/god_report`

**Formal requirements**
- \[\text{ReportClaim}\Rightarrow \exists \text{receipt\_pointer}\wedge \exists \text{sha256}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/report_claim_pointer_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_audit_report_schema
- test_god_report_watermark_present

**Integration tests**
- test_generate_reports_on_sample_run

**Formal proofs**
- KT_PROD_CLEANROOM/specs/reporting/ReportSoundness.v1.md

**Acceptance criteria**
- Audit report JSON validates and links to every receipt/hmac.
- God report marked NON-CANONICAL and references machine report.

### Seal artifact
- `seal_reporting_god_report_v1.json`

---

## Team 18 — Kaggle Certification Notebook Engineer

**Direct Objective**: Produce a golden, read-only Kaggle notebook that runs the canonical acceptance test: preflight → growth gate → (optional) phase2 → seal export, without mutating the repo.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Notebook must not modify repo code (no sed -i, rm -rf, git reset/clean in repo).
- All artifacts must be written outside repo into out_dir, with tarball+sha256.
- Notebook must set pinned SHA and pinned Python environment explicitly.

### Inter-Dependency Map
- **consumes** CI/Preflight & Platform Matrix Engineer via `kt.canonical_lane.entrypoints.v1`
- **consumes** Sovereign OS Kernel & Sandbox Engineer via `kt.io_guard_enable.v1`
- **provides** Delivery Pack & Client Handoff Engineer via `kt.delivery_pack.inputs.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/notebooks/KT_KAGGLE_GOLDEN_CELL_v1.ipynb`
- `KT_PROD_CLEANROOM/tests/test_notebook_forbidden_mutations.py`
- `KT_PROD_CLEANROOM/specs/notebooks/kaggle_run_contract.v1.md`

**API endpoints / contracts**
- `NOTEBOOK:KT_KAGGLE_GOLDEN_CELL_v1`

**Formal requirements**
- \[\text{NotebookRun}\Rightarrow \text{PreflightPass}\wedge \text{SealExportProduced}\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/notebook_smoke_inputs.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_notebook_no_forbidden_commands

**Integration tests**
- test_kaggle_notebook_smoke_cpu

**Formal proofs**
- KT_PROD_CLEANROOM/specs/notebooks/NotebookNonMutation.v1.md

**Acceptance criteria**
- Notebook produces seal tarball and prints sha256.
- Notebook fails closed if PINNED_SHA missing.

### Seal artifact
- `seal_kaggle_certification_notebook_v1.json`

---

## Team 19 — Delivery Pack & Client Handoff Engineer

**Direct Objective**: Create the sealed delivery pack (tarball + manifest + sha256) and a client-facing handoff guide that explains verification and replay.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Delivery pack must include manifest listing every artifact and sha256.
- Pack must be verifiable offline using validator and meta-evaluator.
- No secrets or disallowed payload text in pack unless explicitly allowed and sealed.

### Inter-Dependency Map
- **consumes** Meta-Evaluator & Seal Verifier Engineer via `kt.delivery_pack.hash_manifest.v1`
- **consumes** Reporting & God Report Engineer via `kt.reporting.outputs.v1`
- **provides** Integrations & API Contract Lead via `kt.delivery_pack.api.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/tools/delivery/build_delivery_pack.py`
- `KT_PROD_CLEANROOM/specs/delivery/delivery_manifest.v1.json`
- `KT_PROD_CLEANROOM/README_DELIVERY_VERIFY.md`
- `KT_PROD_CLEANROOM/tests/test_delivery_pack_manifest_complete.py`

**API endpoints / contracts**
- `POST /delivery/pack/build`
- `GET /delivery/pack/manifest`

**Formal requirements**
- \[\text{DeliveryPack}\Rightarrow \forall f\in Files.\; sha256(f)=Manifest.sha256[f]\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/delivery_pack_smoke.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_delivery_manifest_schema
- test_manifest_lists_all_files

**Integration tests**
- test_build_delivery_pack_and_verify

**Formal proofs**
- KT_PROD_CLEANROOM/specs/delivery/DeliverySoundness.v1.md

**Acceptance criteria**
- Pack verifies offline; manifest complete; hashes match.

### Seal artifact
- `seal_delivery_pack_client_handoff_v1.json`

---

## Team 20 — Integrations & API Contract Lead

**Direct Objective**: Define stable API contracts (CLI + optional HTTP) for admission, suite eval, tournament, meta-evaluation, telemetry, and reporting so teams integrate without ambiguity.

### Technical Constraints
- Fail-closed only; diagnostics may be added but gates may not be weakened. (Operating constraints)
- Repo treated as frozen unless a comprehensive system audit passes; all changes must include system-wide audit impact analysis. (Operating constraints)
- No autonomous production mutation; any constitutional/law change requires a human-signed law_seal with >=3 approvers and post-apply receipts.
- Canonical lane must be deterministic: no wall-clock, uuid, non-seeded randomness, unpinned deps, or environment-dependent paths.
- Canonical lane must be IO-guarded: deny network egress and restrict writes to allowlisted roots (exports/_runs/*).
- Contracts must be versioned and schema-bound; breaking changes require new version and law approval.
- No external network calls from canonical lane; integration endpoints are local or controlled.
- All endpoints must return explicit FAIL_CLOSED error codes.

### Inter-Dependency Map
- **consumes** Admission Gate Engineer via `kt.admission.api.v1`
- **consumes** Telemetry & Observability Lead via `kt.telemetry.api.v1`
- **consumes** Reporting & God Report Engineer via `kt.reporting.api.v1`
- **consumes** Schema Registry & Canonicalization Engineer via `kt.contract_schemas.v1`

### Work Order Detail
**Artifacts to deliver**
- `KT_PROD_CLEANROOM/specs/api/kt_api_contracts.v1.yaml`
- `KT_PROD_CLEANROOM/specs/api/error_codes.v1.json`
- `KT_PROD_CLEANROOM/tests/test_api_contract_examples_validate.py`

**API endpoints / contracts**
- `GET /contracts/v1`
- `POST /contracts/validate`

**Formal requirements**
- \[\text{EndpointResponse} := \langle status, code, message, receipt\_pointer\rangle\]

**Test vectors**
- `KT_PROD_CLEANROOM/tests/vectors/api_examples.v1.jsonl`

### Definition of Done (DoD)
**Unit tests**
- test_error_codes_total
- test_contract_yaml_valid

**Integration tests**
- test_contracts_used_by_all_tools_smoke

**Formal proofs**
- KT_PROD_CLEANROOM/specs/api/ContractStability.v1.md

**Acceptance criteria**
- All tools reference the same contract versions; CI blocks mismatches.

### Seal artifact
- `seal_integrations_api_contracts_v1.json`

---

