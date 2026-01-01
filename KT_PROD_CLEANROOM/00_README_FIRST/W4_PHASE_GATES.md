# W4 PHASE GATES

## W4.0 — Intake & Authority Lock (Hard Gate)
Deliverables:
- `01_INPUTS_READONLY/TEMPLE_V1_SNAPSHOT/TEMPLE_RELEASE_MANIFEST.jsonl`
- `01_INPUTS_READONLY/TEMPLE_V1_SNAPSHOT/TEMPLE_V1_SEAL.md`
- `00_README_FIRST/W4_RULES.md`
- `02_PROVENANCE_LEDGER/custody_chain.md`

Gate Condition:
- Inputs are locked; pointers recorded; no code copied into V2; no indexing performed.

## W4.1 - Candidate Harvest Index (Measurement-Only)
Deliverables:
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/sha256_manifest.jsonl`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/file_catalog.jsonl`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/ast_index.jsonl`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/ast_parse_failures.jsonl`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/import_graph.json`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/ENTRYPOINTS_REPORT.md`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/CONFIG_DEPENDENCIES_REPORT.md`
- `03_SYNTHESIS_LAB/01_CORPUS_INDEX/SECRETS_LOCATORS_REPORT.md`

Gate Condition:
- Measurement complete and deterministic; no code copied into V2.

## W4.2 - Organ Candidate Sets & De-dup Mapping (No Synthesis)
Deliverables:
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/ORGAN_CANDIDATE_SETS.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/DEDUP_CLUSTERS.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/GHOST_LOGIC_CLUSTER_REPORT.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/DRIFT_REGISTER_W4.md`

Gate Condition:
- Candidate variants are enumerated and clustered; no winners selected; no code copied into V2.

## W4.3 - Comparative Dominance Analysis vs KT_TEMPLE_V1 (No Synthesis)
Deliverables:
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/ORGANS_VS_V1_SCORECARDS.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/W4_DOMINANCE_DECISIONS.md`

Gate Condition:
- Shortlists only; if evidence is insufficient, verdict is `Unknown` (fail-closed).

## W4.4 - Concept-First Integration (Design-Only)
Deliverables:
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/CONCEPT_REGISTRY.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/W4_5_BACKLOG.md`
- `03_SYNTHESIS_LAB/02_COMPARATIVE_REPORTS/DISQUALIFICATION_PATTERNS.md`

Gate Condition:
- Concepts/tickets exist; no code copied into V2; no synthesis performed.

## W4.5 - One-Concept Integration Loop (Bounded Changes)
For each concept ID, all steps are mandatory and fail-closed:

- W4.5.1 Plan: `03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_<ID>_PLAN.md`
- W4.5.1b (S1): `04_PROD_TEMPLE_V2/docs/W4_5_DIFF_RATIONALE_<ID>.md` (required when concept references historical code/logic)
- W4.5.1c (S2): `04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py` + `04_PROD_TEMPLE_V2/docs/STATE_VAULT_SCHEMA_SPEC.md` (required before any state/ledger/receipt work)
- W4.5.2 Minimal implementation: only under `04_PROD_TEMPLE_V2/`
- W4.5.3 Verification: invariants must all PASS (Import Truth, Negative Space, single execution path, temporal replay, context poisoning bounds) and S3 guard must PASS
- W4.5.4 Decision gate: accept (integrated) or revert (rejected); preserve evidence

Substrate rule:
- C001 Invariants Gate is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C002 Schemas as Bounded Contracts is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C002 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C002_SCHEMAS_SUBSTRATE_SEAL.md`
- C005 Governance Event Hashing Logger is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C005 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C005_GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL.md`
- C008 State Vault append-only discipline is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C008 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C008_STATE_VAULT_SUBSTRATE_SEAL.md`
- C010 Runtime Registry + Substrate Spine + Import-Time Sovereignty is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C010 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C010_RUNTIME_TOPOLOGY_SUBSTRATE_SEAL.md`

Gate Condition:
- Hard stop after each concept; no batching multiple concepts.

Integrated concepts (non-substrate):
- C011 Paradox Injection Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C011_VERIFICATION.md`
- C012 Temporal Fork & Deterministic Replay Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C012_VERIFICATION.md`
- C013 Multiversal Evaluation Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C013_VERIFICATION.md`
- C014 Council Router Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C014_VERIFICATION.md`
- C015 Cognitive Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C015_VERIFICATION.md`
- C016 Teacher/Student & Curriculum Boundary: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C016_VERIFICATION.md`
- C017 Thermodynamics / Budget: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C017_VERIFICATION.md`

## W4.G9 - V2 Freeze (Gold Master)

Deliverables:
- `04_PROD_TEMPLE_V2/docs/V2_FULL_RELEASE_MANIFEST.jsonl` (full-tree fingerprint; self-excluding)
- `04_PROD_TEMPLE_V2/docs/V2_MANIFEST_STABILITY_PROOF.md`
- `04_PROD_TEMPLE_V2/docs/KT_TEMPLE_V2_SEAL.md`
- `04_PROD_TEMPLE_V2/docs/V2_FINAL_VERIFICATION_INDEX.md`
- `04_PROD_TEMPLE_V2/docs/V2_IMMUTABILITY_ATTESTATION.md`

Gate Condition:
- Freeze artifacts exist and are internally consistent; no runtime code changes performed during freeze.
