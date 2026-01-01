# W4 PHASE GATES (POINTER)

Canonical document:
- `KT_PROD_CLEANROOM/00_README_FIRST/W4_PHASE_GATES.md`

Substrate rule (excerpt):
- C001 Invariants Gate is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C002 Schemas as Bounded Contracts is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C002 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C002_SCHEMAS_SUBSTRATE_SEAL.md`
- C005 Governance Event Hashing Logger is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C005 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C005_GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL.md`
- C008 State Vault append-only discipline is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C008 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C008_STATE_VAULT_SUBSTRATE_SEAL.md`
- C010 Runtime Registry + Substrate Spine + Import-Time Sovereignty is substrate; it may not be modified except by explicit authorization plus a new seal + manifest + verification.
- C010 seal (SEALED): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C010_RUNTIME_TOPOLOGY_SUBSTRATE_SEAL.md`

V2 freeze artifacts (G9):
- Full-tree manifest: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_FULL_RELEASE_MANIFEST.jsonl` (self-excluding)
- Stability proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_MANIFEST_STABILITY_PROOF.md`
- Seal: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/KT_TEMPLE_V2_SEAL.md`

Integrated (post-freeze) concepts:
- C011 Paradox Injection Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C011_VERIFICATION.md`
- C012 Temporal Fork & Deterministic Replay Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C012_VERIFICATION.md`
- C013 Multiversal Evaluation Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C013_VERIFICATION.md`
- C014 Council Router Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C014_VERIFICATION.md`
- C015 Cognitive Engine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C015_VERIFICATION.md`
- C016 Teacher/Student & Curriculum Boundary: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C016_VERIFICATION.md`
- C017 Thermodynamics / Budget: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C017_VERIFICATION.md`
[W5.2][C021] Teacher Factory sealed (tooling-only). Any changes require new authorization + new verification report.

[W5.4][C020] Dream Loop implemented (tooling-only). Any changes require new authorization + new verification report.

[W5.5][C022] Council provider adapters implemented under `04_PROD_TEMPLE_V2/src/council/providers/` (leaf-level, disabled-by-default, no-network, hash-only). See `04_PROD_TEMPLE_V2/docs/W5_5_C022_VERIFICATION.md`.

[W5.6][C023+] Evaluation expansion implemented (tooling-only) under `tools/growth/eval_harness_plus/`. See `tools/growth/docs/W5_6_C023_PLUS_VERIFICATION.md`.

[W5.7][C024] Training warehouse implemented (tooling-only) under `tools/growth/training_warehouse/` with artifacts under `tools/growth/artifacts/training_warehouse/`. See `tools/growth/docs/W5_7_C024_VERIFICATION.md`.

[W5.8][C025] Distillation pipeline implemented (tooling-only) under `tools/growth/distillation/` with artifacts under `tools/growth/artifacts/distillation/`. See `tools/growth/docs/W5_8_C025_VERIFICATION.md`.
