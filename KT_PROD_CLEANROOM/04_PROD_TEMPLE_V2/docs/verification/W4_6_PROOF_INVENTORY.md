# W4.6-B Proof Inventory (V2 Gates G0–G9)

This inventory is **report-only**: statuses below are derived strictly from **existing artifacts on disk** (docs/reports/tests present). No tests were re-run and no new behavior was introduced.

## Gate: G0 — Authority Lock (Precondition)

Status: **FAIL**

Evidence:
- `KT_PROD_CLEANROOM/00_README_FIRST/W4_RULES.md`
- `KT_PROD_CLEANROOM/00_README_FIRST/W4_PHASE_GATES.md`
- `KT_PROD_CLEANROOM/00_README_FIRST/WHEN_IS_V2_DONE.md`
- `KT_PROD_CLEANROOM/W4_PHASE_GATES.md`

Missing (minimum proof artifacts):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (required by `WHEN_IS_V2_DONE.md`)

Blocker (exact):
- Runtime entrypoint path / Spine callable / vault path / approved runtime import roots are not explicitly declared in a single registry file (auto-discovery remains possible).

Minimum next action:
- **W4.6 corrective patch:** create `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` and update verification/guard tooling to use it (no conventions).

## Gate: G1 — Runtime Topology (Single Execution Path)

Status: **FAIL**

Evidence:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/entrypoint.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C001_VERIFICATION.md` (notes Spine-side wiring deferred)

Missing (minimum proof artifacts):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (explicit Entry + Spine declaration)
- A V2 Spine callable/module (substrate-mode Spine) and a proof artifact showing Entry → Spine → exit
- A single-path proof report (e.g., `docs/verification/EXECUTION_PATH_PROOF_V2.md`) tying the above to a PASS claim

Blocker (exact):
- V2 has no Spine module/callable; `src/entrypoint.py` does not call Spine (it only invokes C001 invariants gate).

Minimum next action:
- New concept required (not yet defined/authorized here): “Minimal V2 Spine orchestrator + Entry→Spine wiring + proof.”

## Gate: G2 — Import Truth (Organ Sovereignty)

Status: **FAIL**

Evidence:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py` (static scan + conservative import matrix)
- Guard reports:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C005.md`

Missing (minimum proof artifacts):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (approved runtime import roots allowlist)
- Import-time enforcement (meta-path guard or equivalent) proving illegal imports are mechanically impossible at runtime, not only “detectable by scan”

Blocker (exact):
- Import Truth exists as a static guard (`check_constitution.py`) but is not bound to an explicit runtime registry and is not enforced at import-time in the runtime environment.

Minimum next action:
- **W4.6 corrective patch:** add the explicit registry + a minimal import-time guard that enforces allowlisted roots and matrix (fail-closed).

## Gate: G3 — Schemas Are the Contract Perimeter (C002)

Status: **PASS**

Evidence:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/base_schema.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/runtime_context_schema.py`
- Docs:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_REGISTRY.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/SCHEMA_VERSION_LOCK.md`
- Verification:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C002_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C002_SCHEMAS_SUBSTRATE_SEAL.md`
- Tests (existence proof; pass results recorded in verification doc):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_schema_contracts.py`

Missing:
- None identified for C002 substrate scope (future organs must still bind through this perimeter).

Minimum next action:
- None (hold C002 immutable; any new schema requires new version/hash + new seal).

## Gate: G4 — State Vault Is the Sole Persistence Authority (C008)

Status: **PASS**

Evidence:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py`
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py`
- Verification:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/C008_STATE_VAULT_SUBSTRATE_SEAL.md`
- Tests (existence proof; pass results recorded in verification doc):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_state_vault.py`

Missing:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` should explicitly declare the vault path (required by G0), but this does not invalidate C008’s internal determinism/append-only guarantees.

Minimum next action:
- Address under G0 (registry).

## Gate: G5 — Temporal Integrity (Receipts + Replay Binding)

Status: **PASS**

Evidence:
- Constitution binding:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/versioning/constitution_registry.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py` (constitution hash invariant)
- Schema binding:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/schema_registry.py`
- Replay fail-closed on unknown constitution hash + hash chain integrity:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py`
- Verification:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md`

Missing:
- Multi-version logic selection is not applicable yet (single-hash regime). If/when multiple constitution/schema versions are introduced, an explicit selection registry must be added and proven fail-closed.

Minimum next action:
- None for current single-version substrate regime.

## Gate: G6 — Context Poisoning Defense (Bounded Deltas)

Status: **PASS**

Evidence:
- Context bounds + raw-content key rejection:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/runtime_context_schema.py`
- Persistence surface boundedness (allowlisted fields only; hash-only semantics possible via `inputs_hash`/`outputs_hash`):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/state_vault_schema.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py`
- Verification:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C001_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C002_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C005_VERIFICATION.md` (hash-only governance event logging)

Missing:
- A consolidated “persistence surfaces enumerated” report for V2 (optional but recommended as V2 grows).

Minimum next action:
- Generate a small report enumerating runtime write surfaces by static scan (no behavior change), once V2 adds more organs.

## Gate: G7 — Security Baseline (Secrets + Provider Discipline)

Status: **FAIL**

Evidence:
- Secrets/provider/training bleed scanning (static):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py`
- Guard reports (PASS at time of generation):
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C008.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/CONSTITUTIONAL_GUARD_REPORT_C005.md`

Missing (minimum proof artifacts):
- A no-network dry-run proof (test/harness) demonstrating **zero** socket/network calls during dry-run execution

Blocker (exact):
- No existing V2 artifact proves “No-Network Dry-Run Rule” beyond policy text; there is no dedicated test or verification report section.

Minimum next action:
- New concept or W4.6 corrective patch (authorization required): add a dry-run test that blocks sockets (fail-closed) and proves Entry/Spine path performs zero network calls.

## Gate: G8 — Verification (Proof, Not Hope)

Status: **FAIL**

Evidence:
- Substrate verifications exist:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C001_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C002_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C008_VERIFICATION.md`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/W4_5_C005_VERIFICATION.md`

Missing (minimum proof artifacts):
- An end-to-end dry-run proof through the canonical runtime path: Entry → Spine → (Router/Crucible/Governance as applicable), with provider/network disabled
- A single aggregated verification report tying the above to gates G1–G8

Blocker (exact):
- V2 has no Spine and therefore no canonical dry-run execution trace exists.

Minimum next action:
- Same as G1: new concept required for minimal V2 Spine + wiring + dry-run proof.

## Gate: G9 — Release Freeze (Gold Master)

Status: **UNKNOWN**

Evidence:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl` exists (concept-scoped append-only entries)

Missing (minimum proof artifacts):
- A full-tree V2 release manifest covering **every file** under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/` in deterministic order
- A two-pass stability proof (byte-identical manifest across two independent passes)
- A V2 seal document declaring proven guarantees + explicit non-goals
- A “no further mutations” attestation block for the frozen V2

Minimum next action:
- Defer until G0–G8 are PASS; then run the freeze phase to generate a full manifest + seal + attestation.
