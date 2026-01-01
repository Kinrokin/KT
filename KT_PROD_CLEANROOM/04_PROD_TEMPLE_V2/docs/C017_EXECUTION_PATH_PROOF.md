# C017 Execution Path Proof — Thermodynamics / Budget (Dry-Run)

Canonical topology (no alternate runtime entrypoints):

- Entry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` (`kt.entrypoint.invoke`)
- Spine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` (`core.spine.run`)
- Thermodynamics organ: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/budget_engine.py` (`thermodynamics.budget_engine.BudgetEngine`)

Proof statements (mechanical, fail-closed):

1. Entry calls Spine only.
   - Entry installs Import Truth from `docs/RUNTIME_REGISTRY.json`, asserts invariants, then resolves and invokes the canonical Spine callable.

2. Spine installs Import Truth before importing organs.
   - All organ imports occur only after `ImportTruthGuard.install(registry)`.

3. Spine allocates a budget domain at the beginning of every Spine run.
   - If `envelope.input` is a `budget.request`, Spine validates and allocates via `BudgetEngine.allocate(...)`.
   - Otherwise, Spine allocates the default domain via `BudgetEngine.allocate_default(...)`.

4. Spine enforces budget ceilings pre-emptively (incremental, deterministic).
   - Before every organ action (Paradox/Temporal/Multiverse/Council/Cognition/Curriculum), Spine calls `_budget_precheck(...)`.
   - `_budget_precheck(...)` constructs a schema-valid `budget.consumption` total and calls `BudgetEngine.consume(...)`.
   - On any refusal, Spine logs a hash-only governance event and halts with `SpineError` (no fallback).

5. Thermodynamics remains non-intelligent, no-network, and non-persistent.
   - `src/thermodynamics/*` has no imports from `memory/*` or `governance/*` (purity).
   - All persistence/events remain Spine-owned via C005+C008 mechanisms.

