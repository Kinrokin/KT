# C013 Execution Path Proof (Dry-Run, No-Network, Non-Authoritative)

Canonical runtime path (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`):

- Entry: `kt.entrypoint:invoke`
- Spine: `core.spine:run`
- Multiverse: `multiverse.multiverse_engine:MultiverseEngine.evaluate`

Wiring evidence:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` resolves and calls the canonical Spine callable from the runtime registry.
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` imports `multiverse.multiverse_engine` only after Import Truth is installed and invokes MultiverseEngine only when `envelope.input` declares a `multiverse.eval_request` payload.
- No other runtime module imports MultiverseEngine directly; there is no bypass path around the Spine dispatcher.

Dry-run / safety constraints:

- Multiverse evaluation is measurement-only: no vault writes, no governance events, no temporal mutation.
- No provider SDK imports are introduced by C013.
- Network usage is prohibited; tests hard-block `socket` to enforce fail-closed behavior.

