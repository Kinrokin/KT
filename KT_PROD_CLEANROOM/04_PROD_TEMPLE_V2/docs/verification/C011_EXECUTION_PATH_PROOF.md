# C011 Execution Path Proof (Dry-Run, No-Network)

Canonical runtime path (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`):

- Entry: `kt.entrypoint:invoke`
- Spine: `core.spine:run`
- Paradox: `paradox.paradox_engine:ParadoxEngine.run`

Wiring evidence:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` resolves and calls the canonical Spine callable from the registry.
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` imports `paradox.paradox_engine` after Import Truth is installed and invokes `ParadoxEngine.run(...)` when `envelope.input` declares a `paradox.trigger` payload.

Dry-run constraints:

- No provider SDK imports are introduced by C011.
- Network usage is prohibited; C011 contains no socket/client code and is covered by the no-network test posture.

