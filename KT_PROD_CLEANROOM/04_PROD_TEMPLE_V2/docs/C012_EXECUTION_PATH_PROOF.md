# C012 Execution Path Proof (Dry-Run, No-Network)

Canonical runtime path (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`):

- Entry: `kt.entrypoint:invoke`
- Spine: `core.spine:run`
- Temporal: `temporal.temporal_engine:TemporalEngine.(create_fork|replay)`

Wiring evidence:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` resolves and calls the canonical Spine callable from the runtime registry.
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` imports `temporal.temporal_engine` only after Import Truth is installed and invokes TemporalEngine only when `envelope.input` declares one of:
  - `temporal.fork.request`
  - `temporal.replay.request`
- No other runtime module imports TemporalEngine directly; there is no bypass path around the Spine dispatcher.

Dry-run constraints:

- No provider SDK imports are introduced by C012.
- Network usage is prohibited; TemporalEngine contains no socket/client code and tests hard-block `socket` to enforce fail-closed behavior.

