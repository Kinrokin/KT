# C014 Execution Path Proof (Dry-Run, No-Network)

Canonical runtime path (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`):

- Entry: `kt.entrypoint:invoke`
- Spine: `core.spine:run`
- Council: `council.council_router:CouncilRouter.plan` and `council.council_router:CouncilRouter.execute`

Wiring evidence:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` installs Import Truth, asserts invariants, and then resolves + calls the canonical Spine callable from the runtime registry.
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` imports `council.council_router` only after Import Truth is installed and invokes CouncilRouter only when `envelope.input` contains a JSON object declaring one of:
  - `schema_id == "council.request"` → `CouncilRouter.plan(...)`
  - `schema_id == "council.plan"` → `CouncilRouter.execute(...)`
- No other runtime module imports CouncilRouter directly; there is no bypass path around the Spine dispatcher.

Dry-run / safety constraints:

- C014 refuses live execution (`mode == LIVE_REQUESTED`) with explicit refusal codes; it does not fabricate outputs.
- Network usage is prohibited; tests hard-block `socket` to enforce fail-closed behavior.

