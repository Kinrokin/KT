# C015 Execution Path Proof (Dry-Run, No-Network)

Canonical runtime path (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`):

- Entry: `kt.entrypoint:invoke`
- Spine: `core.spine:run`
- Cognition: `cognition.cognitive_engine:CognitiveEngine.plan` and `cognition.cognitive_engine:CognitiveEngine.execute`

Wiring evidence:

- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` installs Import Truth, asserts invariants, and then resolves + calls the canonical Spine callable from the runtime registry.
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` imports `cognition.cognitive_engine` only after Import Truth is installed and invokes CognitiveEngine only when `envelope.input` contains a JSON object declaring one of:
  - `schema_id == "cognition.request"` → `CognitiveEngine.plan(...)`
  - `schema_id == "cognition.plan"` → `CognitiveEngine.execute(...)`
- No other runtime module imports CognitiveEngine directly; there is no bypass path around the Spine dispatcher.

Dry-run / safety constraints:

- Cognition is deterministic and bounded; it produces hashes and numeric summaries only.
- Network usage is prohibited; tests hard-block `socket` to enforce fail-closed behavior.
- Cognition emits no raw reasoning traces and performs no state persistence.

