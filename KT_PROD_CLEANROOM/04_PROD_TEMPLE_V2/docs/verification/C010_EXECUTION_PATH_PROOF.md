# C010 Execution Path Proof (V2 Substrate Mode)

Canonical runtime route (declared, no discovery):
- Registry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- Entry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py` (`invoke`)
- Spine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py` (`run`)

Proof mechanism:
- Dry-run test executes Entry → Spine and asserts deterministic structural outcome:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_no_network_dry_run.py`

Notes (non-claims):
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/entrypoint.py` exists for historical wiring (C001), but is not the canonical Entry and is not referenced by the runtime registry.

