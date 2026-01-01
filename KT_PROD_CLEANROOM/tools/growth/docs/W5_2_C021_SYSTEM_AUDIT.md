# W5.2 C021 System Audit (Pre-Change)

Scope: Growth-layer tooling only.

Audit intent:
- Preserve kernel sovereignty (no runtime imports, no Entry→Spine invocation).
- Constrain writes to tooling-only paths under `KT_PROD_CLEANROOM/tools/growth/`.
- Enforce deterministic, lossy, signed curriculum compilation with append-only registry.

Audit checkpoints:
- Writable targets limited to:
  - `KT_PROD_CLEANROOM/tools/growth/teacher_factory/`
  - `KT_PROD_CLEANROOM/tools/growth/docs/`
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/`
- No runtime kernel files will be modified.
- No runtime organ imports in the teacher process.
- No raw runtime outputs (stdout/stderr/traces) are accepted as inputs.

Result: PASS — proceed with C021 implementation within the boundaries above.
