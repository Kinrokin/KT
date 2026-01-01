# W5.4 C020 System Audit (Pre-Change)

Scope: Growth-layer tooling only.

Audit intent:
- Preserve kernel sovereignty (no runtime imports; kernel invocation only via existing subprocess harness tooling).
- Constrain writes to tooling-only paths under `KT_PROD_CLEANROOM/tools/growth/`.
- Ensure C020 outputs are **receipt-only** and **draft-only** (no curriculum ingestion, no scoring, no interpretation).

Audit checkpoints:
- Writable targets limited to:
  - `KT_PROD_CLEANROOM/tools/growth/dream_loop/`
  - `KT_PROD_CLEANROOM/tools/growth/docs/`
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/`
- No runtime kernel files will be modified.
- No runtime organ imports in the dream loop.
- Kernel interaction occurs only through `tools/growth/crucible_runner.py` subprocess invocation.
- C020 does not open or parse kernel `stdout.json`/`stderr.log`; it consumes only the C019 summary and receipt pointers.
- Curriculum output is draft-only (hash lists) and is not signed or registered.

Result: PASS — proceed with C020 implementation within the boundaries above.

