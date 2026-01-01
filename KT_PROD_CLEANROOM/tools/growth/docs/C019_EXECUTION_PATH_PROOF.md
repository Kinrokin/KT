# C019 Execution Path Proof — Crucible Runner (Tooling-Only)

Canonical topology:

Growth Tool (C019)
→ Harness (subprocess)
→ Kernel Entry
→ Kernel Spine
→ Authorized Runtime Organs

Proof statements (mechanical, fail-closed):

1) C019 does not import runtime organs in the tool process.
- The runner invokes kernels only via `subprocess` and does not import kernel modules (`kt`, `core`, `schemas`, `memory`, `governance`, etc.) into the growth process.

2) Kernel invocation boundary is JSON-only.
- C019 passes exactly `{"input": "<string>"}` to the kernel harness via stdin.
- All other metadata (kernel_target, hashes, budgets, run_id, seed) is stored in runner artifacts and the append-only ledger, not injected into the kernel as extra top-level keys.

3) Per-run isolation.
- Each run uses a dedicated artifact root:
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/c019_runs/<kernel_target>/<run_id>/`
- V2 runs patch the runtime registry repo-root in-process (inside the subprocess) so the kernel’s state vault writes land under the per-run artifact root (no repo pollution).

