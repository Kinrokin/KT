# C018 Execution Path Proof — Epoch Orchestrator (Tooling-Only)

Canonical topology:

Growth Tool (C018 Orchestrator)
-> C019 Runner (subprocess)
-> Kernel Entry
-> Kernel Spine
-> Authorized Runtime Organs

Proof notes:
- Orchestrator invokes C019 via subprocess only; it does not import runtime organs.
- Runner sends exactly `{"input":"<string>"}` to the kernel via stdin.
- Kernel writes receipts into a per-run artifacts directory (no repo pollution).

Commands executed (example epoch):
- `python -m KT_PROD_CLEANROOM.tools.growth.orchestrator.epoch_orchestrator --epoch KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json --mode normal`

Result:
- Epoch summary written to `KT_PROD_CLEANROOM/tools/growth/artifacts/epochs/EPOCH-0001-GOV-HONESTY/epoch_summary.json`
