# C020 Execution Path Proof (Tooling-Only)

Canonical topology for C020:

`DreamSpec` → (deterministic candidate generation) → (materialize crucible YAML as artifacts) → `C019 crucible_runner.py` (subprocess) → receipt refs → `C021 curriculum_compiler.compile_bundle` (hash-only draft) → `DreamRunResult` (receipt-only)

Key constraint: C020 never imports or executes runtime organs; kernel execution occurs only via the existing C019 subprocess harness.

