# C021 Execution Path Proof — Teacher Factory (Tooling-Only)

Canonical topology:

Teacher Factory (C021)
-> CurriculumCompiler.compile()
-> CurriculumSigner.sign()
-> CurriculumRegistry.register()

Proof notes:
- No runtime organs are imported or executed.
- No Entry→Spine invocation occurs.
- Inputs are metadata-only (epoch manifests + run records).
- Outputs are lossy, deterministic, and signed.

Commands executed (example package):
- Bundle creation: `KT_PROD_CLEANROOM/tools/growth/teacher_factory/bundles/BUNDLE-GOV-HONESTY-01.json`
- Compile + sign + register: one-shot tooling run (see verification report).

Artifacts written:
- `KT_PROD_CLEANROOM/tools/growth/artifacts/teacher_factory/packages/<package_id>.json`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/teacher_factory/packages/<package_id>.sig.json`
- `KT_PROD_CLEANROOM/tools/growth/artifacts/teacher_factory/curriculum_registry.jsonl`
