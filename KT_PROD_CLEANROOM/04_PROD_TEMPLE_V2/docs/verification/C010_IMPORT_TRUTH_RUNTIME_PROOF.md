# C010 Import Truth Runtime Enforcement Proof

Single source of truth:
- Registry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
  - `runtime_import_roots` allowlist
  - `organs_by_root` mapping
  - `import_truth_matrix`

Runtime import-time guard (fail-closed):
- Implementation: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/import_truth_guard.py`
- Installed by:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py`
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`

Proof mechanism:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_no_network_dry_run.py` asserts:
  - importing a non-allowlisted internal root fails closed
  - a synthetic internal importer triggers an import-matrix violation and fails closed

