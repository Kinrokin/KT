# ADAPTER_LINEAGE_SYSTEM (forensic)

This document maps lineage/ancestry tracking for factory artifacts and (where present) adapters.

## 1) parent_hash is the primary lineage primitive

Many schema-bound artifacts include `parent_hash` and are content-hash addressed. This creates a hash-linked chain.

Concrete examples:
- Policy bundle: `kt.policy_bundle.v1` includes `parent_hash` (see `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/schemas/fl3_policy_bundle_schema.py`).
- Hash manifests and phase traces:
  - `kt.hash_manifest.v1` includes `parent_hash`
  - `kt.factory.job_dir_manifest.v1` includes `parent_hash`
  - `kt.factory.phase_trace.v1` includes `parent_hash`
  (constructed in `KT_PROD_CLEANROOM/tools/training/fl3_factory/manifests.py`).
- Derived artifacts:
  - `kt.immune_snapshot.v1`, `kt.epigenetic_summary.v1`, `kt.fitness_region.v1` all include `parent_hash` (see `derived.py`).

## 2) run_job.py builds a sequential parent_hash chain

In `KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py`, the factory updates `parent_hash` after each phase:
- jobspec hash → dataset hash → trace hash → judgement hash → train hash → eval hash → signal hash → derived fitness hash → promotion hash → phase_trace hash → manifests hash

This is the concrete lineage chain for a single job run.

## 3) Explicit “genetics” artifacts

The repo includes explicit schemas/manifests for “genetics-like” operations:
- `kt.breeding_manifest.v1` (see `KT_PROD_CLEANROOM/tools/training/fl3_factory/breeding.py`)

Forensic note:
- This exists as a manifest/receipt.
- Whether it is used for real weight-mixing or “recipe breeding” depends on which run_kind paths are executed (BREEDING) and what the training lane does (MRT-0 vs weight-bearing).

## 4) Temporal lineage graph schema exists

There is a schema:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.temporal_lineage_graph.v1.json`

Forensic note:
- The presence of a schema does not imply it is populated on the canonical factory lane today; verify by searching for actual file emission in job dirs.

