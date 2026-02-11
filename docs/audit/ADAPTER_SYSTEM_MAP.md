# ADAPTER_SYSTEM_MAP (forensic)

This document maps where “adapters” live, what an adapter is in the current system, how it is packaged, and how it is referenced by routing or selection logic.

## 1) Adapter types currently in play

### AdapterType A (FL4 MRT-0 canonical lane)
- Not neural weights.
- “Adapter” is a schema-bound *policy bundle* (`kt.policy_bundle.v1`) written to:
  - `job_dir/hypotheses/policy_bundles.jsonl`

### Weight-bearing adapters (MRT-1 / LoRA / etc.)
- There is code infrastructure that supports weight artifacts (e.g., `.safetensors`) in some manifests, but FL4 MRT-0 promotion explicitly forbids them in canonical runs.

## 2) Factory job directory (shadow root)

Created by `KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py` under:
- `KT_PROD_CLEANROOM/exports/adapters_shadow/...`

Key artifacts in a canonical job_dir include:
- `job.json` (`kt.factory.jobspec.*`)
- `dataset.json` (`kt.factory.dataset.v1`)
- `reasoning_trace.json` (`kt.reasoning_trace.v1`)
- `judgement.json` (`kt.factory.judgement.v1`)
- `train_manifest.json` (`kt.factory.train_manifest.v1`) — MRT-0 means this points to policy bundles, not weights
- `hypotheses/policy_bundles.jsonl` (`kt.policy_bundle.v1` records)
- `eval_report.json` (`kt.factory.eval_report.v2`)
- `signal_quality.json` (`kt.signal_quality.v1`)
- `immune_snapshot.json` / `epigenetic_summary.json` / `fitness_region.json`
- `promotion.json` (`kt.factory.promotion.v1`)
- `phase_trace.json` (`kt.factory.phase_trace.v1`)
- `hash_manifest.json` (`kt.hash_manifest.v1`)
- `job_dir_manifest.json` (`kt.factory.job_dir_manifest.v1`)

## 3) Promoted package + discoverability (promoted root)

Promotion materialization is handled by:
- `KT_PROD_CLEANROOM/tools/verification/fl4_promote.py`

Promoted packages are content-addressed under:
- `KT_PROD_CLEANROOM/exports/adapters/<adapter_id>/<adapter_version>/<content_hash>/...`

Discoverability index:
- `KT_PROD_CLEANROOM/exports/adapters/promoted_index.json` (`kt.promoted_index.v1`)

## 4) Runtime routing (Council router)

Runtime routing lives in:
- `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py`

Forensic note:
- This runtime routing system is primarily about provider selection and runtime invocation discipline.
- It is not the FL4 MRT-0 factory selection mechanism (which is offline and receipt-bound).

