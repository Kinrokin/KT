# LEARNING_SIGNAL_INDEX (forensic)

Goal: enumerate every *learning trigger* / *signal* / *selection gate* that exists in the current repo, and show where it is produced and consumed.

This index is grounded in concrete code paths and on-disk artifacts (schema-bound JSON/JSONL).

## 1) Factory lane (FL3/FL4 MRT-0) — policy-bundle evolution (no weights)

### Hypothesis generation (genotype → policy bundle)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/hypotheses.py`
  - `build_policy_bundles(job_id, seed, parent_hash, count)`
  - Output: `hypotheses/policy_bundles.jsonl` (written by `KT_PROD_CLEANROOM/tools/training/fl3_factory/train.py`)
  - Signal type: structured categorical genotype (5 genes) per `kt.policy_bundle.v1`
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/eval.py` (loads the JSONL)
  - `KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py` (requires schema-valid bundles in canonical lane)

### Deterministic scoring (utility floor + probes)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/eval.py`
  - Output: `eval_report.json` (`kt.factory.eval_report.v2`) containing:
    - `utility_floor_score` (float [0,1])
    - `utility_floor_pass` (bool)
    - `metric_bindings[]` (metric id + version/schema/impl hashes)
    - `metric_probes[]` (independent probe agreement + delta)
    - `probe_policy` (tolerance + fail_on_disagreement)
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/promote.py` (requires `final_verdict == PASS`)
  - `KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py` (replays checks and fails closed on mismatch)

### Signal-quality gate (risk/strikes)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/signal.py`
  - Output: `signal_quality.json` (`kt.signal_quality.v1`) with `risk_estimate`, `governance_strikes`, `status`
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py` (tournament entrant gating)
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/derived.py` (fitness-region derivation)

### Derived fitness region (A/B/C)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/derived.py`
  - Outputs (all schema-bound):
    - `immune_snapshot.json` (`kt.immune_snapshot.v1`)
    - `epigenetic_summary.json` (`kt.epigenetic_summary.v1`)
    - `fitness_region.json` (`kt.fitness_region.v1`, `fitness_region ∈ {A,B,C}`)
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/promote.py` (promotion forbidden unless `fitness_region == A`)

### Promotion decision (PROMOTE/REJECT)
- Producer: `KT_PROD_CLEANROOM/tools/training/fl3_factory/promote.py`
  - Output: `promotion.json` (`kt.factory.promotion.v1`)
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/verification/preflight_fl4.py` (runs promotion if decision is PROMOTE)
  - `KT_PROD_CLEANROOM/tools/verification/fl4_promote.py` (atomic materialization + promoted index update)

### Promotion materialization (content-addressed, atomic)
- Producer: `KT_PROD_CLEANROOM/tools/verification/fl4_promote.py`
  - Writes promoted package under `KT_PROD_CLEANROOM/exports/adapters/...`
  - Updates `KT_PROD_CLEANROOM/exports/adapters/promoted_index.json` (`kt.promoted_index.v1`)

### Determinism / manifest gates
- Producer/Consumer:
  - `KT_PROD_CLEANROOM/tools/training/fl3_factory/manifests.py` emits:
    - `hash_manifest.json` (`kt.hash_manifest.v1`)
    - `job_dir_manifest.json` (`kt.factory.job_dir_manifest.v1`)
    - `phase_trace.json` (`kt.factory.phase_trace.v1`)
  - `KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py` verifies these deterministically.
  - `KT_PROD_CLEANROOM/tools/verification/fl4_determinism_canary.py` enforces stable manifest root hash for a canonical job.

## 2) Growth lane (crucibles/epochs) — coverage + PASS/FAIL pressure

### Crucible execution outcome + coverage evidence
- Producer:
  - `KT_PROD_CLEANROOM/tools/growth/crucible_runner.py` (subprocess wrapper; prints summary JSON to stdout)
  - `KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py` (core runner; writes per-run artifacts)
- Artifacts:
  - `.../c019_runs/<kernel_target>/<run_id>/crucible_coverage.json` (coverage proof; validated fail-closed for non-coverage kernels)
  - epoch-local logs under `.../epochs/<epoch_id>/<crucible_id>/{stdout.json,stderr.log,run_record.json}`
- Consumer(s):
  - `KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py` (aggregates, fail-closes if coverage missing)
  - `KT_PROD_CLEANROOM/tools/growth/e2e_gate.py` (requires milestone PASS + pressure OPERATIONAL)

## 3) Multi-axis "cognitive fitness" / discovery battery lane (FL3.2 receipts)

These exist as schema-bound artifacts and verifiers, but are not the scoring surface used by FL4 MRT-0 promotion.

- `KT_PROD_CLEANROOM/tools/verification/run_discovery_battery.py`
- `KT_PROD_CLEANROOM/tools/verification/compute_cognitive_fitness.py`
- `KT_PROD_CLEANROOM/AUDITS/DISCOVERY_BATTERY.json`, `ANCHOR_REFERENCE_SET.json`, `COGNITIVE_FITNESS_POLICY.json`
