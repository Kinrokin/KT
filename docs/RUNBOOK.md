# KT Reproducibility Runbook

Use the required environment for the workflow you are validating. A separately
frozen proof packet retains its own dependency lock, commands and acceptance
criteria. The examples below describe existing offline growth and measurement
entrypoints; running them is not proof of training or whole-system completion.

## 1) Select an external work area

From the repository root, choose an absolute directory outside this checkout.
The shell examples use Linux/WSL paths:

```bash
export KT_RUN_ROOT="$HOME/kt-runs/local-growth"
export KT_GROWTH_ARTIFACTS_ROOT="$KT_RUN_ROOT/growth"
export PYTHONPATH="$PWD/KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src:$PWD/KT_PROD_CLEANROOM"
export PYTHONDONTWRITEBYTECODE=1
export KT_LIVE=0
mkdir -p "$KT_RUN_ROOT"
```

The growth root contains `c019_runs/`, `epochs/`, `salvage/` and the C019
`ledgers/` directory. Keep downloaded packets, model exports and scratch outside
source as well. The old ignored artifact/ledger directories remain compatibility
fallbacks when the override is unset. Other training, factory and operator
programs have their own output contracts; this variable is not a global override
for every KT tool.

Preserve prior runs. Epochs use their existing collision/resume rules; do not
delete evidence to make a command pass. Use absolute paths for the override.
Supported growth entrypoints resolve a relative value against
`KT_PROD_CLEANROOM`, but that compatibility behavior places output in the source
checkout and is not the documented external-work-area flow.

## 2) One crucible run

The supported CLI is the top-level growth runner. The similarly named file in
`crucibles/` is its implementation library.

```bash
python KT_PROD_CLEANROOM/tools/growth/crucible_runner.py \
  --crucible KT_PROD_CLEANROOM/tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml \
  --kernel V2_SOVEREIGN
```

The JSON summary identifies the run ID, outcome and artifact directory. Inspect
that outcome; successful process startup alone is not a passing crucible.

## 3) Epoch preflight and execution

Preflight checks the plan and existing output history without invoking a kernel:

```bash
python -m tools.growth.orchestrator.epoch_orchestrator \
  --epoch KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json \
  --preflight --no-auto-bump
```

Execute the same plan when its prerequisites are satisfied:

```bash
python -m tools.growth.orchestrator.epoch_orchestrator \
  --epoch KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json \
  --mode salvage
```

Record the actual epoch ID from the output, including any automatically added
`_RUN<N>` suffix. Set `KT_EPOCH_DIR` to that exact directory under
`$KT_GROWTH_ARTIFACTS_ROOT/epochs`. An explicit `--salvage-out-root` still takes
precedence when a separate external salvage destination is required.

## 4) Evaluate existing artifacts

The evaluation harness requires the epoch manifest, each participating run
record, the artifact root and a delta ledger. The bundled honesty suite has
three fixed `input_refs`; verify those IDs are present in this run and match the
provided records. Missing or mismatched evidence must fail closed. Do not change
the suite expectations simply to obtain a pass.

After setting `KT_EPOCH_DIR` to the exact emitted epoch directory:

```bash
: "${KT_EPOCH_DIR:?Set KT_EPOCH_DIR to the emitted epoch directory}"
python KT_PROD_CLEANROOM/tools/growth/eval_harness/eval_runner.py \
  --suite KT_PROD_CLEANROOM/tools/growth/eval_harness/SUITE-GOV-HONESTY-01.json \
  --epoch-manifest "$KT_EPOCH_DIR/epoch_manifest.json" \
  --run-record "$KT_EPOCH_DIR/CRU-GOV-HONESTY-01/run_record.json" \
  --run-record "$KT_EPOCH_DIR/CRU-GOV-HONESTY-02/run_record.json" \
  --run-record "$KT_EPOCH_DIR/CRU-GOV-HONESTY-03/run_record.json" \
  --artifacts-root "$KT_GROWTH_ARTIFACTS_ROOT" \
  --delta-ledger "$KT_GROWTH_ARTIFACTS_ROOT/ledgers/eval_deltas.jsonl"
```

Eval+ reads an epoch and its sibling C019 evidence without kernel invocation:

```bash
python KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py \
  --epoch-dir "$KT_EPOCH_DIR" \
  --epoch-id "$(basename "$KT_EPOCH_DIR")" \
  --out "$KT_RUN_ROOT/eval-plus/$(basename "$KT_EPOCH_DIR").json"
```

The input epoch must remain within the configured growth root's `epochs/`
directory. Eval+ refuses overwrite; `--allow-existing` only permits an existing
result whose hash matches the recomputed result. Inspect the result's status and
the selected metric bounds; default bounds alone do not establish capability.

## 5) Verification scope

Output-path regression fixtures live in
`KT_PROD_CLEANROOM/tools/growth/orchestrator/tests/test_epoch_orchestrator.py`
and `KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/tests/test_eval_harness_plus.py`.
Select the appropriate test battery and keep its temporary/cache outputs in a
fresh external test directory. A general `pytest` invocation also includes other
factory/runtime tests and is not a synonym for this bounded path check.

Historical relocation manifests preserve old and current artifact locations and
hashes. Resolve archived paths through those manifests; do not rewrite old
receipts, copy archives into source or discard unfinished work. No command in
this runbook establishes independent benchmark, training or release acceptance.

## 6) Registry verification

Run `python -B -m scripts.repo_pristine_census --check` to inspect the existing
registry and retained reports without regenerating them. A registry registration
or source classification does not authorize an execution. The current packet
contract and manifest explicitly select no execution packet; the historical
BUD100, Pareto, KTCF and CFFIX packets remain readable evidence.

The registry preserves `sha256` as the historical registration digest.
`current_file_sha256` checks the exact current checkout bytes using the repository's
LF checkout attributes, including the default text rule; the checker never normalizes bytes silently. The registry
excludes only its own current digest to avoid a self-hash cycle. Its reconciliation
base identifies the source parent, not a future commit or an accepted runtime.

After a reviewed source change, update its current file binding and register any
new tracked file before running the checks. Preserve historical digests and the
review evidence outside source. Historical packet/census writers require explicit
migration to this binding contract before reuse; running their old generation
paths may restore stale selections and must fail validation.
