# KT Reproducibility Runbook (No Artifacts Committed)

This repo is designed to be **provable** and **fail-closed**.

By policy:
- Runtime artifacts are written under `KT_PROD_CLEANROOM/tools/growth/artifacts/` and are **gitignored**.
- Tooling ledgers are written under `KT_PROD_CLEANROOM/tools/growth/ledgers/` and are **gitignored**.

## 1) Quick local proof (offline)

From repo root:

```bash
python -m pytest -q
```

## 2) One canonical crucible run (V2_SOVEREIGN)

Run a single crucible against the V2 kernel via the tooling harness:

```bash
python KT_PROD_CLEANROOM/tools/growth/crucibles/crucible_runner.py --crucible KT_PROD_CLEANROOM/tools/growth/crucibles/CRU-GOV-HONESTY-01.yaml --kernel V2_SOVEREIGN
```

Expected side effects (local only, not committed):
- New directory under `KT_PROD_CLEANROOM/tools/growth/artifacts/c019_runs/`
- Append(s) under local ledgers in `KT_PROD_CLEANROOM/tools/growth/ledgers/`

## 3) Batch run (epoch) + evaluation loop

```bash
python KT_PROD_CLEANROOM/tools/growth/orchestrator/epoch_orchestrator.py --epoch-plan KT_PROD_CLEANROOM/tools/growth/epochs/EPOCH-0001-GOV-HONESTY.json
```

Then evaluate:

```bash
python KT_PROD_CLEANROOM/tools/growth/eval_harness/eval_runner.py --suite KT_PROD_CLEANROOM/tools/growth/eval_harness/SUITE-GOV-HONESTY-01.json --artifacts-root KT_PROD_CLEANROOM/tools/growth/artifacts
```

Then (optional) run eval+:

```bash
python KT_PROD_CLEANROOM/tools/growth/eval_harness_plus/eval_plus_runner.py --artifacts-root KT_PROD_CLEANROOM/tools/growth/artifacts
```

## Notes

- If any step cannot be proven (missing artifacts, kernel identity mismatch, schema mismatch), tooling must halt fail-closed.
- If you run on Windows with `core.autocrlf=true`, this repo includes `.gitattributes` to keep canonical text files in LF for stable hashing.
