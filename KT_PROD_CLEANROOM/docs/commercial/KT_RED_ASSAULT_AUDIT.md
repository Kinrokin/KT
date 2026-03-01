# KT Red Assault Audit (Adversarial Evaluation + Failure Library)

This offering runs a bounded, governed red-assault lane and produces a client-deliverable failure library with replayable evidence.

SKU: `SKU_RA`  
Lane: `red_assault.v1`

## Inputs
- A pinned KT checkout (e.g. `KT_V1_SEALED_20260217`).
- An agreed red-assault pack id (hash-referenced / governed).
- Agreed run parameters: pressure level, sample count, seed.

## Operator Command (Preferred)
- `python -m tools.operator.kt_cli --profile v1 red-assault --pack-id <id> --pressure-level <low|med|high> --sample-count <n> --seed <int>`

## Outputs
Each run produces the standard delivery bundle plus red-assault reports:
- `reports/red_assault_summary.json`
- `reports/failure_taxonomy.json`
- `reports/top_failures.jsonl`

Reference spec:
- `KT_PROD_CLEANROOM/docs/commercial/KT_DELIVERY_BUNDLE_SPEC.md`

## Typical Timeline (planning estimate)
- +2–5 business days depending on pack size, sampling, and review cadence.

## Pricing Logic (framework; no numbers)
- Base fee + scale factor for sample count and pressure level (compute + analysis).

## Acceptance Criteria
- secret scan `PASS` and delivery linter `PASS`.
- Reports listed above exist and are schema-valid for the lane.
- No sensitive payloads embedded in canonical repo surfaces; dual-use content is hash-referenced only.
