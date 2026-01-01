# W5.4 C020 Verification (Dream Loop)

This report is **evidence-first** and **measurement-only**. C020 generates bounded crucibles (inputs), executes them via C019 subprocess harness, and emits **receipt references + hash-only curriculum drafts**.

## What was implemented

- C020 implementation: `KT_PROD_CLEANROOM/tools/growth/dream_loop/`
- Constitutional guard: `KT_PROD_CLEANROOM/tools/growth/check_c020_constitution.py`

## What is proven

- Tooling-only: no runtime imports from C020 modules (guard PASS).
- Deterministic candidate generation (unit tests).
- One dream run executed with ≥2 candidates.
- Outputs contain no kernel stdout/stderr bodies; only run IDs, receipt refs, and draft hashes.

## Commands executed

- Unit tests:
  - `python -m unittest -q KT_PROD_CLEANROOM/tools/growth/dream_loop/tests/test_dream_loop.py`
- Constitutional guard:
  - `python KT_PROD_CLEANROOM/tools/growth/check_c020_constitution.py KT_PROD_CLEANROOM/tools/growth/dream_loop`
- One dream run:
  - `python KT_PROD_CLEANROOM/tools/growth/dream_loop/dream_runner.py --spec KT_PROD_CLEANROOM/tools/growth/artifacts/dream_loop/DREAM-0002-GOV-HONESTY/dream_spec.yaml`

## Run evidence (receipt-only)

- Dream spec:
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/dream_loop/DREAM-0002-GOV-HONESTY/dream_spec.yaml`
- Dream result (receipt-only + draft-only):
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/dream_loop/DREAM-0002-GOV-HONESTY/dream_result.json`
- Candidate receipt roots (C019 artifact dirs):
  - `tools/growth/artifacts/c019_runs/V2_SOVEREIGN/76d40f7ca8dc0cbf97b061650350f687eb66daf3866fecc82685dccbd8c297a4`
  - `tools/growth/artifacts/c019_runs/V2_SOVEREIGN/d36fa8b28353371f9d91c2676a505fa5623c1ab9e4b20bef14a3864cae46a736`
- Curriculum draft (hash-only; not signed; not registered):
  - `KT_PROD_CLEANROOM/tools/growth/artifacts/dream_loop/DREAM-0002-GOV-HONESTY/curriculum_draft.json`

## Fail-closed posture

- If any subprocess invocation fails, or if C019 does not produce the expected hash-only summary, C020 halts with an exception (no fallback).
- C020 does not score or interpret outcomes; it only records what happened.

