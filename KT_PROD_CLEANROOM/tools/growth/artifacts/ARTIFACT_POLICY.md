# Artifacts Policy

`KT_PROD_CLEANROOM/tools/growth/artifacts/` is intentionally **empty in git**.

All artifacts produced by running crucibles/epochs/evals/warehouse/distillation are generated **after clone** and must remain local to preserve:

- reproducibility discipline
- IP cleanliness
- avoidance of committing prompts/outputs/logs

This directory exists so tooling has a stable location to write outputs in a local environment.

