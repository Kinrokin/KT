# C006 Second-Host Runbook

Purpose: execute the deferred `C006` reentry immediately when a second host is available.

## Inputs

- `KT_PROD_CLEANROOM/reports/post_wave5_c006_friendly_host_handoff_pack.json`
- `KT_PROD_CLEANROOM/reports/post_wave5_c006_second_host_submission_template.json`
- `KT_PROD_CLEANROOM/reports/kt_independent_replay_recipe.md`
- `KT_PROD_CLEANROOM/reports/c006_deferral_heartbeat.json`

## Steps

1. Build or stage the second-host bundle with `python -m tools.operator.build_c006_second_host_bundle`.
2. Move the bundle to the second host without adding hidden dependencies.
3. Run the detached verifier steps described in `kt_independent_replay_recipe.md`.
4. Fill the submission template with the second-host result, machine fingerprint, and receipt refs.
5. Place the completed return file at `KT_PROD_CLEANROOM/reports/imports/post_wave5_c006_second_host_return.json`.
6. Run the rerun checklist in `docs/operator/C006_VALIDATOR_RERUN_CHECKLIST.md`.

## Hard boundaries

- Do not claim `E2` until the return file exists and the validators pass.
- Do not narrate verifier-only second-host success as broad runtime proof.
- Do not widen comparative or commercial claims from the second-host run alone.
