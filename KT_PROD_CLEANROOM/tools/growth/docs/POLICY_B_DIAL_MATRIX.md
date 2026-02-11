# POLICY B DIAL MATRIX

Rule: If a dial exists, it must be schema-declared, logged, emitted as an artifact, and fed into a dataset row.

Schema source (authoritative)
- `KT_PROD_CLEANROOM/tools/growth/state/policy_b_variable_registry.json`

Artifact source (per epoch)
- `KT_PROD_CLEANROOM/tools/growth/state/plan_suggester.py` emits `plan_suggestion.json` with `signals.policy_b_values`.

Dataset source
- `KT_PROD_CLEANROOM/tools/growth/state/build_phaseA2_dataset.py` emits `kt_phaseA2_dataset.jsonl` with `policy_b_values`.

Matrix

| Dial | Schema | Artifact | Dataset | Notes |
| --- | --- | --- | --- | --- |
| paradox_pressure | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | bounded low |
| novelty_pressure | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | bounded low |
| verification_pressure | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | bounded low |
| time_pressure | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | bounded low |
| risk_pressure | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | bounded low |
| entropy_target | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | observe only |
| proof_density | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | measured only |
| entropy | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | computed only |
| coverage_fatigue | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | computed only |
| curvature | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | logged only |
| temperature | policy_b_variable_registry.json | plan_suggestion.json | kt_phaseA2_dataset.jsonl | fixed baseline |

Paradox handling flags (recorded as constants in registry and carried into plan_suggestion/dataset):
- pas_enabled
- apf_enabled
- pog_enabled
- belnap_states_logged
- both_events_counted

Governance invariants (recorded as constants in registry and carried into plan_suggestion/dataset):
- write_once_refusal
- invalid_domain_rejection
- missing_receipt_failure
- kt_live_proof_gate
- training_runtime_air_gap
- court_gated_recommendation_logic
