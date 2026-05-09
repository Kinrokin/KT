"""PREP_ONLY template artifact. Cannot authorize runtime cutover, R6 opening, package promotion, or commercial activation claims."""

PREP_ONLY_INVARIANTS = {
  "authority": "PREP_ONLY",
  "cannot_authorize_commercial_activation_claims": true,
  "cannot_authorize_lobe_escalation": true,
  "cannot_authorize_package_promotion": true,
  "cannot_authorize_runtime_cutover": true,
  "cannot_mutate_trust_zone_law": true,
  "cannot_mutate_truth_engine_law": true,
  "cannot_open_r6": true
}
