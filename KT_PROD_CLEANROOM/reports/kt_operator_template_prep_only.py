"""PREP_ONLY template artifact. Cannot authorize runtime cutover, R6 opening, package promotion, or commercial activation claims."""

PREP_ONLY_INVARIANTS = {'authority': 'PREP_ONLY', 'cannot_authorize_runtime_cutover': True, 'cannot_open_r6': True, 'cannot_authorize_lobe_escalation': True, 'cannot_authorize_package_promotion': True, 'cannot_authorize_commercial_activation_claims': True, 'cannot_mutate_truth_engine_law': True, 'cannot_mutate_trust_zone_law': True}
