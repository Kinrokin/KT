# MOTION_TRANSITIONS_V1 and MOTION_METRICS_V1 Schema

## transitions.json
- schema: "MOTION_TRANSITIONS_V1"
- scope: "CRUCIBLE" | "EPOCH" | "CYCLE"
- id: crucible_id / epoch_id / cycle_id
- counts:
    - domain_transitions: { "D:A->D:B": int, ... }
    - subdomain_transitions: { "S:A->S:B": int, ... }
    - microdomain_transitions: { "M:A->M:B": int, ... }
- matrices (optional):
    - domain_matrix: { "rows": [...], "cols": [...], "values": [[...]] }
- missing_tag_count: int
- trace_head_hash: str
- ledger_entry_hash: str

## motion_metrics.json
- schema: "MOTION_METRICS_V1"
- scope: "CRUCIBLE" | "EPOCH" | "CYCLE"
- id: crucible_id / epoch_id / cycle_id
- metrics:
    - domain_hop_rate: float
    - subdomain_hop_rate: float
    - mean_revisit_latency_steps_domain: float
    - mean_revisit_latency_steps_subdomain: float
    - max_revisit_latency_steps_domain: int
    - path_length_mean: float (optional)
    - hop_entropy_domain: float
    - paradox_entry_count: int (optional)
    - paradox_resolution_count: int (optional)
- proof:
    - trace_head_hash: str
    - ledger_entry_hash: str
