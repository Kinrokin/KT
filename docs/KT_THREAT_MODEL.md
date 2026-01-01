# KT Threat Model (Baseline)

Primary risks KT defends against:

- Silent fallback behavior (must fail closed)
- Hidden execution paths / entrypoint drift
- Secrets leakage into committed artifacts
- Context/receipt bloat (bounded, schema-validated surfaces)
- Non-deterministic replay

Primary mitigations are enforced via constitutional guards, schema perimeters, and append-only evidence ledgers.

