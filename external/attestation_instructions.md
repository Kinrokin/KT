# Independent External Re-Audit Attestation Instructions

This package is for an outside reviewer. KT cannot self-author or self-satisfy the independent attestation gate.

Current blocked state:

```text
H06_EXTERNAL_REAUDIT_DEFERRED__INDEPENDENT_ATTESTATION_REQUIRED
```

The reviewer should inspect the evidence bundle, run the listed commands, compare claims against the claim ceiling, and return a verdict of `ACCEPTED`, `DEFERRED`, or `REJECTED` using `external/attestation_template.json`.

An accepted attestation does not authorize commercial claims by itself. It only permits KT to rerun the external re-audit attempt lane with independent evidence present.
