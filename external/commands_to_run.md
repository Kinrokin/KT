# External Re-Audit Commands To Run

Run from the repository root unless noted otherwise.

```bash
cd KT_PROD_CLEANROOM
python -m tools.operator.trust_zone_validate
python -m tools.operator.validate_external_attestation --require-accepted
python -m pytest --no-cov -q tests/operator/test_validate_external_attestation.py
python -m pytest --no-cov -q tests/operator/test_run_kt_external_reaudit_attempt.py
git diff --check
```

If `validate_external_attestation --require-accepted` fails because the attestation is missing, the correct verdict is `DEFERRED`, not accepted.
