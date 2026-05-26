# Validation Commands

```bash
python -m pytest --no-cov -q tests/test_accountability_kernel_gates.py
python -m pytest --no-cov -q tests/test_formal_math_specialist_routing.py
python -m pytest --no-cov -q tests/test_adapter_isolation.py
python -m pytest --no-cov -q tests/test_cross_domain_translation_engine.py
python -m pytest --no-cov -q tests/test_fmea_repair_bid_matrix.py
python -m pytest --no-cov -q tests/test_repo_state_diff_contract.py
python scripts/validate_json_artifacts.py
python -m tools.operator.trust_zone_validate
python KT_PROD_CLEANROOM/tools/operator/taxonomy_drift_scan.py
git diff --check
```

If paths differ, use repo-native equivalents.
