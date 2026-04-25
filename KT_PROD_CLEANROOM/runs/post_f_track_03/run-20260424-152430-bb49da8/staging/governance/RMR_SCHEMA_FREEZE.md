---
human_review_required: true
title: RMR Schema Freeze Law v1
---

# RMR Schema Freeze Law v1

This document freezes `governance/RMR_SCHEMA_v1.json` for Track 03 and any counted H1 execution.

## Freeze rule

1. The canonical schema file is `governance/RMR_SCHEMA_v1.json`.
2. Its expected digest is:

```text
7e6024cca27146f7eee6d169ee0de41342b2cd34cc798ecfe057cdd2be93c219
```

3. Any counted execution that observes a different digest MUST fail with exit code `30`.
4. Amendments are allowed only through the multisig workflow below and are never retroactive to an already-issued counted proof bundle.

## Multisig amendment workflow

Use the exact branch naming convention below:

```bash
git checkout main
git pull --ff-only origin main
git checkout -b governance/rmr-schema-amend-v1-<ticket>
python tests/schema_validator.py --schema governance/RMR_SCHEMA_v1.json --examples
git add governance/RMR_SCHEMA_v1.json governance/RMR_SCHEMA_FREEZE.md governance/multisig_approvals.json
git commit -m "governance: amend RMR schema v1 for <ticket>"
git push -u origin governance/rmr-schema-amend-v1-<ticket>
```

Create or update `governance/multisig_approvals.json` with at least `required` mock or production signatures.

```bash
cat governance/multisig_approvals.json
```

Merge only after independent review and after the approvals count is satisfied:

```bash
python scripts/stage_and_promote.sh --check-multisig-only
```

After merge to `main`, update:
- `governance/H1_EXPERIMENT_MANIFEST.json.expected_schema_digest`
- `staging/manifest.json`
- all downstream receipts that reference the old digest.

## Branch law

- `main` is canonical.
- `expansion/*` branches are `LAB_ONLY` until merged.
- No counted artifact may claim canonical standing from an expansion branch without a protected merge.

## Auditor commands

```bash
python tests/schema_validator.py --schema governance/RMR_SCHEMA_v1.json --manifest governance/H1_EXPERIMENT_MANIFEST.json
python - <<'PY'
from pathlib import Path
import hashlib
p = Path("governance/RMR_SCHEMA_v1.json")
print(hashlib.sha256(p.read_bytes()).hexdigest())
PY
```

## Amendment rejection triggers

Reject the amendment if any of the following is true:
- a required field is removed without migration notes;
- the schema broadens accepted values for `reason_codes`, `why_not`, or `provider_calls` without review;
- the amendment is proposed after a counted run has begun;
- the multisig count is below the configured threshold;
- tests do not pass on Ubuntu 22.04 / Python 3.11 / bash.

## Notes

This freeze law exists to stop silent reinterpretation of proof objects mid-campaign. The schema may evolve later, but never during a counted H1 court.
