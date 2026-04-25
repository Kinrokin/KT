---
human_review_required: true
title: Publication Legal Pack
---

# Publication Legal Pack

## Disqualifier wording

A proof bundle is **disqualified** if any of the following occurs:

- freshness violation → exit code `20`
- schema drift → exit code `30`
- beta contamination → exit code `40`
- holdout leakage → exit code `50`
- runtime integrity failure → exit code `60`
- unsigned or unpublished bundle → exit code `70`

A disqualified bundle must never be described as counted evidence.

## Auditor verification commands (mock mode)

```bash
python tests/schema_validator.py --schema governance/RMR_SCHEMA_v1.json --manifest governance/H1_EXPERIMENT_MANIFEST.json
./scripts/proof_bundle_publish.sh --mock --run-id run-20260424-152430-bb49da8 --seed 42
python - <<'PY'
from pathlib import Path
import base64, hashlib, json
bundle = Path("bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz")
sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
sig_lines = Path("signatures/proof_bundle_run-20260424-152430-bb49da8.sig").read_text().splitlines()
assert base64.b64decode(sig_lines[0]).decode() == sha
assert sig_lines[1] == "mock-signer:mock-key-id"
print("mock signature verified")
PY
python - <<'PY'
import json
index = json.load(open("mock_rekor/index.json", "r", encoding="utf-8"))
assert any(item["bundle"] == "proof_bundle_run-20260424-152430-bb49da8.tar.gz" for item in index)
print("mock Rekor entry verified")
PY
```

## Auditor verification commands (production)

```bash
export COSIGN_KEY=/secure/path/cosign.key
export REKOR_URL=https://rekor.sigstore.dev
./scripts/proof_bundle_publish.sh --prod --run-id run-20260424-152430-bb49da8 --seed 42
cosign verify-blob --key "${COSIGN_KEY}.pub" --signature signatures/proof_bundle_run-20260424-152430-bb49da8.sig bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz
```

## Publication boundary

Permitted publication claims:
- the bundle is signed;
- the bundle is timestamped or mock-indexed;
- the proof object schema was frozen during counted execution;
- the counted run passed the listed acceptance checks.

Forbidden publication claims:
- “best AI”
- broad model superiority
- full-system superiority
- router/lobe superiority from this package alone
- Kaggle/math carryover
- enterprise readiness without separate evidence
