---
human_review_required: true
title: KT E2E Lawful Commitment Superiority Playbook
run_id: run-20260424-152430-bb49da8
generated_utc: 2026-04-24T15:27:00Z
---

# KT E2E Lawful Commitment Superiority Playbook

This playbook is the commit-ready operating document for Track 03. It is intentionally concrete, bounded, fail-closed, and optimized for a standard Linux environment (Ubuntu 22.04 / Python 3.11 / bash). It stages all counted work beneath:

```text
KT_PROD_CLEANROOM/runs/post_f_track_03/run-20260424-152430-bb49da8/staging
```

It is designed to do the following without endless cleanup loops:

1. freeze Track 02 footing,
2. harden proof-law objects,
3. bind current HEAD freshness,
4. add the minimum lawful runtime bridge,
5. enforce holdout, beta, and anti-shortcut rules,
6. produce a deterministic proof bundle,
7. run exactly one smoke lane and one counted H1 lane,
8. fail closed on any disqualifier, and
9. preserve a clean promotion path.

---

## 1. Constitutional goals

The campaign is not allowed to morph into a broader product or civilization claim. This package exists to lawfully answer a narrower question:

> Can KT run one bounded H1 proof attempt with fresh, schema-frozen, receipt-backed evidence while preserving all current governance truths and fail-closed boundaries?

The answer must be derived from artifacts, not narration.

### Hard rules

- H0 canonical truth remains sacred.
- Counted artifacts use RFC3339 UTC timestamps with `Z`.
- Randomness defaults to `--seed 42`.
- Historical receipts are supporting-only; they do not override current-head truth.
- `main` is canonical. `expansion/*` branches are non-authoritative until merged.
- Files marked `human_review_required: true` are not auto-promoted.
- Production signing is opt-in. Mock mode is the default.

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | success |
| 10 | preflight failure |
| 20 | freshness disqualifier (stale head) |
| 30 | schema drift disqualifier |
| 40 | beta contamination disqualifier |
| 50 | holdout leakage disqualifier |
| 60 | runtime integrity disqualifier |
| 70 | publishability disqualifier |
| 99 | unknown error |

---

## 2. Repository layout

```text
staging/
  KT E2E Lawful Commitment Superiority Playbook.md
  governance/
  reports/
  packet/
  training/
  runtime/
  council/
  scripts/
  ci/
  tests/
  docs/
  appendix/
  keys/
  agents/
  kimi_jobs/
  schedules/
  canonical/
  data/
  mock_rekor/
  samples/
  staging/manifest.json
```

### Why the layout matters

- `governance/` holds frozen laws and manifest truth.
- `reports/` holds current-head and run receipts.
- `packet/` holds bounded input rows.
- `runtime/` contains the thinnest lawful execution shim.
- `scripts/` are the only shell entrypoints required for smoke, counted, publication, and promotion.
- `tests/` enforce acceptance checks.
- `canonical/` is the promotion target, not the staging workspace itself.

---

## 3. Determinism contract

Determinism is non-negotiable. Every artifact in this package follows the same rules:

1. SHA256 only, lowercase hex.
2. Sorted file ordering before any manifest or tar/gzip digest.
3. Deterministic tarball settings:

```bash
tar --sort=name --mtime='UTC 2024-01-01' --owner=0 --group=0 --numeric-owner -czf proof_bundle_${RUN_ID}.tar.gz ...
```

4. Default seed is always `42`.
5. Counted timestamps are RFC3339 UTC with a `Z` suffix.
6. Mock signing never introduces non-determinism into the bundle digest; the mock Rekor index is additive and external to the bundle.

### Deterministic verification commands

```bash
python tests/schema_validator.py --schema governance/RMR_SCHEMA_v1.json --manifest governance/H1_EXPERIMENT_MANIFEST.json --examples
bash scripts/proof_bundle_publish.sh --mock --run-id run-20260424-152430-bb49da8 --seed 42
cat bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz.sha256
```

Expected shape:

```text
<64 lowercase hex>  proof_bundle_run-20260424-152430-bb49da8.tar.gz
```

---

## 4. Frozen proof objects

### 4.1 RMR schema

The canonical Route-Margin Record schema lives at:

```text
governance/RMR_SCHEMA_v1.json
```

It is a Draft-07 JSON Schema and includes ten valid examples. The counted court treats it as immutable. The validator compares the current file digest to:

```text
expected_schema_digest = 7e6024cca27146f7eee6d169ee0de41342b2cd34cc798ecfe057cdd2be93c219
```

### 4.2 Schema freeze law

Read and obey:

```text
governance/RMR_SCHEMA_FREEZE.md
```

The schema may be amended only via a multisig git workflow. Any drift during counted execution is an immediate `30`.

### 4.3 H1 experiment manifest

The manifest is the campaign constitution. It enumerates:
- frozen files,
- mutable files,
- beta quarantine rules,
- TTL,
- required multisig,
- expected schema digest,
- manifest digest.

The file is:

```text
governance/H1_EXPERIMENT_MANIFEST.json
```

### 4.4 Current head receipt

The head receipt is the freshness anchor:

```text
reports/cohort0_current_head_receipt.json
```

It binds:
- repo name,
- commit,
- tree digest,
- timestamp,
- signer keys,
- mock Rekor entry,
- example openssl/cosign commands,
- a mock signed payload.

---

## 5. The minimum lawful runtime bridge

### Problem being solved

The audits identified a runtime name-vs-implementation gap. To prevent that gap from infecting the H1 court, this package adds a minimal, deterministic, auditable shim instead of pretending the full lobe runtime already exists.

### File

```text
runtime/minimal_lobe_shim.py
```

### Purpose

- read RMR rows or packet objects,
- derive deterministic decisions from row structure plus seed,
- emit provider receipts,
- emit a mock signature,
- do the smallest amount of real execution necessary to make the court auditable.

### CLI

```bash
python runtime/minimal_lobe_shim.py   --input packet/residual_alpha_packet_spec.json   --seed 42   --out work/smoke/receipt.json
```

### Sample output excerpt

```json
{
  "__generated_by_agent__": true,
  "runtime": "minimal_lobe_shim",
  "seed": 42,
  "provider_calls": [
    {
      "provider": "openai_hashed",
      "prompt_sha256": "<sha256>",
      "response_sha256": "<sha256>",
      "receipt_id": "prov-rmr-0001-42"
    }
  ],
  "receipt": {
    "digest_sha256": "<sha256>",
    "signature": "<base64digest>:mock-signer:mock-key-id"
  }
}
```

### Why this is lawful

It does not overclaim. It proves only that:
- a bounded runtime path exists,
- it emits receipts,
- it is deterministic,
- it can be exercised under frozen rules.

---

## 6. CouncilRouter execute-mode hardening

### Files

- `council/council_router_execute_toggle.patch`
- `council/sample/council_router_before.py`
- `council/sample/council_router_after.py`

### Problem being solved

Dry-run or refusal-only routing is not enough for counted proof. The package therefore demonstrates the minimum change required:
- no empty provider plans in execute mode,
- explicit provider invocation,
- explicit provider receipts,
- fail-closed behavior when providers are missing.

### Review commands

```bash
git apply --check council/council_router_execute_toggle.patch
python -m pytest -q tests/test_council_router_sample.py
```

Expected:

```text
2 passed
```

---

## 7. Packet geometry and counted evidence

### Residual alpha packet

```text
packet/residual_alpha_packet_spec.json
```

This packet includes:
- 10 example rows,
- mirror/masked/counterfactual variants,
- holdout policy,
- weighting for variant classes,
- deterministic timestamps.

### Packet law

- counted rows may not be beta,
- counted rows may not contain holdout IDs,
- holdout rows may exist in the packet for structural completeness but must not be counted,
- counterfactual rows may carry higher weight,
- mirror and masked rows exist to defeat shortcut exploitation.

### Example inspection command

```bash
python - <<'PY'
import json
obj = json.load(open("packet/residual_alpha_packet_spec.json", "r", encoding="utf-8"))
print(len(obj["rows"]))
print(obj["rows"][0]["rmr_id"], obj["rows"][0]["variant"])
PY
```

Expected:

```text
10
RMR-0001 base
```

---

## 8. Anti-shortcut and blind holdout controls

### 8.1 Anti-shortcut detector

```text
scripts/anti_shortcut_detector.py
```

This detector reads rows and computes:
- mirror invariance,
- masked invariance.

It fails with `60` if invariance falls below thresholds.

Example:

```bash
python scripts/anti_shortcut_detector.py   --input packet/residual_alpha_packet_spec.json   --mirror-threshold 0.90   --masked-threshold 0.90   --json-out work/smoke/invariance.json
```

### 8.2 Blind holdout loader

```text
scripts/blind_holdout_loader.py
data/holdout_ids.txt
```

This loader checks that counted rows do not contain holdout IDs.

Example:

```bash
python scripts/blind_holdout_loader.py   --holdout-file data/holdout_ids.txt   --packet packet/residual_alpha_packet_spec.json   --json-out work/smoke/holdout_check.json
```

Expected clean output:

```json
{
  "clean": true,
  "leakage": []
}
```

---

## 9. Preflight and disqualifiers

Shared preflight logic lives in:

```text
scripts/preflight_common.sh
```

It enforces:
- schema digest,
- head freshness,
- multisig count,
- beta cleanliness,
- holdout cleanliness.

### Preflight example

```bash
source scripts/preflight_common.sh
ensure_schema_digest
ensure_receipt_fresh
ensure_multisig_count
ensure_clean_beta packet/residual_alpha_packet_spec.json
ensure_no_holdout_leakage packet/residual_alpha_packet_spec.json
```

If any step fails, the script exits with the relevant code.

### Simulated stale-head failure

```bash
python - <<'PY'
import json
p = "reports/cohort0_current_head_receipt.json"
obj = json.load(open(p, "r", encoding="utf-8"))
obj["timestamp"] = "2020-01-01T00:00:00Z"
json.dump(obj, open(p, "w", encoding="utf-8"))
PY
bash scripts/run_h1_smoke.sh
```

Expected shell status:

```text
20
```

---

## 10. Smoke lane

The smoke lane exists to confirm:
- the schema is frozen,
- the head is fresh,
- the packet is clean,
- runtime emits receipts,
- proof bundle publication works in mock mode.

### Command

```bash
bash scripts/run_h1_smoke.sh
```

### What it does

1. run preflight,
2. execute the minimal lobe shim,
3. run anti-shortcut detection,
4. publish a mock proof bundle,
5. write a smoke log to `samples/run_h1_smoke.log`.

### Success signature

```text
[INFO] Smoke run completed successfully
```

---

## 11. Counted lane

The counted lane is the one-pass H1 attempt. It is stricter than smoke:
- it rolls back on error,
- it refuses beta rows,
- it refuses holdout leakage,
- it validates runtime receipt presence,
- it publishes a bundle.

### Command

```bash
bash scripts/run_h1_counted.sh
```

### Overriding input for testing

```bash
bash scripts/run_h1_counted.sh --input /tmp/custom_packet.json --seed 42
```

### Simulated beta disqualifier

```bash
python - <<'PY'
import json
obj = json.load(open("packet/residual_alpha_packet_spec.json", "r", encoding="utf-8"))
obj["rows"][0]["beta"] = True
obj["rows"][0]["counted"] = True
json.dump(obj, open("/tmp/beta_packet.json", "w", encoding="utf-8"))
PY
bash scripts/run_h1_counted.sh --input /tmp/beta_packet.json
```

Expected exit code:

```text
40
```

---

## 12. Proof bundle publication

The publication script is:

```text
scripts/proof_bundle_publish.sh
```

### Mock mode

Default mode is mock. It:
- creates `bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz`,
- writes `bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz.sha256`,
- writes `signatures/proof_bundle_run-20260424-152430-bb49da8.sig`,
- appends a deterministic pseudo-UUID entry to `mock_rekor/index.json`.

### Production mode

Production mode requires:

```bash
export COSIGN_KEY=/secure/path/cosign.key
export REKOR_URL=https://rekor.sigstore.dev
bash scripts/proof_bundle_publish.sh --prod --run-id run-20260424-152430-bb49da8 --seed 42
```

### Determinism note

The bundle digest is independent of:
- the mock Rekor entry,
- local uid/gid,
- local mtime,
- filesystem ordering.

The script copies inputs into a temp directory and archives them with canonical metadata.

---

## 13. Staging and promotion

Promotion is handled by:

```text
scripts/stage_and_promote.sh
```

### Rules

- checks multisig count,
- blocks files with `human_review_required: true`,
- writes a promotion receipt,
- performs atomic copy into `canonical/`,
- optionally creates a git commit if the repo is a git checkout.

### Promotion example

```bash
bash scripts/stage_and_promote.sh
```

### Multisig-only check

```bash
bash scripts/stage_and_promote.sh --check-multisig-only
```

Expected:

```text
multisig approvals satisfied
```

---

## 14. Test suite

### Test inventory

- `tests/test_schema_validator.py`
- `tests/test_anti_shortcut_detector.py`
- `tests/test_council_router_sample.py`
- `tests/acceptance_smoke.py`

### Full test command

```bash
python -m pytest -q tests/test_schema_validator.py tests/test_anti_shortcut_detector.py tests/test_council_router_sample.py tests/acceptance_smoke.py
```

### Acceptance assertions

The tests explicitly assert:

- freshness failure → `20`,
- schema drift → `30`,
- beta contamination → `40`,
- holdout leakage → `50`,
- runtime integrity failure → `60`,
- reproducible bundle hashes under identical seed,
- mock publication verification via signature and mock Rekor entry.

---

## 15. Auditor workflow

An independent reviewer should perform the following in order:

```bash
python tests/schema_validator.py --schema governance/RMR_SCHEMA_v1.json --manifest governance/H1_EXPERIMENT_MANIFEST.json --examples
bash scripts/run_h1_smoke.sh
bash scripts/run_h1_counted.sh
python - <<'PY'
from pathlib import Path
import base64, hashlib, json
bundle = Path("bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz")
sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
sig_lines = Path("signatures/proof_bundle_run-20260424-152430-bb49da8.sig").read_text().splitlines()
assert base64.b64decode(sig_lines[0]).decode() == sha
assert sig_lines[1] == "mock-signer:mock-key-id"
index = json.load(open("mock_rekor/index.json", "r", encoding="utf-8"))
assert any(item["bundle"] == "proof_bundle_run-20260424-152430-bb49da8.tar.gz" for item in index)
print("auditor mock verification complete")
PY
```

Expected final line:

```text
auditor mock verification complete
```

---

## 16. Operational boundaries

This package is intentionally narrow.

### It proves

- schema freeze is enforceable,
- head freshness is enforceable,
- beta and holdout disqualifiers are enforceable,
- a runtime shim can emit receipts,
- a deterministic proof bundle can be signed and indexed.

### It does not prove

- broad multi-lobe superiority,
- best-model status,
- enterprise readiness,
- multi-tenant production operations,
- external commercial traction,
- full civilization-stack completion.

Those remain future tracks.

---

## 17. Production switch procedure

### Replace mock keys

```bash
cp /secure/path/cosign.key keys/mock_cosign_key.pem
cp /secure/path/rekor.pem keys/mock_rekor_key.pem
```

### Set environment

```bash
export COSIGN_KEY=/secure/path/cosign.key
export COSIGN_PASSWORD='<secure-password>'
export REKOR_URL='https://rekor.sigstore.dev'
```

### Run

```bash
bash scripts/proof_bundle_publish.sh --prod --run-id run-20260424-152430-bb49da8 --seed 42
```

### Verify

```bash
cosign verify-blob --key "${COSIGN_KEY}.pub"   --signature signatures/proof_bundle_run-20260424-152430-bb49da8.sig   bundle/proof_bundle_run-20260424-152430-bb49da8.tar.gz
```

---

## 18. Cleanliness model

The package is built to stop endless cleaning.

### Why it stays clean

- all counted outputs live under `work/` and `bundle/`,
- promotion is atomic,
- quarantine is additive,
- logs live under `samples/`,
- the manifest enumerates every staged file,
- disqualifiers abort before silent mutation can accumulate.

### Recommended hygiene command

```bash
find work -maxdepth 2 -type f | sort
find bundle -maxdepth 1 -type f | sort
find signatures -maxdepth 1 -type f | sort
```

---

## 19. Example end-to-end session

```bash
python -m pytest -q tests/test_schema_validator.py tests/test_anti_shortcut_detector.py
bash scripts/run_h1_smoke.sh
bash scripts/run_h1_counted.sh
bash scripts/stage_and_promote.sh --check-multisig-only
```

Sample terminal output:

```text
4 passed
[INFO] Starting H1 smoke run
[INFO] Smoke run completed successfully
[INFO] Starting counted H1 run
[INFO] Counted H1 run completed successfully
multisig approvals satisfied
```

---

## 20. Final counted acceptance contract

A counted H1 run is accepted only if all of the following are true:

1. schema digest matches `expected_schema_digest`,
2. head receipt timestamp age <= `ttl_seconds`,
3. multisig approvals count >= `required_multisig`,
4. no counted row has `beta == true`,
5. no counted row includes holdout IDs,
6. runtime receipt contains `provider_calls` and `receipt.signature`,
7. anti-shortcut invariance passes thresholds,
8. proof bundle and signature exist,
9. proof bundle digest verifies,
10. mock or production Rekor publication exists.

Any failure is a disqualifier, not a soft warning.

---

## 21. File-by-file quick map

| File | Purpose |
|---|---|
| `governance/RMR_SCHEMA_v1.json` | canonical proof object schema |
| `governance/RMR_SCHEMA_FREEZE.md` | schema amendment law |
| `governance/H1_EXPERIMENT_MANIFEST.json` | campaign constitution |
| `reports/cohort0_current_head_receipt.json` | freshness and head truth |
| `runtime/minimal_lobe_shim.py` | deterministic runtime bridge |
| `council/council_router_execute_toggle.patch` | execute-mode example hardening |
| `scripts/run_h1_smoke.sh` | smoke orchestration |
| `scripts/run_h1_counted.sh` | counted orchestration |
| `scripts/proof_bundle_publish.sh` | deterministic packaging and publication |
| `scripts/stage_and_promote.sh` | multisig-gated promotion |
| `scripts/anti_shortcut_detector.py` | invariance enforcement |
| `scripts/blind_holdout_loader.py` | holdout leakage enforcement |
| `tests/schema_validator.py` | core validation logic |
| `tests/acceptance_smoke.py` | high-level smoke assertions |
| `docs/publication_legal_pack.md` | publication language and auditor commands |

---

## 22. The one thing that matters most

This package is not trying to prove everything.

It is trying to make one counted H1 court:
- lawful,
- fresh,
- deterministic,
- auditable,
- publishable,
- and hard to fake.

That is what Track 03 needs.

---

## 23. Appendices in this package

See:
- `appendix/reason_codes.md`
- `appendix/why_not_taxonomy.md`
- `appendix/example_rmr_rows.json`
- `appendix/sample_provider_receipt.json`
- `appendix/sample_rmr_input.json`
- `appendix/proof_bundle_sample.tar.gz`

These exist to shorten review time and keep the package self-contained.

---

## 24. Final note

If you execute this package exactly as written, one of two things will happen:

1. you will produce an auditable counted proof bundle; or
2. you will prove the ceiling honestly through a fail-closed disqualifier.

Both outcomes are valid. The package is built so that ambiguity is not.

End of playbook.
