---
title: "KT Data Evaluation Matrix"
volume: "Volume III - Technical Stack and Pipeline"
chapter: "Chapter 3"
author_role: "Systems Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume III - Technical Stack and Pipeline
### Chapter 3 - Data Evaluation Matrix

#### Chapter intent (plain-English)
This matrix defines what artifacts are required to evaluate and certify a system in KT, where they must live, how they are hashed, and how a third party verifies them offline. [SRC:USER_PACKET]

#### Core rule set (plain-English)
- The repo is read-only during runs: no mutation of sealed anchors, receipts, or governance surfaces.
- All evidence writes are WORM: create-once or byte-identical no-op.
- Allowed write roots are limited to export run roots and explicitly allowlisted export surfaces. [SRC:USER_PACKET]

---

#### Artifact classes (required vs optional)

Required for any governed run:
- Pins:
  - Sealed tag and commit.
  - Law bundle pin file and recomputed hash match.
  - Suite registry id and determinism anchor expected root.
- Run root evidence:
  - `run_sweep_audit` logs and `sweep_summary.json`.
  - One-line verdict.
  - Hash files for key artifacts.

Optional by engagement scope:
- Datasets:
  - Local-only dataset snapshots and dataset hash manifests.
- Adapters:
  - Adapter artifact directories, adapter hash manifests, promotion/quarantine receipts.
- Suites:
  - Suite packs (including metamorphic variants) generated under exports run roots.
- Runtime (hat plane):
  - Routing receipts, orchestration transcripts, runtime behavior summaries.
- Red-team coverage:
  - Safe reports and aggregate metrics; sensitive payloads are not embedded in canonical surfaces. [SRC:USER_PACKET]

---

#### Locations, hashing, determinism, and verification

Pins and governance anchors:
- Location: `KT_PROD_CLEANROOM/AUDITS/`
- Hashing:
  - Law bundle recompute must match `AUDITS/LAW_BUNDLE_FL3.sha256`.
  - Suite registry id and determinism anchor hash must match expected values.
- Verification:
  - `python -m tools.verification.run_sweep_audit --sweep-id OPERATOR_VERIFY` [SRC:NEEDS_VERIFICATION]

Run roots (operator evidence):
- Location: `KT_PROD_CLEANROOM/exports/_runs/<RUN_KIND>/<UTC_TS>/...`
- Hashing:
  - Each run must emit sha256 for critical artifacts (verdict, sweep summary, manifests).
  - Prefer manifest-of-manifests for delivery bundles (file list + sha256 per file).
- Determinism:
  - Run IDs must be unique per run; deterministic claims must be proven via rerun evidence roots, not asserted. [SRC:USER_PACKET]

Adapters (factory lane outputs):
- Location (allowlisted): `KT_PROD_CLEANROOM/exports/adapters/**` and `KT_PROD_CLEANROOM/exports/adapters_shadow/**`
- Hashing:
  - Adapter artifact directory must include a schema-bound hash manifest.
  - Promotion decision must reference adapter hash and inputs. [SRC:USER_PACKET]
- Verification:
  - Verify adapter directory exists and referenced hashes match.
  - Verify any promotion/quarantine receipt references the same hashes.

Suites and suite packs:
- Location:
  - Canonical suites: suite registry referenced paths (read-only).
  - Generated packs: exports run roots only (default; promotion to law surface requires a governed change). [SRC:USER_PACKET]
- Hashing:
  - Pack manifest lists each generated case file path and sha256.
  - Pack manifest includes transform list and seed.
- Verification:
  - Recompute sha256 for each case and compare to manifest.

Hat plane (runtime demo):
- Location: exports run roots only.
- Determinism:
  - Explicitly record seeds and input hashes; do not claim determinism without replay proof.
- Verification:
  - Run report must include write-root allowlist and a "no mutation" guardrail assertion. [SRC:USER_PACKET]

---

#### Offline Kaggle constraints (local snapshot discipline)
Plain-English: Kaggle runs must be offline and must not rely on remote model hubs or remote datasets. [SRC:USER_PACKET]

Required inputs (local-only):
- Base snapshot directory (local path): `BASE_SNAPSHOT_DIR=<local_path>`
- Suite registry file (copied locally or mounted): `SUITE_REGISTRY_FL3.json`
- Adapter directories (local path list): `ADAPTER_DIRS=[...]`

Required outputs (WORM):
- `results.json` (schema-bound if available)
- `meta.json` (inputs, pins, versions, seeds, hashes)
- `hashes.sha256.txt` (sha256 for every emitted artifact)

---

#### Sources (stubs)
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

