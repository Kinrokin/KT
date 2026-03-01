# KT Delivery Bundle Spec (Artifact-Driven, Contract-Friendly)

This document defines the **standard delivery bundle** for KT engagements. It is intentionally mechanical:
- Deliverables are accepted only when **paths exist** and **hashes/verdict lines match**.
- The bundle is created from existing evidence directories (no repo mutation, no resealing).

## Canonical Principles (Hard)
- Evidence is WORM: create-once or byte-identical no-op.
- The run directory is the source of truth. A ZIP is a packaging convenience.
- No secrets are printed or embedded (key presence/length checks only).
- No sensitive prompt payloads are embedded in canonical text surfaces; hashes + bounded summaries only.

## Bundle Layout (Minimum)
For each engagement, deliver at least one **run directory** under:
- `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/<UTC_TS>_<purpose>/`

Minimum contents (names may vary slightly by lane; acceptance is based on the lane manifest + linter PASS):
- `verdict.txt` (one line; paste-safe)
- `reports/one_line_verdict.txt`
- `status_report.json` and/or `certify_report.json` (machine summary; lane-dependent)
- `evidence/run_protocol.json` (+ optional `.md`)
- `evidence/secret_scan_report.json` (must be `PASS` for client delivery)
- `sweeps/<sweep_id>/sweep_summary.json` (authoritative PASS/FAIL)
- `sweeps/<sweep_id>/*.log` (test + validator transcripts)
- `delivery/KT_DELIVERY_<run_id>.zip`
- `delivery/delivery_manifest.json`
- `hashes/KT_DELIVERY_<run_id>.zip.sha256`
- `evidence/replay.sh` and `evidence/replay.ps1`

If seal-pack verification is in scope, include pointers to:
- `KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL/<pack_id>/seal_verify_report.json`
- `KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL/<pack_id>/red_assault_report.json`

## Standard ZIP Packaging (Recommended)
The operator factory generates a standard ZIP from the run evidence directory:
- `delivery/KT_DELIVERY_<run_id>.zip`

Include the lane’s delivery manifest:
- `delivery/delivery_manifest.json`:
  - pins (sealed tag/commit, law bundle hash, suite registry id, determinism anchor)
  - verdict line
  - zip path + sha256
  - replay command reference

Note: older/legacy bundles may include a plaintext `delivery_manifest.txt`. Prefer the JSON manifest for all new deliveries.

## Acceptance Criteria (Measurable)
- Sweep harness `status=PASS` for the agreed sweep id(s).
- V1 anchors remain unchanged when operating V1:
  - sealed tag resolves to the sealed commit
  - law bundle hash recompute matches `LAW_BUNDLE_FL3.sha256`
  - suite registry validates and matches pinned `suite_registry_id`
- Worktree remains clean before and after each run (unless explicitly allowed).
- No network access and no installs performed during runs.
