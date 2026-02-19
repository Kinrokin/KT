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
- `KT_PROD_CLEANROOM/exports/_runs/.../<UTC_TS>_<purpose>/`

Minimum contents (names may vary by tool; verify with `verdict.txt` + `sweep_summary.json`):
- `verdict.txt` (one line; paste-safe)
- `status_report.json` and/or `certify_report.json` (machine summary)
- `sweeps/<sweep_id>/sweep_summary.json` (authoritative PASS/FAIL)
- `sweeps/<sweep_id>/*.log` (test + validator transcripts)
- `hashes.txt` or equivalent hash ledger (if produced by the tool)

If seal-pack verification is in scope, include pointers to:
- `KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL/<pack_id>/seal_verify_report.json`
- `KT_PROD_CLEANROOM/exports/adapters_shadow/_runs/FL4_SEAL/<pack_id>/red_assault_report.json`

## Standard ZIP Packaging (Recommended)
Deliver a ZIP created from the run directory (no additional computation required):
- `KT_<ENGAGEMENT_ID>_<UTC_TS>_DELIVERY.zip`

Include a short, plaintext manifest adjacent to the ZIP:
- `delivery_manifest.txt`:
  - `git_head=<sha>`
  - `sealed_tag=<tag>` (if applicable)
  - `law_bundle_hash=<hex64>`
  - `suite_registry_id=<hex64>`
  - `sweep_summary=<path>`
  - `verdict=<verbatim one-line verdict>`
  - `zip_sha256=<hex64>`

## Acceptance Criteria (Measurable)
- Sweep harness `status=PASS` for the agreed sweep id(s).
- V1 anchors remain unchanged when operating V1:
  - sealed tag resolves to the sealed commit
  - law bundle hash recompute matches `LAW_BUNDLE_FL3.sha256`
  - suite registry validates and matches pinned `suite_registry_id`
- Worktree remains clean before and after each run (unless explicitly allowed).
- No network access and no installs performed during runs.

