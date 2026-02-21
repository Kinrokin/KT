---
title: "Titan Notebook Suite Canon"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Titan Operator Notebooks"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
This document is the notebook/cell map for running Titan Red-Assault v2 offline. It is designed to produce jurisdiction-grade evidence packs deterministically with WORM semantics.

## Sacred Constraints (Do Not Touch)
- No network access.
- No installs.
- WORM outputs only under `KT_PROD_CLEANROOM/exports/_runs/**`.
- Do not change env lock required keys.
- Do not overwrite evidence; write new timestamped run roots only.

## Notebook 00 — Environment Seal and Pins
### Cell 00.1 — Set env lock
- Purpose: enforce the host contract from `KT_PROD_CLEANROOM/AUDITS/FL4_ENV_LOCK.json`.
- Inputs: env lock JSON
- Outputs: env proof JSON under run root
- WORM path: `<RUN_ROOT>/reports/env_lock_proof.json`
- Failure modes: missing/extra tracked env vars => fail closed

### Cell 00.2 — Pins gate
- Inputs: sealed tag, law bundle pin file, recompute primitive
- Outputs: pin report + hashes
- WORM path: `<RUN_ROOT>/reports/pins_gate.json`

## Notebook 01 — Base Snapshot and Adapter Discovery
### Cell 01.1 — Base snapshot verify
- Inputs: local base snapshot path (offline)
- Outputs: snapshot hash manifest
- WORM path: `<RUN_ROOT>/reports/base_snapshot_hashes.json`

### Cell 01.2 — Adapter discovery
- Inputs: adapter dir
- Outputs: adapter manifest (hashes)
- WORM path: `<RUN_ROOT>/reports/adapter_manifest.json`

## Notebook 02 — Pack Admission Verify
### Cell 02.1 — Load pack manifest
- Inputs: `pack_manifest.json`
- Outputs: normalized manifest + sha256
- WORM path: `<RUN_ROOT>/reports/pack_manifest_normalized.json`

### Cell 02.2 — Verify admission record
- Inputs: suite registry index + admission record(s)
- Outputs: admission verification report
- WORM path: `<RUN_ROOT>/reports/admission_verify.json`
- Failure modes: missing signatures/hashes => terminal reject

## Notebook 03 — World Set Build (MVE)
### Cell 03.1 — Build world set from pack
- Inputs: `world_set.json` + invariants ref
- Outputs: `world_set_built.json` + sha256
- WORM path: `<RUN_ROOT>/mve/world_set.json`

## Notebook 04 — Run Rounds 0–5 (Incremental Sealing)
Each round is a separate cell group; after each round, write partial outputs and hash manifests.

### Cell 04.R — Execute round R
- Inputs: adapter id, cases subset, world set, validators, thresholds, seed
- Outputs: round artifacts + transcripts
- WORM path: `<RUN_ROOT>/rounds/R*/...`
- Failure modes: any terminal reason code => stop and quarantine

## Notebook 05 — Determinism Rerun
### Cell 05.1 — Rerun identical inputs
- Inputs: same as Notebook 04
- Outputs: second manifest
- Acceptance: manifest hashes match exactly

## Notebook 06 — Scoring + Conflict Admission
### Cell 06.1 — Run validators
- Inputs: outputs, contracts, thresholds
- Outputs: validator reports + reason codes
- WORM path: `<RUN_ROOT>/validators/...`

### Cell 06.2 — Conflict admission gate
- Inputs: conflict events + measurement basis receipt
- Outputs: conflict admission report
- WORM path: `<RUN_ROOT>/mve/conflict_admission.json`

## Notebook 07 — Evidence Pack Bundling
### Cell 07.1 — Build evidence zip
- Inputs: run root evidence
- Outputs: `EVIDENCE.zip`, `MANIFEST.json`, sha256 files, replay.txt
- WORM path: `<RUN_ROOT>/delivery/...`

## Notebook 08 — Replay Verification
### Cell 08.1 — Verify manifest hashes
- Inputs: `MANIFEST.json`
- Outputs: PASS/FAIL replay verification report
- WORM path: `<RUN_ROOT>/reports/replay_verify.json`

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

