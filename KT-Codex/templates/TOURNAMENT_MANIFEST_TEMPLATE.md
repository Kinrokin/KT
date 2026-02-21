---
title: "Tournament Manifest Template (Draft)"
volume: "KT Codex - Templates"
chapter: "Tournament"
author_role: "Program Manager"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
This template defines a deterministic tournament run configuration for comparing contenders under identical suites and acceptance thresholds. It is designed for offline execution with WORM evidence outputs. [SRC:USER_PACKET]

## Fields (fill-in)
- Tournament id:
- Engagement id:
- Sealed anchors verified: (tag, commit, law hash, suite registry id, determinism anchor)
- Contenders:
- Suites:
- Rounds:
- Repeats per case:
- Seed schedule:
- Scoring axes:
- Promotion thresholds:
- Refusal policy and codes:
- Required outputs:
- Replay requirement:
- Delivery bundle contents:

## Outputs (required)
- `tournament_manifest.json`
- `scoreboard.json`
- `per_round_results/` (export-only; WORM)
- `hashes.sha256.txt`
- `verdict.txt` (one-line verdict)

## Replay checklist
- Verify inputs are hash-bound and recorded.
- Rerun at least one round and compare required evidence roots.
- Fail-closed on any missing artifact or schema mismatch. [SRC:USER_PACKET]

