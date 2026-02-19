# KT Suite Packs (Operator Workflow)

This document describes how to expand KT coverage **without** changing V1 law surfaces and **without** leaking sensitive payloads into canonical text.

## Principles (Hard)
- Generate new packs under `KT_PROD_CLEANROOM/exports/_runs/...` first (non-law).
- Do not embed sensitive prompt payloads in canonical repo surfaces; use hash references and sealed redpacks outside canonical surfaces.
- Determinism: generation should be repeatable given the same inputs + seed.

## Generate a Metamorphic Pack (Non-Law)
Prereq:
- `PYTHONPATH` includes `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src` and `KT_PROD_CLEANROOM`.

Command (example):
- `python -m tools.suites.generate_metamorphic_variants --in-suite KT_PROD_CLEANROOM/AUDITS/SUITES/SUITE_FORMAT_CONTROL.v1.json --seed 123 --variants-per-case 2 --transforms whitespace,punctuation,format,order`

Outputs (under a new `exports/_runs/...` directory):
- `suite_metamorphic.v1.json` (schema-valid `kt.suite_definition.v1`)
- `generation_report.*.json` + `verdict.txt`

## Evaluate a Pack
Use existing suite evaluation tooling (canonical entrypoints). Pack generation must not add new execution surfaces.

## Promote Into Law (Later, Explicit)
If and only if you decide to make a suite pack part of the canonical law-bound set:
- Propose a new EPIC with a law amendment + receipts.
- Only then copy the suite definition into `AUDITS/` and update the suite registry under governed process.

