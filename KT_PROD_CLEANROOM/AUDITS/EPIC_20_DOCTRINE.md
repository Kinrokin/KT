# EPIC_20 — Canonical Kaggle Cells / Notebooks (BINDING DOCTRINE)

## Purpose

EPIC_20 defines a **copy/paste canonical execution surface** for KT V1 demonstrations:

- MRT-1 operational certification battery (tests + meta-evaluator + determinism canary).
- Router hat demo (deterministic routing receipts).
- Suite evaluation + consolidated audit report demo (EPIC_17 + EPIC_18).

These scripts are **operator tooling**, not enforcement gates.

## Invariants

- Scripts must be **self-contained** and explicit (no placeholders for critical steps).
- Scripts must not print secrets.
- Canonical-lane flags (`KT_CANONICAL_LANE=1`) must not be exported during `pytest`.

## Location

Canonical cell scripts live in `KT_PROD_CLEANROOM/AUDITS/KAGGLE/`.

