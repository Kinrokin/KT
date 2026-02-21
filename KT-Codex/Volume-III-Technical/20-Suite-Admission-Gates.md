---
title: "Suite Admission Gates"
volume: "Volume III — Technical Stack & Pipeline"
chapter: "Admission Gate Matrix (v1)"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-21"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:USER_PACKET", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (Plain-English)
This is the gate matrix that maps admission checks to required artifacts, failure modes, and reason codes. It is designed for operators and auditors: no ambiguity and no silent green.

## Gate Matrix (v1)
| Gate | Required artifact(s) | Failure mode | Reason code(s) | Terminal |
|---|---|---|---|---|
| Pins gate | sealed tag commit, law bundle hash pin | mismatch | RC_GOV_ADMISSION_MISSING_ARTIFACT_0001 / RC_GOV_MEASUREMENT_BASIS_UNAUTHORIZED_0003 | Yes |
| Clean tree | `git status --porcelain=v1` empty | dirty tree | RC_GOV_ADMISSION_MISSING_ARTIFACT_0001 | Yes |
| Dual-use policy | pack publish classes, redpack hash refs | unsafe payload in canonical | RC_SEC_SECRET_LEAKAGE_SUSPECT_0501 | Yes |
| Schema validation | schemas + pack JSON | invalid shape / dup keys | RC_SCHEMA_INVALID_OUTPUT_0201 / RC_SCHEMA_DUPLICATE_KEYS_0202 | Yes |
| Pack integrity | `hash_manifest.json` + recompute | hash mismatch | RC_GOV_ADMISSION_MISSING_ARTIFACT_0001 | Yes |
| Validator binding | validator contract ids | missing/unrecognized | RC_GOV_MEASUREMENT_BASIS_UNAUTHORIZED_0003 | Yes |
| Coverage minimums | case tags + pack rules | under-covered | RC_VAL_UFV_VIOLATION_0104 | No (policy may upgrade) |
| World-set binding | world set + invariants | missing/invalid ordering | RC_MVE_WORLD_NOT_DECLARED_0401 | Yes |
| Determinism expectation | determinism canary manifests | divergence | RC_DET_ARTIFACT_HASH_DIVERGENCE_0301 | Yes |
| Signature verification | operator_sig + registry_sig | missing/invalid sig | RC_GOV_ADMISSION_MISSING_ARTIFACT_0001 | Yes |

## Notes
- Terminal failures reject admission; do not proceed to execution for claims.
- Non-terminal failures may be allowed only if the profile explicitly permits and the decision is logged (governed).

## Sources
- [SRC:USER_PACKET]
- [SRC:NEEDS_VERIFICATION]

