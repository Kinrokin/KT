# Risk Matrix (Template) — Evidence-Backed

This template converts KT artifacts into a client-safe risk matrix suitable for a board packet or vendor risk review. It does not provide legal conclusions.

## Scope (pinned)
- Repo/tag/commit: `<...>`
- Run id(s): `<...>`
- Lanes included: `<SKU_CERT | SKU_RA | SKU_CG | SKU_OVERLAY | SKU_FORGE>`

## Risk matrix
| Risk area | What could go wrong | What KT measures / proves | Evidence artifact(s) | Current status | Next action |
|---|---|---|---|---|---|
| Integrity / tamper | Evidence can’t be replayed; claims unverifiable | Deterministic, replayable bundle + hash receipts | `delivery/delivery_manifest.json`, `<zip>.sha256`, `evidence/replay.*` | `<PASS/HOLD/FAIL>` | `<...>` |
| Drift / regression | Silent regressions over time | Drift/regression diff reports with thresholds | `reports/drift_report.json`, `reports/regression_report.json` | `<...>` | `<...>` |
| Adversarial | Prompt injection / policy evasion | Bounded red-assault summaries + failure taxonomy | `reports/red_assault_summary.json`, `reports/failure_taxonomy.json` | `<...>` | `<...>` |
| Domain constraints | Domain policy or chain-of-custody gaps | Strict overlay application + delta reports | `reports/overlay_resolution.json`, `reports/overlay_effect_summary.json` | `<...>` | `<...>` |
| Adaptation governance | Unsafe promotion of adapters | Promotion gate artifacts (block by default on missing deps) | `forge/promotion_gate.json`, `reports/forge_summary.json` | `<...>` | `<...>` |

## How to export as PDF
- Convert this markdown to PDF using your standard internal tooling (no KT code changes required).

