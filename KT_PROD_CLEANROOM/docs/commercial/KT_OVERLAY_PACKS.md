# KT Overlay Packs (Commercial)

Overlay packs are **strict, hash-verified** layers that tailor scope/policy/reporting for a domain **without** changing sealed law surfaces. They exist to answer the client question:

“Can you evaluate and report against our domain constraints in a way that is replayable and auditable?”

## What an overlay is
- A declared, versioned, hash-addressed pack listed in:
  - `KT_PROD_CLEANROOM/AUDITS/OVERLAYS/OVERLAY_REGISTRY.json`
- Metadata and selection rules that the operator lane can apply in **strict** mode.
- A way to make domain coverage composable and reviewable (finance, healthcare, insurance, security/compliance, public sector chain-of-custody).

## What an overlay is not
- Not executable code injection.
- Not a place to embed sensitive prompt payloads or dual-use content.
- Not a law amendment; admission into law-bound registries is a separate governed process.

## Operator entrypoint (SKU_OVERLAY)
Strict mode is required for audit-grade runs:
- `python -m tools.operator.kt_cli --profile v1 overlay-apply --overlay-id <id> --target-lane <certify|red_assault|continuous_gov|forge> --strict`

## Outputs (per run)
Every overlay application produces a standard delivery bundle plus:
- `reports/overlay_resolution.json`
- `reports/overlay_diff.json`
- `reports/overlay_effect_summary.json`

## Acceptance criteria (mechanical)
- Overlay ids must exist in the registry; missing ids fail-closed in strict mode.
- Overlay pack hashes must match the registry’s pinned sha256; mismatch fails-closed.
- Overlay application must be recorded in `evidence/run_protocol.json` and `delivery/delivery_manifest.json`.

## Typical engagement pattern
1) Run `SKU_CERT` (baseline proof) against the agreed base scope.
2) Apply overlay(s) in strict mode and re-run the agreed lane(s).
3) Deliver both bundles, plus a short “delta narrative” anchored to the overlay reports.

## Pricing logic (framework; no numbers)
- Per-overlay fee (scope + review + strict apply runs).
- Optional bundle pricing for a full vertical set (e.g., finance + insurance).

