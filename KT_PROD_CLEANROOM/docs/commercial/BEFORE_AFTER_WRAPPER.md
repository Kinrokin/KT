# Before/After Narrative Wrapper (Evidence-Backed)

Use this document to communicate improvement (typically for `SKU_FORGE` or remediation work) without making uncited claims.

## 1) Executive summary (2–4 sentences)
- Baseline: `<baseline_run_id>` (date/time, lane, scope)
- Change: `<what_changed>` (adapter id / config hash / overlay id)
- Result: `<headline_metric_delta>` (bounded, measured)
- Status: `<PASS | HOLD | FAIL>` and why (one sentence)

## 2) Evidence references (must be concrete)
- Baseline run dir: `<path under exports/_runs/...>`
- Baseline delivery zip sha256: `<hex64>`
- After run dir: `<path under exports/_runs/...>`
- After delivery zip sha256: `<hex64>`

## 3) What changed (no marketing, just facts)
- Inputs:
  - model id: `<string>`
  - adapter id: `<string>`
  - seed: `<int>`
  - overlay ids (if any): `<list>`
- Training config hash (if forge): `<hex64>`
- Dataset manifest hash (if forge): `<hex64>`

## 4) What did not change (guardrails)
- Sealed anchors unchanged (if operating v1 profile).
- Law bundle hash unchanged.
- Suite registry id unchanged.
- No network; no installs (audit-grade lanes).

## 5) Results (table)
| Metric | Baseline | After | Delta | Gate |
|---|---:|---:|---:|---|
| `<metric>` | `<x>` | `<y>` | `<y-x>` | `<must_improve/no_regress>` |

## 6) Promotion decision (if applicable)
- Promotion gate artifact: `forge/promotion_gate.json`
- Decision: `<PROMOTED | BLOCKED | QUARANTINED>`
- Blocking reason(s): `<reason codes or short text>`

## 7) Limitations / disclaimers
- Results apply only to the pinned scope and agreed packs.
- No guarantee of generalization beyond measured conditions.

