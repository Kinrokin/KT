---
human_review_required: true
title: Router Court Spec
---

# Router Court Specification

This document defines the bounded four-head architecture for Track 03 H1.

## Heads

1. **Route head** — predicts the winning specialist or abstain.
2. **Margin head** — predicts route margin versus best static baseline.
3. **Reason-code head** — emits enumerated reason codes only.
4. **Why-not head** — emits bounded refusal / non-selection labels.

## Inputs

- frozen residual-alpha packet rows from `packet/residual_alpha_packet_spec.json`
- mirror and masked variants
- provider receipts emitted by `runtime/minimal_lobe_shim.py`
- blind holdout IDs from `data/holdout_ids.txt`

## Canonical training commands

```bash
python -m training.router_train   --packet packet/residual_alpha_packet_spec.json   --out training/out/router_model.json   --seed 42   --epochs 12   --heads route margin reason why_not
```

```bash
python -m training.router_eval   --model training/out/router_model.json   --packet packet/residual_alpha_packet_spec.json   --out training/out/router_metrics.json   --seed 42
```

## Expected metric JSON example

```json
{
  "route_accuracy": 0.91,
  "margin_mae": 0.08,
  "reason_code_exact": 0.88,
  "why_not_exact": 0.87,
  "masked_invariance": 0.95,
  "mirror_invariance": 0.95,
  "abstention_preserved": true
}
```

## Non-goals

- no broad capability claims
- no best-model claims
- no Kaggle/math carryover
- no multi-lobe superiority claim from H1 alone

## Acceptance

The counted court may proceed only if:
- masked and mirror invariance are above configured thresholds;
- beta rows are absent;
- holdout IDs are absent;
- route outputs are receipt-backed and deterministic for the same seed.
