# KT13 Expand Repair V1 Operator Runbook

Authority: internal/shadow benchmark and repair-signal collection only.

Current cutline head: `0f1bdd118204130ec676c9e68e2d06791ecf5006`

Packet path:

```text
packets/kt13_expand_repair_v1.zip
```

Packet SHA256:

```text
b7fc6fc762989e396fe81ff7954b19d374cc3d474986b471e03d83202f5d901f
```

## Kaggle Setup

1. Create a Kaggle notebook.
2. Turn GPU on.
3. Turn Internet on.
4. Upload `packets/kt13_expand_repair_v1.zip` as a Kaggle dataset or place it in `/kaggle/working`.
5. If the HF adapter store is private, provide `HF_TOKEN` through Kaggle secrets or environment variables.
6. Leave `KT_REQUESTED_HEAD` unset unless intentionally pinning a specific commit.
7. Optionally set `KT_PACKET_SHA256` to the packet hash above.

## One-Cell Bootstrap

Paste the contents of:

```text
packets/kt13_expand_repair_v1/KAGGLE_BOOTSTRAP_CELL.py
```

into a single Kaggle cell and run it.

## Expected Receipts

The runner emits receipts under:

```text
/kaggle/working/kt13_expand_repair_v1_outputs
```

Required initial receipts include:

```text
head_binding_receipt.json
run_manifest.json
evaluator_integrity_receipt.json
benchmark_leakage_scan.json
route_regret_matrix.json
verified_work_per_token_scorecard.json
assessment_summary.json
```

If head binding fails, the runner emits:

```text
blocker_ledger.json
```

and exits non-zero.

## Return From Kaggle

Upload back only the small assessment/review ZIP or the output receipt directory. Do not upload full model artifacts unless a separate import lane requests them.

## Claim Ceiling

This run does not authorize commercial launch, external audit completion, external validation acceptance, S-tier, beyond-SOTA, category leadership, frontier parity, Kimi parity, 7B amplification, router superiority, multi-lobe superiority, production readiness, runtime cutover, or canonical promotion.

Clean target:

```text
KT_13_EXPANDED_DETACHED_BENCHMARK_REPAIR_SIGNAL_BOUND__TARGETED_RETRAIN_NEXT
```
