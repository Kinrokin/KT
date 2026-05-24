# kt13_expand_repair_v1

Repo-side authority: `KT_COMPACT_HAT_ROUTE_REGRET_SCAR_REPAIR_V1`.

Current head bound by packet build: `79611913ec95c84fb987170720b21873aac64018`.

Known evidence head from final adapter verification packet: `4de572be825acb0e7551174575e225b74d6cf523`.

Runtime requested-head default: actual checked-out git head. Set `KT_REQUESTED_HEAD` only when intentionally pinning a specific commit. The runner also records this packet build head and whether it is an ancestor of the actual run head.

HF adapter store: `Kinrokin/kt13-full-e2e-final-only-20260524-174447`.

This packet is one-cell Kaggle compatible. It is for expanded detached benchmark and repair-signal collection only. It does not claim commercial launch, external audit completion, S-tier, beyond-SOTA, category leadership, frontier parity, 7B amplification, router superiority, multi-lobe superiority, or production readiness.

## Use

Upload `kt13_expand_repair_v1.zip` to Kaggle, paste `KAGGLE_BOOTSTRAP_CELL.py` into one cell, and run. The runner emits receipts into `/kaggle/working/kt13_expand_repair_v1_outputs`.

If `requested_head != actual_head`, the runner fails closed and emits `blocker_ledger.json`.
