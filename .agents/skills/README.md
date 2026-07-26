# KT Agent Skills

This directory contains Codex-readable KT operating skills. These are not product claims, model claims, or runtime authority. They are execution protocols for repo-side and furnace-side work.

## Current core skills

1. `kt-authority-cutline` — establish the controlling state before any repo, PR, handoff, merge, launch, or Kaggle decision.
2. `kt-repo-review-microfix` — classify review defects and produce the smallest lawful repair instead of a new architecture cycle.
3. `kt-proof-runtime-vertical` — prove one bounded runtime path is actually called, gated, evidenced, consumed, and rollback-able.

## Required call order

For normal repo-side KT work:

```text
kt-authority-cutline
→ kt-repo-review-microfix if any review/check/source/authority defect exists
→ kt-proof-runtime-vertical when executing PR-B-style runtime verticalization
→ kt-authority-cutline again after merge or handoff
```

## Global skill law

```text
Any packet, prompt, receipt, or handoff whose stated repo state conflicts with live GitHub truth is archive-only.
```

```text
No component is runtime-integrated merely because code, schemas, tests, packets, or receipts exist. Runtime integration requires a real invocation chain with gate, output, consumer, proof, and rollback evidence.
```
