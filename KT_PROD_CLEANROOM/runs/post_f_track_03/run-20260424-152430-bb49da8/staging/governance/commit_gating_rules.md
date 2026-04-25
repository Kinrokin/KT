---
human_review_required: true
title: Commit Gating Rules
---

# Commit Gating Rules

1. `main` is the only canonical branch.
2. Files whose first ten lines contain `human_review_required: true` MUST NOT be auto-promoted by automation.
3. `scripts/stage_and_promote.sh` MUST verify:
   - clean worktree or explicit staging-root mode;
   - multisig approvals present and count >= `governance/H1_EXPERIMENT_MANIFEST.json.required_multisig`;
   - no beta rows in counted payloads;
   - no holdout IDs in counted payloads;
   - no schema drift relative to `expected_schema_digest`;
   - no unsigned proof bundle if promotion depends on publication.
4. Auto-promotion is allowed only for files not marked human-review-required and only after all tests pass.
5. Every promotion writes a promotion receipt under `canonical/`.
