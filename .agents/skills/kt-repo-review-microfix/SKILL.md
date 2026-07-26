---
name: kt-repo-review-microfix
description: Convert PR review comments, CI failures, source-index mismatches, verifier defects, and stale-head findings into the smallest lawful repair. Use when a KT PR is dirty, review-blocked, semantically questionable, or green-but-not-clean.
---

# KT Repo Review Microfix

## Purpose

Stop review recursion. This skill decides whether a review finding is a blocker, a local hygiene repair, or non-blocking context, then produces the smallest lawful fix.

It must be called when any of these exist:

```text
unresolved PR review thread
requested changes
CI failure
semantic validator failure
source index size/hash mismatch
path containment issue
schema verifier issue
head/replay mismatch
claim wording concern
stale branch-side handoff
checks green but review not clean
```

## Core question

```text
What exactly broke, why does it matter, and what is the smallest repair that proves it cannot recur?
```

## Severity law

```text
P0/P1 authority, verifier, path, hash, claim, replay, source binding, safety, or execution-path defect:
BLOCK downstream execution and repair before merge or next tranche.

P2 portability, determinism, reviewer usability, or verifier ergonomics defect:
FIX before downstream execution if it touches handoff, verifier, source truth, or proof objects.

P3 naming/comment/test readability defect:
FIX only if already touching the same surface, unless it risks audit confusion.
```

## Blocked failure classes

```text
new architecture packet for a small verifier bug
admin bypass
reopening old PRs after merge
unresolved review threads ignored
review comments spawning endless broad packets
missing hostile regression tests
fixing symptoms without regenerating dependent artifacts
branch-side compile treated as final execution authority
source-index entries pointing to commits that do not contain the declared bytes
```

## Required defect matrix

For every finding, produce:

```text
finding_id:
source: reviewer / CI / semantic court / manual / live source
affected_file:
affected_authority_plane: path / source / verifier / claim / runtime / artifact / test / docs
severity: P0 / P1 / P2 / P3
blocks_merge: true/false
blocks_downstream_execution: true/false
root_cause:
minimal_patch:
hostile_test:
dependent_artifacts_to_regenerate:
resolved_by:
```

## Microfix workflow

```text
1. Run kt-authority-cutline first.
2. Read unresolved review threads and current PR state.
3. Classify each finding with the severity law.
4. Reject broad architecture expansion unless the defect truly changes architecture.
5. Patch the smallest existing surface.
6. Add one hostile regression test per authority-relevant defect.
7. Regenerate every dependent artifact from final bytes.
8. Re-run local validators and relevant tests.
9. Push same PR if still open; otherwise create one tiny post-merge repair PR from current main.
10. Resolve/supersede threads only after tests prove the fix.
11. Merge normally through protected path.
12. Fresh-clone replay if authority-bearing.
```

## Required hostile tests by defect class

```text
path containment:
../ escape, root_evil prefix collision, symlink leaf, intermediate symlink, directory/non-regular target

envelope verifier:
stale envelope head, stale envelope source-set, empty payload field, whitespace payload field, explicit conflicting CLI arg, wrong payload_path

source index:
repo_path + old head + new hash fails, commit-bound exact bytes pass, checkout-relative generated source pass, head null without mode fails

claim boundary:
forbidden claim string fails, allowed bounded claim passes, counterfactual cannot overwrite official verdict

runtime proof:
missing gate event fails, missing consumer acknowledgement fails, broken event-chain hash fails, zero denominator coverage fails
```

## Output format

Return:

```text
WHAT_BROKE:
WHY_IT_MATTERS:
MINIMAL_FIX:
FILES_TO_TOUCH:
HOSTILE_TESTS:
DERIVED_ARTIFACTS_TO_REGENERATE:
VALIDATION_COMMANDS:
SAME_PR_OR_NEW_PR:
MERGE_DISCIPLINE:
RETURN_CONTRACT:
```

## Core rule

```text
A review comment becomes work only if it can change truth, safety, replay, authority, execution reliability, or audit clarity.
```

Do not use this skill to design new systems. Use it to end the current defect.
