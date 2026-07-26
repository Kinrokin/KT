---
name: kt-authority-cutline
description: Establish the controlling KT repo and artifact state before any packet, PR, merge, Kaggle, launch, or go/no-go decision. Use first whenever stale authority, branch-vs-main truth, claim ceiling, handoff validity, or next lawful move matters.
---

# KT Authority Cutline

## Purpose

Stop ghost chasing. This skill determines what is actually controlling right now.

It must be called before:

```text
repo-side packet delivery
PR execution
PR merge advice
review repair decisions
Kaggle or HF furnace work
handoff authorization
launch/go-no-go answers
claim expansion discussion
```

## Core question

```text
What is current, what is historical, and what is the next lawful move?
```

## Failure classes blocked

```text
old packet reused after repo advanced
branch success treated as merged-main truth
pre-merge artifact treated as final handoff
review comment ignored because checks passed
claim ceiling drift
Kaggle rerun after repo import already happened
architecture recursion when the next move is a microfix
compiled handoff executed from stale head
current truth inferred from chat instead of live source
```

## Mandatory source order

Resolve conflicts in this order:

```text
live GitHub main / protected branch truth
current PR state and review-thread state
current claim ceiling
current authority registry / evidence graph / current-truth projection
fresh-clone or detached replay receipts
Hugging Face artifact hash/revision receipts
Kaggle raw run evidence
historical packets and chats
research/theory
```

## Required live checks

When repository access is available, inspect:

```text
current main head
latest merged PRs relevant to the lane
current open PRs and unresolved review threads
compiled handoff head
final detached handoff head and SHA, if present
claim ceiling file and SHA
current graph/truth generated_from_head
current graph/truth merged_main_head
source-index head-binding posture
whether packet stated state matches live repo truth
```

## Decision law

```text
Any packet, prompt, receipt, or handoff whose stated repo state conflicts with live GitHub truth is archive-only.
```

```text
A branch-side artifact may support review, but cannot become final execution authority after merge unless regenerated or detached from the final merged head.
```

```text
If review threads remain unresolved on a verifier, source, claim, path, hash, replay, or authority surface, downstream execution is HOLD.
```

```text
If checks are green but review threads identify authority-relevant defects, review wins.
```

## Output format

Return this structure:

```text
CURRENT_HEAD:
LATEST_RELEVANT_MERGED_PR:
OPEN_RELEVANT_PR:
CURRENT_PACKET_OR_HANDOFF:
ARCHIVE_PACKETS:
CLAIM_CEILING:
GRAPH_TRUTH_HEADS:
REVIEW_THREAD_STATE:
GO_OR_HOLD:
NEXT_LAWFUL_MOVE:
WHY:
DO_NOT_DO:
```

## Go/Hold labels

Use only these labels:

```text
GO_REPO_PR
GO_REVIEW_MICROFIX
GO_DETACHED_HANDOFF_EXECUTION
GO_KAGGLE_FURNACE
HOLD_STALE_PACKET
HOLD_UNRESOLVED_REVIEW
HOLD_MERGED_MAIN_REBIND_REQUIRED
HOLD_CLAIM_CEILING
HOLD_MISSING_ARTIFACT
HOLD_SOURCE_AUTHORITY_MISMATCH
```

## Minimal answer style

Be direct:

```text
WHAT IS CURRENT
WHAT IS ARCHIVE
WHAT IS BLOCKING
WHAT TO SEND
WHAT NOT TO SEND
```

Do not produce a new architecture packet from this skill. This skill cuts authority; it does not expand scope.
