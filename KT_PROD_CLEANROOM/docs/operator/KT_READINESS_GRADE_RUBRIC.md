# KT Readiness Grade (Rubric, v1)

This rubric produces an evidence-backed readiness grade for KT as an **operator factory**.
It is not a marketing score; it is a mechanical checklist with explicit failure semantics.

Two separate grades are produced:
- **Audit-grade readiness**: requires clean worktree, pinned anchors, offline posture, replayable delivery bundles.
- **Practice readiness**: allows dirty worktree / rehearsal lanes but must still be deterministic and fail-closed.

## Grade bands
- `A` = 90–100
- `B` = 80–89
- `C` = 70–79
- `D` = 60–69
- `F` = <60

If any **terminal blocker** is present, overall status is `HOLD` regardless of score.

## Terminal blockers (force HOLD)
1) Key compromise not remediated (known leak; no rotation + reseal plan)
2) Canonical lane cannot be executed in a clean environment (pins or law bundle mismatch)
3) Replay verification fails for delivered bundles
4) Secret scan fails for any client delivery bundle

## Scoring dimensions (100 points)
### 1) Integrity anchors (20)
- sealed tag resolves to sealed commit (10)
- law bundle hash recompute matches pinned sha256 (5)
- suite registry id + determinism anchor match pinned profile (5)

### 2) Evidence + delivery discipline (20)
- WORM run roots under `KT_PROD_CLEANROOM/exports/_runs/**` (5)
- delivery bundle emitted (zip + sha256 + manifest + replay wrappers) (10)
- delivery linter + secret scan both PASS (5)

### 3) Factory lanes operable (20)
- `status` lane PASS (2)
- `certify ci_sim` produces expected fail-as-expected semantics (3)
- `certify canonical_hmac` PASS in a clean environment (10)
- `red-assault`, `continuous-gov`, `overlay-apply`, `forge` all execute and emit required artifacts (5)

### 4) Domain pressure posture (20)
- domain playbooks exist and define high-pressure portfolios (5)
- fintech (or primary vertical) portfolio meets minimum breadth targets (5)
- metamorphic pack generator exists and is used deterministically (5)
- dual-use policy enforced via gated redpack hash refs (5)

### 5) Promotion governance (10)
- promotion gates are explicit and fail-closed (5)
- temporal fitness / regression blocking posture documented (5)

### 6) Operational hardening (10)
- no secrets printed (presence/length only) in operator lanes (5)
- clean-machine replay instructions exist and are tested (5)

## Output artifact contract
Readiness grading must emit:
- `readiness_grade.json` (machine)
- `readiness_grade.md` (human summary)
- inputs: git head, git status, and references to the lane run dirs used as evidence

## How to run (operator)
Practice readiness (allows dirty worktree):
- `python -m tools.operator.readiness_grade --profile v1 --allow-dirty`

Audit readiness (fail-closed on dirty worktree):
- `python -m tools.operator.readiness_grade --profile v1`
