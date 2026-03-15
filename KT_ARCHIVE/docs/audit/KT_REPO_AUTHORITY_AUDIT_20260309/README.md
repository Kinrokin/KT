# KT Repo Authority Audit 2026-03-09

## Target Pin

| Field | Value |
| --- | --- |
| branch | `main` |
| head | `46173df31a9242c2e8f4bd7a1494b3466d1a89b9` |
| `origin/main` | `4cf1b9d100f8699fa192d6a5409c69bc6e94761d` |
| tracked worktree | clean |
| remote parity | no, local `main` is ahead by 6 commits |
| clean-clone equivalent | no |
| ignored local residue | present |

## Inventory First

| Measure | Count |
| --- | --- |
| tracked files | 1635 |
| canonical | 1015 |
| lab | 306 |
| archive | 97 |
| commercial | 139 |
| generated/runtime truth | 75 |
| quarantined | 3 |

## Residue Outside The Tracked Census

| Path | Files | Directories |
| --- | --- | --- |
| `.venv` | 887 | 134 |
| `.pytest_cache` | 5 | 2 |
| `__pycache__` | 1 | 0 |
| `KT_PROD_CLEANROOM/exports` | 66982 | 22733 |
| `exports` | 28 | 23 |

Secret-like local residue observed: `.env.secret`

## Stale Tracked Truth Surfaces

- `KT_PROD_CLEANROOM/reports/current_state_receipt.json` still validates `4cf1b9d100f8699fa192d6a5409c69bc6e94761d`
- `KT_PROD_CLEANROOM/reports/runtime_closure_audit.json` still validates `4cf1b9d100f8699fa192d6a5409c69bc6e94761d`
- `KT_PROD_CLEANROOM/reports/posture_consistency_receipt.json` still validates `4cf1b9d100f8699fa192d6a5409c69bc6e94761d`
- `KT_PROD_CLEANROOM/reports/live_validation_index.json` still points at `79cec06bbfa8e8b38331712596c79976a863b5f2`

Fresh live validation was run against `HEAD` and produced `CANONICAL_READY_FOR_REEARNED_GREEN`, but the tracked truth surfaces were not resynced afterward.

## Artifact Index

- `repo_target.json`: pinned branch, head, remote divergence, and target status
- `repo_census.csv`: path-by-path classification for every tracked file
- `repo_census_summary.json`: zone, authority, status, and recommendation counts
- `trust_zone_registry.json`: recommended six-zone registry for this repo
- `local_residue_summary.json`: ignored local residue outside the tracked census
- `current_head_truth_source.json`: single current-head truth anchor for this packet
- `blocker_matrix.json`: machine-readable blockers derived from the ordered work plan
- `operator_posture_note.md`: short operator rule for documentary-only and non-posture surfaces
- `IMPLEMENTATION_COMPLETION_REPORT_20260309.md`: completion delta for the law-enforcement tranche
- `system_atlas.md`: system boundaries, flows, dependencies, and contradiction surfaces
- `truth_authority_map.md`: authoritative vs documentary vs stale surfaces
- `subsystem_scorecard.md`: separate closure and capability grades by subsystem
- `workset_and_priority_order.md`: freeze, ratify, archive, quarantine, and ordered repair plan
- `final_kt_snapshot.md`: the current repo-state snapshot after classification

## Evidence Basis

- tracked inventory from `git ls-files`
- pinned state from `git branch --show-current`, `git rev-parse HEAD`, `git rev-parse origin/main`, and `git status --short --branch`
- fresh head validation from `tmp/kt_truth_matrix_20260309_head.json`
- fresh posture reconciliation from `tmp/kt_truth_engine_20260309/posture_consistency_enforcement_receipt.json`
- fresh conflict evidence from `tmp/kt_truth_engine_20260309/posture_conflict_receipt.json`
