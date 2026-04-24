# Repo Boundary

This repo is meant to stay narrow, professional, and mechanically aligned to live truth.

The active root keep-set is:

- `KT_PROD_CLEANROOM/`
- `docs/`
- `ci/`
- `.github/`
- `.devcontainer/`
- root control files such as `README.md`, `REPO_CANON.md`, `.gitignore`, and `LICENSE`

The current cold or quarantined roots are:

- `KT_ARCHIVE/` externalized from the active canonical tree
- `KT-Codex/` quarantined from the active canonical tree; any local residue there is non-authoritative and must not override live posture

The current local-only scratch or forensic surfaces are:

- `_tmp/`
- `KT_PROD_CLEANROOM/tmp/`
- `KT_PROD_CLEANROOM/transcripts/`
- root `reports/` used for detached local runtime artifacts
- local worktree snapshots such as `git_status_snapshot.txt`, `git_diff_stat.txt`, `git_untracked_manifest.txt`, `git_branch_snapshot.txt`, `git_worktree.patch`, and `git_index.patch`
- local editor/cache residue such as `.vscode/`, `.pytest_cache/`, `.pytest_wave2a/`, and `.coverage`

The current local-only active overlay is:

- `.envsecrets` at the repo root

Use the live manifest at:

- `KT_PROD_CLEANROOM/reports/repo_boundary_working_manifest.json`

Use the physical relocation map at:

- `KT_PROD_CLEANROOM/reports/repo_externalization_map.json`

That manifest is the running source of truth for:

- which roots are active
- which roots are cold and should be externalized
- which roots are scratch and should not accumulate in the active tree
- which surfaces still have active dependencies and therefore need split/migration before removal

Boundary law summary:

- `KT_ARCHIVE/` is not required in the active export; archive externalization is already proven.
- `KT-Codex/` is no longer part of the active canonical tree. Historical or local residue there is lineage only unless a future receipt explicitly promotes something back into current truth.
- `_tmp/`, `KT_PROD_CLEANROOM/tmp/`, and `KT_PROD_CLEANROOM/transcripts/` are scratch and must not accumulate in canonical history.
- root `reports/` and the freeze snapshot files are local forensic support, not live theorem or product truth.
- local editor overlays such as `.vscode/` should stay outside the active tree.
- `.envsecrets` remains in the active root as an ignored local-only secret overlay required for local operator execution; it is not canonical truth and must not be committed.

Current external landing zone:

- `D:/user/rober/OneDrive/Kings_Theorem_Externalized/repo_cleanup_20260413/`
