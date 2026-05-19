# Current vs Archive Context Policy

Purpose: keep agents, reviewers, and operators focused on current authority without deleting historical proof.

Current context should load first:

- current state and allowed claims boundary
- current blocker ledger
- current receipts and validation reports
- current launch-wedge documents
- current external attestation intake package
- active operator tools and tests

Archive context should be indexed, hashable, and searchable, but not default-loaded:

- old branch-bound artifacts
- superseded packet drafts
- historical generated reports
- old conversation exports
- forensic dumps
- stale proof bundles

Cleanup mode:

Demote, hash, archive, and index stale material. Do not delete proof unless a separate retention/deletion authority exists.
