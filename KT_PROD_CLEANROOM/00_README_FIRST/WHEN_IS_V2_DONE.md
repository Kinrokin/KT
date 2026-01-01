# When Is V2 Done? (KT_TEMPLE_V2 Completion Criteria)

This document defines the **fail-closed** criteria for declaring `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/` complete and freezing it as **KT_TEMPLE_V2**.

V2 is **DONE iff** every gate below is proven `PASS`, all required artifacts exist, and there are **zero open exceptions**.

## G0 — Authority Lock (Precondition)

- `KT_TEMPLE_ROOT/` remains **KT_TEMPLE_V1** (law; read-only).
- `KT_MASS_REALITY/` remains read-only evidence (no destructive edits).
- `KT_PROD_CLEANROOM/` is the only writable W4 location.
- V2 Negative Space is enforced: **only** `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/` is runtime-importable.
- No Silent Auto-Discovery: runtime entrypoint path, Spine entry function, vault path, and runtime import roots must be explicitly declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` (no convention-based searching).

## G1 — Runtime Topology (Single Execution Path)

- Exactly one canonical runtime entrypoint exists under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/` (the Entry organ).
- Entry does only: validate envelope (via schemas + invariants) → call Spine → exit.
- No other runtime invocation routes exist (no alternate CLIs, runners, or `__main__` guards in runtime surface).
- Spine Definition (substrate mode): Spine is the minimal orchestrator callable declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json` that exercises gates + schema validation + state vault + governance event logging without external providers.

## G2 — Import Truth (Organ Sovereignty)

- Allowed organ→organ import matrix is defined and enforced (static + import-time guard).
- Runtime Surface: `src/` is necessary but not sufficient — only approved runtime package roots (declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`) are importable at runtime; any other module under `src/` must fail Import Truth.
- Adapters remain leaf-level; provider SDKs are never imported at module import-time in runtime organs.
- Training-only / non-runtime paths are not importable from runtime (`tests/`, `tools/`, `docs/`, datasets, curriculum, epochs).

## G3 — Schemas Are the Contract Perimeter (C002)

- **No data crosses a runtime boundary without schema validation** (Entry input, organ deltas, persistence envelopes).
- Unknown fields are rejected (no silent drops).
- Oversized values are rejected (bounded strings/arrays/objects and bounded total payload size).
- Schema registry is explicit + hash-addressed (no “latest”, no auto-upgrade, no fallback).

## G4 — State Vault Is the Sole Persistence Authority (C008)

- Single append-only JSONL vault location is defined (Temple-only runtime artifact).
- Writes are crash-safe and streaming-safe (no whole-file reads, newline/partial-write detection).
- Records are schema-validated (C002) and hash-chained (parent continuity).
- Replay is deterministic and fail-closed on truncation, corruption, insertion, reordering, or mismatch.
- No “best effort repair” modes exist.

## G5 — Temporal Integrity (Receipts + Replay Binding)

- Every persisted record binds:
  - `constitution_version_hash`
  - `schema_id`
  - `schema_version_hash`
  - `event_hash`, `payload_hash`, `parent_hash`
- Replay selects historical logic strictly by recorded hashes; if not available/known → **halt** (no fallback).
- Retroactive reinterpretation is forbidden; only forward-versioned evolution is permitted.

## G6 — Context Poisoning Defense (Bounded Deltas)

- Receipt/state-vault payload surfaces are hash-only or bounded by schema; no raw prompts, no raw context, no unbounded arrays/strings.
- Any organ emitting deltas/persistence must be explicitly schema-bounded; utilities may not emit deltas.
- Bloat vectors are mechanically rejected (schema + invariants gate).

## G7 — Security Baseline (Secrets + Provider Discipline)

- S3 Constitutional Guard remains `PASS` for `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/`.
- No secrets are present in-repo (no `.env`, no key literals, no private key blocks) on runtime surface.
- Providers remain disabled-by-default unless a separate authorization explicitly enables live providers.
- No-Network Dry-Run Rule: verification must prove that dry-run execution performs **zero** network calls (direct or indirect).

## G8 — Verification (Proof, Not Hope)

Minimum required proofs must exist and be reproducible (low-RAM safe mode):

- Import Truth verification: `PASS`
- Negative Space verification: `PASS`
- Single execution path proof: `PASS`
- Schema rejection-path tests: `PASS`
- State vault tamper/truncation/reorder tests: `PASS`
- Replay matrix tests: `PASS` (unknown hash → fail-closed)
- Dry-run canonical run through Entry → Spine → organs succeeds without external providers/network calls.

## G9 — Release Freeze (Gold Master)

V2 may be frozen as **KT_TEMPLE_V2** only when:

- A complete, deterministic release manifest exists for **every file** under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`:
  - `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_RELEASE_MANIFEST.jsonl`
  - Deterministic ordering, full coverage, and **byte-identical** across two independent hashing passes (same lines, same order, same bytes)
- A human-readable seal document exists declaring the proven guarantees and out-of-scope items (constitutional tone).
- Decision log records the freeze with pointers to:
  - manifest
  - seal
  - final verification report set
- “No further mutations” attestation is recorded under V2 docs.

## Substrate Closure Rule (W4.5 loop)

V2 is not “done” if any integrated concept is missing any of:

- plan (`03_SYNTHESIS_LAB/04_ACTION_PLANS/W4_5_CONCEPT_<ID>_PLAN.md`)
- verification report (lab + V2 docs mirror)
- (if substrate) substrate seal doc under `04_PROD_TEMPLE_V2/docs/`
- append-only manifest entries for all touched files
- decision log entry + phase-gate update

## Fail-Closed Declaration

If any gate is `FAIL` or `UNKNOWN`, V2 is **NOT DONE**.

The only legal outputs at that point are:

- a blocker list (exact file paths + missing proofs), and
- a request for explicit authorization to proceed with the minimum corrective concept needed.
