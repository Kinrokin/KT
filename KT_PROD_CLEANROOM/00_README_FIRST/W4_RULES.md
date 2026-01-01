# W4 RULES (KT_PROD_CLEANROOM)

## Authority Lock
- `KT_TEMPLE_ROOT/` is KT_TEMPLE_V1 and is **law** and **read-only**.
- `KT_MASS_REALITY/` is read-only input evidence (variants + priors); provenance must be preserved.
- `KT_PROD_CLEANROOM/` is the only writable location for W4 work.

## Safety Posture (Non-Negotiable)
- Safety-critical infrastructure: fail-closed on ambiguity, incompleteness, or unprovable claims.
- No silent fallbacks, no mock substitutions, no “best guess” execution paths.
- No destructive edits to Mass Reality or KT_TEMPLE_V1.

## Negative Space (V2)
- Only `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/` may be runtime-importable.
- `tests/`, `tools/`, `docs/` are non-runtime only.

## Runtime Prohibitions (Unless Explicitly Authorized Later)
- No providers or network calls in runtime.
- No UI in runtime.
- No training/curriculum/epochs in runtime.

## Super-Gates (Binding)
- Gate A: Dominance proof over KT_TEMPLE_V1 (correctness/robustness/governance/safety).
- Gate B: Controlled evolution (W >= I): every transplant/synthesis must have an evidence package and tests proving improvement.

## W4.0 Hard Stop
- No indexing, scanning, or code copying into `04_PROD_TEMPLE_V2/` until authority is locked under W4.0 deliverables.
