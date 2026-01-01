# W4.5 DIFF RATIONALE (TEMPLATE)

Concept ID: `<C###>`
Concept Name: `<name>`
Created At (UTC): `<YYYY-MM-DDTHH:MM:SSZ>`

Purpose: S1 "Ghost of Versions Past" triple-diff. Prevent phantom dependency reimplantation.

## Inputs (Evidence Pointers Only)
- V1 manifest (snapshot): `KT_PROD_CLEANROOM/01_INPUTS_READONLY/TEMPLE_V1_SNAPSHOT/TEMPLE_RELEASE_MANIFEST.jsonl`
- Candidate pointers (Mass Reality paths): `<paths>`
- Current V2 working tree: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`
- W4 indexes (hash/AST/import graph): `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/01_CORPUS_INDEX/`

## Mapping: Candidate ↔ V1 ↔ V2
Candidate module(s) (paths only):
- `<candidate path>`

V1 baseline analogue(s) (path + hash from V1 manifest; "none" is allowed if provable):
- `<v1 path> sha256=<hash>`

V2 target location(s) (planned paths under V2; may be absent pre-implementation):
- `<v2 path>`

## Diff A — Candidate vs V1 (Historical Divergence)
Evidence (hash/AST/imports; no full file diffs required):
- Candidate sha256: `<hash>`
- V1 sha256: `<hash or none>`
- Candidate imports (summary): `<list>`
- V1 imports (summary): `<list>`
- Candidate public symbols (classes/functions): `<list>`
- V1 public symbols (classes/functions): `<list>`

What changed historically?
- `<answer>`

Why did it diverge historically?
- `<answer>`

Evidence pointers supporting "why" (required; paths only):
- `<paths>`

## Diff B — V1 vs Current V2 (Evolution Already in V2)
Evidence (manifest/hash comparison; no code execution):
- V1 file hash(es): `<hashes>`
- V2 file hash(es): `<hashes>`

What already evolved in V2?
- `<answer>`

## Diff C — Candidate vs Current V2 (Re-implant Delta)
Evidence (hash/AST signature comparison):
- Candidate sha256: `<hash>`
- V2 sha256: `<hash or none>`
- Import surface delta: `<summary>`
- Symbol surface delta: `<summary>`

What would change if the candidate were reintroduced?
- `<answer>`

## Constitutional Risk Check (Fail-Closed)
Was the divergence fixing a bug, closing a loophole, or enforcing governance?
- `<answer>`

Does reintroducing candidate logic violate current schema/receipt constraints (S2)?
- `<answer>`

Does reintroducing candidate logic introduce any disqualification patterns?
- `<answer>`

## Verdict
Verdict: `<Proceed / Blocked>`
If blocked, list blockers (evidence pointers):
- `<blocker>`
