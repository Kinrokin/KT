# V2 Full Manifest Stability Proof (Two-Pass)

Objective:
- Prove `docs/V2_FULL_RELEASE_MANIFEST.jsonl` is deterministic and byte-stable across two independent generation passes.

Result: PASS

Method (fail-closed):
- Enumerate all files under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/` (lexicographic by relative path).
- For each file, record: `path`, `bytes`, `mtime_utc`, `sha256`.
- Exclude `docs/V2_FULL_RELEASE_MANIFEST.jsonl` from enumeration (self-referential inclusion is not well-defined).
- Generate manifest twice to independent temporary outputs.
- Compare the two outputs byte-for-byte; if not identical, halt.

Notes (non-negotiable):
- This proof does not embed the manifest hash inside any file covered by the manifest; the stability claim is based on byte-identical comparison only (no circular dependency).
