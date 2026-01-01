# KT_TEMPLE_V2 SEAL (Gold Master Declaration)

This document declares the KT V2 Temple (`KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/`) as a sealed, auditable constitutional substrate.

## Proven Guarantees (Constitutional)

- **Single Runtime Path (Declared):** canonical runtime execution is `Entry -> Spine -> exit`, as declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`.
- **Negative Space:** runtime-importable surface is restricted to allowlisted roots under `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/`.
- **Import Truth (Enforced):** illegal runtime imports fail closed at import time via the import guard, using the allowlist + organ matrix declared in `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`.
- **Schemas as Contract Perimeter:** schema binding is explicit; unknown fields and oversized payloads are rejected (fail-closed).
- **State Vault Sovereignty:** persistence is append-only JSONL, schema-validated, hash-chained, and replay-verified (fail-closed on corruption or drift).
- **Governance Logging (Hash-Only):** governance events persist only hashes via the state vault; no raw prompts/context/policy internals.
- **No-Network Dry-Run Proof:** dry-run verification proves zero network calls (fail-closed on any socket usage).

## Gold Master Fingerprint (Release Manifests)

- Full-tree fingerprint: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_FULL_RELEASE_MANIFEST.jsonl`
- Two-pass stability proof: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/V2_MANIFEST_STABILITY_PROOF.md`
- Self-exclusion rule: `docs/V2_FULL_RELEASE_MANIFEST.jsonl` excludes itself from enumeration (self-referential inclusion is not well-defined); this exception is explicitly documented and proven.

## Explicit Non-Goals (Out of Scope)

- Live providers / SDK execution
- Routing strategies, adapters, or cognition engines (Crucible / CouncilRouter)
- Training, curriculum, epochs, datasets
- Performance tuning / cost optimization
- UI/API surfaces beyond the declared canonical entry

## Change Control (Non-Negotiable)

Any change to V2 (including docs that define runtime truth) requires:

1) explicit new authorization  
2) updated verification proving all invariants remain PASS  
3) an updated release manifest and full-tree freeze  

No hotfixes. No silent edits. Fail-closed.
