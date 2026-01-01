# W4 NAMING CONVENTIONS

## Canonical Roots
- Clean-room repo root: `KT_PROD_CLEANROOM/`
- V2 runtime root (Negative Space): `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/`

## Evidence vs Runtime
- Evidence/pointers only: `01_INPUTS_READONLY/`
- Provenance ledger (append-only intent): `02_PROVENANCE_LEDGER/`
- Comparative analysis + plans: `03_SYNTHESIS_LAB/`

## Files
- Use explicit, descriptive filenames. No “final”, “latest”, “new2”.
- Any derived artifact should declare its source inputs (paths + hashes) in its header.
