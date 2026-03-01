# Pre-Sales Diagnostic (Operator-Ready Intake)

This intake is designed to (1) select the right SKU(s), and (2) ensure the engagement can be executed in a boring, offline, fail-closed way with replayable evidence.

## What we will not ask for
- Secrets/keys in plaintext (ever).
- Production customer data unless explicitly contracted and handled out-of-band.
- Permission to install arbitrary dependencies on client machines.

## Minimal “Proof of Life” demo (no client data required)
These commands produce a client-verifiable run directory under `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/**`:
- `python -m tools.operator.kt_cli --profile v1 status`
- `python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim`
- (optional) `python -m tools.operator.kt_cli --profile v1 hat-demo`

## Intake questions (copy/paste)
### A) Scope
1) What are you certifying: a repo tag/commit, a container image digest, or both?
2) Which SKU(s) do you want now: `SKU_CERT`, `SKU_RA`, `SKU_CG`, `SKU_OVERLAY`, `SKU_FORGE`?
3) What’s the decision you need to support: vendor onboarding, audit response, incident response, product launch, insurance renewal?

### B) Environment and constraints
4) Can the run environment be offline (no network) for audit-grade runs?
5) Can we write WORM evidence under `KT_PROD_CLEANROOM/exports/_runs/**`?
6) Are dependency installs forbidden during the run? (Recommended: yes.)

### C) Evidence and replay expectations
7) Who must be able to replay the bundle: internal security, external auditor, customer, insurer?
8) What is the replay target OS: Linux, Windows, both?
9) Do you require a one-line paste-safe verdict for board/audit artifacts? (Recommended: yes.)

### D) Keys and attestations (canonical lane)
10) Do you want the audit-grade `canonical_hmac` lane? If yes, confirm HMAC keys exist in environment:
   - `KT_HMAC_KEY_SIGNER_A` present (do not share value)
   - `KT_HMAC_KEY_SIGNER_B` present (do not share value)

### E) Model/adapters (if in scope)
11) Are you evaluating a base model snapshot, adapters, or both?
12) Are model artifacts available offline as local paths? (Operator lanes do not fetch.)

### F) Domain overlays
13) Which overlays do you want applied (if any)? Example: finance/healthcare/security.
14) Do you want strict mode (fail-closed on missing overlay or hash mismatch)? (Recommended: yes.)

### G) Continuous governance (if in scope)
15) Do you have baseline run directories to diff against? If not, do you want the first run to become baseline?
16) What drift thresholds should hard-fail vs warn?

### H) Forge (if in scope)
17) Is training allowed (separate lane), or do you want a stub rehearsal first?
18) What promotion policy do you want (must-improve, no-regress metrics, temporal fitness memory)?

## Red flags (fail-closed reasons)
- Unpinned scope (“latest main”), or inability to identify the system state.
- Evidence cannot be written WORM, or run roots are not preserved.
- Client requires audit-grade claims but cannot provide canonical key management.

## Output of this diagnostic
At the end of intake, the proposal should contain:
- SKU selection + lane mapping
- explicit inputs required (paths, pins, keys presence-only)
- deliverables (artifact list) and acceptance criteria

