# HMAC Key Rotation (Operator Runbook)

This runbook rotates `KT_HMAC_KEY_SIGNER_A` and `KT_HMAC_KEY_SIGNER_B` **without ever printing the key values** to stdout/stderr.

## Why rotate
Rotate immediately if:
- key material was pasted into chat, logs, tickets, or screenshots
- key material may have been captured by screen recording or terminal logging
- you cannot prove key custody

## Rotation (Windows PowerShell)
Use the provided helper (session-only by default):
- `KT_PROD_CLEANROOM/tools/operator/rotate_hmac_keys.ps1`

Run in your current PowerShell session (recommended; session-only, persists in that shell):
- `& "KT_PROD_CLEANROOM/tools/operator/rotate_hmac_keys.ps1"`

If your execution policy blocks scripts, set a **process-scoped** bypass for the current shell (does not persist system-wide), then run:
- `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`
- `& "KT_PROD_CLEANROOM/tools/operator/rotate_hmac_keys.ps1"`

Optional (persist to **User** environment variables; still does not print key values):
- `& "KT_PROD_CLEANROOM/tools/operator/rotate_hmac_keys.ps1" -PersistUser`

What the script prints (safe):
- presence + length only
- sha256 fingerprints of the key strings (non-reversible)

## Verification (safe)
Presence/length only:
- `python -c "import os; print({k:{'present':bool(os.getenv(k)),'length':len(os.getenv(k) or '')} for k in ['KT_HMAC_KEY_SIGNER_A','KT_HMAC_KEY_SIGNER_B']})"`

Operator status proof (prints no key values):
- `python -m tools.operator.kt_cli --profile v1 status`

## Critical consequence (fail-closed)
Rotating the keys will cause **canonical-lane HMAC verification to FAIL_CLOSED** until all HMAC-pinned artifacts are re-signed under the new keys.

In this repo, the following are HMAC-pinned and will not validate under rotated keys:
- suite registry signoffs (`KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json`) via `hmac_key_fingerprint`
- any HMAC-attested law amendments already sealed and referenced by the law bundle

Practical impact:
- `python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac` will fail until a governed reseal/re-attestation process is executed.

## Safety rules
- Never print key values.
- Never write key values to disk (repo, run roots, temp files).
- Prefer storing long-lived keys in an OS secret store; use session-only env vars for short-lived operations.
- Treat rotated-out keys as permanently compromised; do not reuse.
