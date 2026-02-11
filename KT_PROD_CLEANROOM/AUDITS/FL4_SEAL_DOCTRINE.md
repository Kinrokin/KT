# FL4 SEAL DOCTRINE (binding)

This doctrine is binding for seal closure.

- Canonical lane is FL4 MRT-0 (AdapterType.A-only): policy bundles only, no weight artifacts.
- Fail-closed supremacy: missing/malformed/unverifiable -> FAIL. Diagnostics may surface cause, never bypass gates.
- Traits are diagnostic-only during seal closure (no adaptive/learned "judge" semantics in the seal lane).
- Law-bundle binding: the seal evidence pack must include `LAW_BUNDLE_FL3.json` and `LAW_BUNDLE_FL3.sha256`.
