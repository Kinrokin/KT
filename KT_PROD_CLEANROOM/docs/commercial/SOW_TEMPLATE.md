# Statement of Work (Template) - KT Governed Evidence Delivery

This template is intentionally artifact-driven: deliverables are accepted only when the referenced hashes and verdict lines exist.

## 1. Scope
- Provide governed verification runs using KT's canonical sweep harness and operator tooling.
- Produce WORM evidence packs and one-line verdict strings.

## 2. Customer Responsibilities (Inputs)
- Provide a pinned repository checkout (tag/commit).
- Provide execution environment (offline) and local storage for `KT_PROD_CLEANROOM/exports/_runs/...`.
- If canonical lane verification is required: provide HMAC keys in environment (never shared; no logging of key material).

## 3. Deliverables
- One or more evidence run directories under `KT_PROD_CLEANROOM/exports/_runs/...` containing:
  - `verdict.txt`
  - `sweep_summary.json` + logs
  - validation reports (as produced by the sweep harness)
- Optional delivery ZIP created from the run directory (no repo mutation).

## 4. Acceptance Criteria
- Sweep harness status `PASS`.
- Law bundle hash matches the pinned `LAW_BUNDLE_FL3.sha256`.
- Suite registry validates and matches pinned `suite_registry_id`.
- Worktree remains clean before and after each run.
- Evidence is WORM-correct (no overwrite).

## 5. Non-Negotiable Constraints
- Fail-closed: any mismatch/ambiguity stops the run.
- No network access; no dependency installs during runs.
- No secrets printed or stored in artifacts.

## Appendix: Delivery Bundle Spec
- See `docs/commercial/KT_DELIVERY_BUNDLE_SPEC.md` for the standard artifact-driven delivery layout.
