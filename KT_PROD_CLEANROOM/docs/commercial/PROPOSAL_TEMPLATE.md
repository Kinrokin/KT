# Proposal Template — KT Operator Factory Engagement

This template is artifact-driven: deliverables are accepted only when the referenced run directories, manifests, and hash receipts exist.

## 0) Cover
- Client: `<CLIENT_NAME>`
- Engagement ID: `<ENGAGEMENT_ID>`
- Date: `<YYYY-MM-DD>`
- Primary decision supported: `<vendor_onboarding | audit_response | incident_response | launch_gate | insurance_renewal>`

## 1) Executive summary (non-technical)
We will produce replayable, deterministic evidence bundles that answer: `<ONE_SENTENCE_RISK_QUESTION>`.

## 2) Scope (what we will run)
Select SKUs (check all that apply):
- [ ] `SKU_CERT` — Certification Pack (Point-in-Time Proof)
- [ ] `SKU_RA` — Red Assault (Adversarial Evaluation + Failure Library)
- [ ] `SKU_CG` — Continuous Governance (Drift + Regression Diffs Over Time)
- [ ] `SKU_OVERLAY` — Domain Overlay Pack(s)
- [ ] `SKU_FORGE` — Adapter Forge (Train → Validate → Promote/Block → Deliver)

Constraints (defaults):
- Offline execution: `[ ] required  [ ] not required (practice only)`
- No dependency installs during run: `[ ] required`
- WORM outputs under `KT_PROD_CLEANROOM/exports/_runs/**`: `[ ] required`

## 3) Inputs required from client
- Pinned scope: `<git_tag | git_commit | container_digest | other>`
- Execution environment: `<linux/windows>`, offline mode `<yes/no>`
- For canonical lane (if in scope): confirm key presence only:
  - `KT_HMAC_KEY_SIGNER_A` present
  - `KT_HMAC_KEY_SIGNER_B` present
- (If model/adapters in scope) local artifact paths: `<...>`
- (If overlays in scope) overlay ids: `<...>`
- (If continuous gov in scope) baseline run dir(s): `<...>`

## 4) Operator runbook (commands)
All runs use the stable operator CLI interface:
- Status: `python -m tools.operator.kt_cli --profile v1 status`
- Certify (audit-grade): `python -m tools.operator.kt_cli --profile v1 certify --lane canonical_hmac`
- Certify (wiring only): `python -m tools.operator.kt_cli --profile v1 certify --lane ci_sim`
- Red assault: `python -m tools.operator.kt_cli --profile v1 red-assault ...`
- Continuous gov: `python -m tools.operator.kt_cli --profile v1 continuous-gov ...`
- Overlay apply: `python -m tools.operator.kt_cli --profile v1 overlay-apply ... --strict`
- Forge: `python -m tools.operator.kt_cli --profile v1 forge ...`

## 5) Deliverables (artifact contract)
For each SKU run, we deliver:
- A WORM run directory under `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/<UTC_TS>_<purpose>/`
- A delivery bundle: ZIP + sha256 + replay wrappers + manifests + one-line verdict

Reference spec:
- `KT_PROD_CLEANROOM/docs/commercial/KT_DELIVERY_BUNDLE_SPEC.md`

## 6) Acceptance criteria (mechanical)
Accepted when:
- sweep/lane status is `PASS` for the agreed scope
- `evidence/secret_scan_report.json` is `PASS`
- delivery linter status is `PASS`
- replay wrappers exist and the client can recompute zip sha256 to match the provided receipt

If any gate fails:
- we fail-closed, produce a next-action note, and do not represent the run as audit-grade PASS.

## 7) Timeline
- Kickoff: `<date>`
- Execution window: `<date range>`
- Delivery: `<date>`
- Optional replay session with client/auditor: `<date>`

## 8) Pricing logic (framework; fill in numbers separately)
Components you may combine:
- base engagement fee (setup + execution + delivery)
- per-run fee (if multiple pinned states/runs)
- per-overlay fee (SKU_OVERLAY)
- cadence retainer (SKU_CG)
- per-iteration fee (SKU_FORGE)
- compute/hardware pass-through (if real training is enabled)

## 9) Exclusions / assumptions
- No legal advice unless explicitly contracted.
- No access to production secrets; keys remain in client environment and are never printed.
- No network-based fetching in audit-grade lanes.

## 10) Change control
Any expansion of scope (new packs, new overlays, new baselines) requires a written change order and produces a new run id + new artifacts.

