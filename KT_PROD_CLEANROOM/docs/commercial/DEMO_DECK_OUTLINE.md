# Demo Deck Outline — KT Operator Factory

This is a slide-by-slide outline for a client-facing deck. Keep it evidence-backed: screenshots and excerpts should reference the run directory artifacts, not claims.

## Slide 1 — Title
- “Deterministic AI Governance Evidence (Replayable, Fail-Closed)”
- Client name + date + engagement id

## Slide 2 — The problem
- AI risk is a governance problem: drift, silent regressions, adversarial prompting, unverifiable claims.
- Auditors/insurers/boards need replayable proof, not narratives.

## Slide 3 — What KT delivers
- One-line verdicts + WORM evidence packs + replay wrappers.
- Determinism and tamper resistance as first-class gates.

## Slide 4 — What KT does not claim
- Not legal advice; not “safety certification”.
- KT provides evidence about a pinned scope under defined evaluation packs.

## Slide 5 — The factory lanes (the product ladder)
- `SKU_CERT`: point-in-time integrity proof
- `SKU_RA`: adversarial evaluation + failure taxonomy
- `SKU_CG`: drift/regression governance over time
- `SKU_OVERLAY`: domain overlays (scope/policy/reporting)
- `SKU_FORGE`: controlled adaptation with promotion gates

## Slide 6 — The artifact contract (why this is defensible)
- Show: `verdict.txt`, `delivery_manifest.json`, zip sha256, `replay.sh` / `replay.ps1`.
- Acceptance is mechanical (paths + hashes + PASS statuses).

## Slide 7 — Example: Certification Pack output
- Screenshot: run directory tree
- Highlight: sweep summary PASS + one-line verdict + manifest pins

## Slide 8 — Example: Red Assault output
- Show: `red_assault_summary.json`, `failure_taxonomy.json`, top failures sample.
- Emphasize: bounded, hash-referenced packs; no sensitive payload embedding.

## Slide 9 — Example: Continuous Governance output
- Show: drift/regression report excerpts; explain thresholds and fail-closed behavior.

## Slide 10 — Overlays: domain tailoring without law changes
- Overlay ids, strict apply, overlay diff/effect summary.

## Slide 11 — Forge: controlled remediation
- Before/after metrics + promotion gate.
- Explain: promotion is blocked unless all dependencies pass.

## Slide 12 — Engagement flow
- Pre-sales diagnostic → kickoff → run(s) → delivery bundle → client replay → optional cadence.

## Slide 13 — Commercial packaging
- SKU ladder with timelines (ranges) and pricing logic (no numbers on slides unless you want to).

## Slide 14 — Next steps
- Choose SKU(s), pin scope, schedule execution window, define acceptance gates.

