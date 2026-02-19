---
title: "KT Codex - SME Review Plan (v1)"
volume: "KT Codex - Metadata"
chapter: "SME Review Plan"
author_role: "Program Manager"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
This plan defines the next SME review cycle for the Codex. It is scoped to reduce risk fastest: validate the technical spine first, then validate doctrine/claims, then validate commercial language. [SRC:NEEDS_VERIFICATION]

## Prioritized SME review order (next 3 chapters)
1) Volume III - Technical: `KT Pipeline Blueprint` [SRC:NEEDS_VERIFICATION]
   - Why first: load-bearing technical spine; ambiguity here compounds downstream risk.
   - Focus: correctness of Intake -> Evaluation -> Hardening -> Certification; WORM semantics; non-mutation guarantees; alignment with sealed KT V1 invariants.

2) Volume I - Doctrine: `KT Doctrine and Philosophy` [SRC:NEEDS_VERIFICATION]
   - Why second: defines the IP and claims surface; affects contracts, liability, and defensibility.
   - Focus: claims vs guarantees; terminology precision; separation of philosophy vs enforceable mechanisms.

3) Volume II - Business: `Business Model and Pricing` [SRC:NEEDS_VERIFICATION]
   - Why third: client-facing; must map offers to what KT actually outputs and can enforce.
   - Focus: deliverables vs promises; feasibility; risk allocation language; measurable acceptance artifacts.

## SME assignments (first 2)
### SME #1 - Legal / Compliance
- Assigned chapters:
  - Volume I - Doctrine and Philosophy
  - Volume II - Business Model and Pricing
- Mandate:
  - Validate regulatory framing and “claims hygiene” (no implied certifications or warranties beyond evidence).
  - Confirm the templates are clearly marked “not legal advice” and are safe scaffolding only. [SRC:NEEDS_VERIFICATION]

### SME #2 - DevSecOps / Systems Governance
- Assigned chapter:
  - Volume III - KT Pipeline Blueprint
- Mandate:
  - Validate operational realism and determinism/replay assumptions.
  - Confirm WORM guarantees and non-mutation boundaries are described as enforceable checks, not wishes.
  - Stress-test CI-sim vs canonical lanes and the operator boundary model. [SRC:NEEDS_VERIFICATION]

## Review mechanics (annotation-only pass)
- SMEs annotate using markers only; do not rewrite prose inline without explicit owner approval:
  - `>>REVIEW:LEGAL:<comment>`
  - `>>REVIEW:DEVSECOPS:<comment>`
- Any recommended change that would alter KT sealed V1 law surfaces must be flagged explicitly as a governed change request (out of scope for Codex documentation). [SRC:NEEDS_VERIFICATION]

## Explicit deferral (intentional)
- Volume IV services expansion
- Volume V operations depth expansion
- Volume VI appendices and index expansion

Reason: these scale from the foundations above and should not be locked until SME corrections propagate. [SRC:NEEDS_VERIFICATION]

