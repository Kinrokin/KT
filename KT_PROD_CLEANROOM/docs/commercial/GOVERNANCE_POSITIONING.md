# Governance Positioning (Commercial Stance)

This document defines how KT is positioned in contracts and client communications. It prevents scope confusion between:
- **governance enforcement + evidence production** (what KT does mechanically), and
- **governance consulting / compliance mapping** (separate work, separate deliverables).

This is not legal advice.

## Option A — Governance enforcement substrate (recommended default)
**Positioning:** KT is an evidence engine and governance enforcement substrate. It produces replayable, deterministic proof artifacts under a pinned scope.

**You deliver**
- WORM run artifacts + delivery bundle (zip + sha256 + replay wrappers + manifests + verdict).
- Mechanical acceptance criteria tied to those artifacts.
- Drift/regression and adversarial reports when those SKUs are in scope.

**You do not deliver (unless separately contracted)**
- SOC2/ISO/HIPAA narratives, mapping tables, or “regulatory interpretation”.
- Board policy writing, legal conclusions, or attestations beyond the artifact contract.

**Why this works**
- It is scalable, defensible, and does not require you to claim authority over the client’s governance framework.

## Option B — KT + governance consulting wrapper
**Positioning:** KT evidence + consulting that maps the evidence into a client’s governance framework (control language, policy drafts, audit prep).

**Additional deliverables**
- Control mapping doc (e.g., “evidence → control objective → coverage gap”).
- Governance recommendations + change control plan.
- Pre-audit package review support.

**Risk**
- Requires domain expertise and careful disclaimers. Treat as a separate SKU/statement of work.

## Option C — White-label compliance backbone (partner channel)
**Positioning:** KT is the backbone for partners (auditors, consultancies, GRC vendors) who provide the governance wrapper.

**You deliver**
- Tooling + artifact contract + training.
- Partner-facing runbooks and acceptance checklists.

**Partner delivers**
- The compliance narrative, controls mapping, and client-facing policy interpretation.

## Recommended contract language (short)
- “Vendor will provide deterministic, replayable evidence artifacts and mechanical acceptance checks as described in the Delivery Bundle Spec. Vendor does not provide legal advice or compliance certification unless explicitly stated as a separate deliverable.”

## How to choose
- Choose **A** if you want a pure product/evidence posture and rapid sales cycles.
- Choose **B** if your team can credibly staff governance consulting.
- Choose **C** if you want scale through partners and strict boundary control.

