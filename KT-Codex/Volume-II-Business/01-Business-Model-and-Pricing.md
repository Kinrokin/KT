---
title: "Business Model and Pricing"
volume: "Volume II - Business Model, Pricing, and Go-To-Market"
chapter: "Chapter 1"
author_role: "Executive Author"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:ISO-9001", "SRC:REG:NIST-AI-RMF-1.0", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume II - Business Model, Pricing, and Go-To-Market
### Chapter 1 - Business Model and Pricing

#### Chapter intent (plain-English)
KT’s business model is selling measurable governance outcomes: deterministic evidence, repeatable certification, and ongoing drift resistance. This chapter defines a three-offer portfolio, pricing drivers, and acceptance language that maps directly to artifacts. [SRC:REG:ISO-9001]

#### Persona Matrix
| Persona | Start here | Outcome |
|---|---|---|
| Executive Author | Executive Summary | Position KT as a governance outcome with proof. |
| Program Manager | Manager Playbook | Deliver engagements with predictable artifacts and timelines. |
| Systems Architect | Engineer Manual | Automate packaging and verification without weakening constraints. |

#### Sealed V1 anchors (reference, read-only)
Plain-English: these anchors are treated as immutable facts for KT V1; business promises must not imply changing them as part of a commercial engagement. [SRC:NEEDS_VERIFICATION]

- Sealed tag: `KT_V1_SEALED_20260217` [SRC:NEEDS_VERIFICATION]
- Sealed commit: `7b7f6e71d43c0aa60d4bc91be47e679491883871` [SRC:NEEDS_VERIFICATION]
- Law bundle hash (V1): `cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906` [SRC:NEEDS_VERIFICATION]
- Suite registry id (V1): `e7a37cdc2a84b042dc1f594d1f84b4ba0a843c49de4925a06e6117fbac1eff17` [SRC:NEEDS_VERIFICATION]
- Determinism expected root hash (V1): `c574cd28deba7020b1ff41f249c02f403cbe8e045cb961222183880977bdb10e` [SRC:NEEDS_VERIFICATION]
- Archived authoritative V1 reseal receipt (do not edit): `KT_PROD_CLEANROOM/reports/kt_archive_manifest.json` entry `vault_receipt_epic24_v1_reseal_under_current_law_fix_post_canonical_hmac_20260217t225856z` [SRC:NEEDS_VERIFICATION]

```text
[Diagram Spec]
type: sales_to_delivery_funnel
nodes:
  - Lead Qualification
  - Pilot Scope (work order)
  - Execution (runs + artifacts)
  - Delivery Bundle
  - Renewal (continuous governance)
edges:
  - Lead Qualification -> Pilot Scope (work order)
  - Pilot Scope (work order) -> Execution (runs + artifacts)
  - Execution (runs + artifacts) -> Delivery Bundle
  - Delivery Bundle -> Renewal (continuous governance)
artifacts:
  - archived intake work order packet
  - one_line_verdict.txt
  - delivery_manifest.txt
  - hash_manifest.json
  - delivery_bundle.zip
```

#### Executive Summary (plain-English)
The market buys KT when they need to prove AI governance under scrutiny. KT wins by converting ambiguous “evaluation” into deterministic evidence that can be replayed. Pricing is anchored to three measurable drivers: scope of systems, depth of coverage, and intensity of audit requirements. [SRC:REG:NIST-AI-RMF-1.0]

- Action checklist (Executive):
  - Choose one wedge: sell a certification pack first, then expand to continuous governance. **Client Delivery Bundle** — see Glossary. [SRC:REG:ISO-9001]
  - Require that each offer specifies acceptance artifacts and a stable verdict line format. **Verdict Line** — see Glossary. [SRC:REG:ISO-9001]
  - Refuse commitments that violate KT constraints (offline, no installs, fail-closed) unless explicitly negotiated. **Fail-Closed** — see Glossary. [SRC:NEEDS_VERIFICATION]

##### Claims hygiene: what KT certifies vs what KT evaluates
Plain-English: commercial language must not overreach. KT certifies evidence and replayability; it evaluates behavior under suites and documents risks. [SRC:INTERNAL:KT_CLIENT_READY_PACK:PLAYBOOK_MD]

- What KT certifies (evidence-level):
  - The system state under a pinned commit/tag and pinned governance surfaces produced the recorded artifacts. **Sealed Commit** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - The delivery bundle hashes match the included artifacts and verification steps. **Hash Manifest** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - The sweep harness outcome (PASS/FAIL) is reproducible under the defined constraints. **Sweep Audit** — see Glossary. [SRC:NEEDS_VERIFICATION]

- What KT does not certify (unless separately evidenced and explicitly scoped):
  - Legal compliance in any jurisdiction.
  - The absence of all future failures.
  - That a model is “safe” in a general sense outside the measured suites. [SRC:NEEDS_VERIFICATION]

##### Offer 1: Certification Pack (point-in-time proof)
Plain-English: a fixed-scope engagement that yields a deterministic evidence bundle and a verdict line.

- Outcome: “We can demonstrate deterministic, audited governance for a specific system version.” [SRC:REG:ISO-9001]
- Deliverables:
  - Delivery bundle ZIP with manifests and hashes. **Evidence Bundle** — see Glossary. [SRC:REG:ISO-9001]
  - Sweep summary and verification transcripts. **Sweep Audit** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - One-line verdict for executives and auditors. **Verdict Line** — see Glossary. [SRC:REG:ISO-9001]
- Typical timeline: 1-2 weeks depending on integration surfaces. [SRC:NEEDS_VERIFICATION]

##### Offer 2: Continuous Governance (subscription)
Plain-English: recurring governed runs that detect drift and produce change evidence.

- Outcome: “Every change is measured and blocked if it breaks rules.” [SRC:REG:ISO-9001]
- Deliverables:
  - Recurring run roots with WORM evidence. **Evidence WORM** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Drift and regression reports with clear next actions. **Regression** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Cadence calendar and escalation path. **Escalation Path** — see Glossary. [SRC:REG:ISO-31000]
- Typical timeline: weekly/monthly cadence after onboarding. [SRC:NEEDS_VERIFICATION]

##### Offer 3: Adversarial Audit (safe)
Plain-English: a bounded evaluation that identifies risk clusters without distributing sensitive payload text.

- Outcome: “We tested failure modes and have evidence and remediation plans.” [SRC:REG:ISO-IEC-23894]
- Deliverables:
  - Safe vector taxonomy and risk register. **Risk Register** — see Glossary. [SRC:REG:ISO-31000]
  - Hash-only references to sensitive case payloads. **Confidential Redpack** — see Glossary. [SRC:REG:ISO-IEC-23894]
  - Remediation plan and rerun proof. **Replay** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Manager Playbook (plain-English)
Your job is to keep delivery deterministic and contract-shaped: every engagement produces the same structure and the same acceptance language, scaled by scope. [SRC:REG:ISO-9001]

- Action checklist (Manager):
  - Use a delivery bundle manifest template and refuse custom deliverables that are not hashable or replayable. **Hash Manifest** — see Glossary. [SRC:REG:ISO-9001]
  - Run pre/post sweeps for meaningful changes and attach sweep summaries to status updates. **System Audit Mandate** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Timebox each phase with explicit exit criteria and failure escalation. **Timebox** — see Glossary. [SRC:REG:ISO-31000]

##### Pricing tiers (starter / pro / enterprise)
Plain-English: pricing is driven by scope and proof requirements, not hype.

| Tier | Target buyer | Typical scope | Primary artifacts | Indicative timeline |
|---|---|---|---|---|
| Starter Audit | Risk, QA, security | One system, narrow suite | evaluation report + risk register | 3-5 days |
| Pro Hardening | Engineering leadership | One system, deeper coverage | remediation plan + rerun evidence | 1-2 weeks |
| Enterprise Governance | Compliance + platform | Multiple systems + cadence | recurring bundles + drift reports | 4-8 weeks |

Notes:
- This is not legal advice; consult counsel for any contract terms. [SRC:NEEDS_VERIFICATION]
- Keep acceptance definition as an artifact list with hashes. **Acceptance Criteria** — see Glossary. [SRC:REG:ISO-9001]

##### SOW snippet patterns (safe, measurable, non-legal)
Plain-English: SOW text should define inputs, outputs, and acceptance artifacts.

- Inputs required:
  - system build identifier (commit or version)
  - allowed evaluation environment and data boundaries
  - named escalation contact for governance decisions [SRC:NEEDS_VERIFICATION]
- Outputs delivered:
  - delivery ZIP with hash manifest
  - sweep summary and transcripts
  - verdict line string
  - risk register and remediation plan (if applicable) [SRC:REG:ISO-9001]
- Acceptance:
  - PASS requires sweep PASS and pin matches; otherwise FAIL with denial evidence. **Fail-Closed** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Engineer Manual (plain-English)
Engineers make the business model real by automating packaging and verification while preserving strict constraints. The design target is “one command produces a client-ready bundle.” [SRC:REG:NIST-SP-800-218-SSDF]

- Action checklist (Engineer):
  - Build outputs as WORM artifacts under run roots; avoid writes into tracked surfaces. **Out-of-Repo Output Root** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Generate a delivery manifest and a hash manifest for every deliverable ZIP. **Hash Manifest** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Ensure secrets are never printed; only log presence and length if needed for diagnostics. **Security and Data Handling** — see Glossary. [SRC:NEEDS_VERIFICATION]

##### ROI calculator spec (inputs, formulas, outputs)
Plain-English: ROI is modeled as avoided audit labor plus reduced incident expectation, minus program cost.

| Input | Description |
|---|---|
| `audit_hours_per_release` | hours spent preparing evidence per release |
| `audit_hourly_cost` | blended hourly cost |
| `releases_per_year` | number of releases |
| `expected_incident_cost` | expected annual cost of severe governance failure |
| `risk_reduction_factor` | fraction reduction from governance hardening (0-1) |
| `kt_program_cost` | annual cost of KT engagement(s) |

Formula (pseudo, not executable):
```text
roi = (audit_hours_per_release * audit_hourly_cost * releases_per_year)
      + (expected_incident_cost * risk_reduction_factor)
      - kt_program_cost
```

Outputs:
- `roi` (annual)
- `payback_months` (if modeled as monthly costs) [SRC:NEEDS_VERIFICATION]

#### Top 5 Load-Bearing Claims (explicit)
1) LOAD-BEARING CLAIM: Clients will pay for deterministic governance evidence when it reduces audit friction and change risk. [SRC:REG:NIST-AI-RMF-1.0]
2) LOAD-BEARING CLAIM: A fixed delivery bundle format reduces delivery cost and increases trust. [SRC:REG:ISO-9001]
3) LOAD-BEARING CLAIM: Pricing can be anchored to measurable scope drivers (systems, suites, audit depth). [SRC:NEEDS_VERIFICATION]
4) LOAD-BEARING CLAIM: Safe adversarial audits can be delivered without distributing sensitive payload text. [SRC:REG:ISO-IEC-23894]
5) LOAD-BEARING CLAIM: One-command packaging is feasible without weakening invariants if the operator boundary is strict. [SRC:REG:NIST-SP-800-218-SSDF]

#### Sources (stubs used in this chapter)
- [SRC:REG:ISO-9001]
- [SRC:REG:NIST-AI-RMF-1.0]
- [SRC:REG:ISO-IEC-23894]
- [SRC:REG:ISO-31000]
- [SRC:REG:NIST-SP-800-218-SSDF]
- [SRC:NEEDS_VERIFICATION]
