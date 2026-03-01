---
title: "KT Doctrine and Philosophy"
volume: "Volume I - Doctrine and Philosophy"
chapter: "Chapter 1"
author_role: "Governance & Compliance Lead"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:NIST-AI-RMF-1.0", "SRC:REG:ISO-IEC-42001", "SRC:REG:ISO-9001", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume I - Doctrine and Philosophy
### Chapter 1 - KT Doctrine and Philosophy

#### Chapter intent (plain-English)
KT is a governance engine: it turns AI work into deterministic, auditable evidence. This chapter defines the doctrine behind that claim and how it becomes a repeatable customer outcome. [SRC:REG:NIST-AI-RMF-1.0]

#### Non-negotiable premise (plain-English)
KT sells proof, not promises. The doctrine is explicitly anti-handwaving: if a claim cannot be reproduced from artifacts, it is not a KT claim. **Audit Trail** — see Glossary. [SRC:INTERNAL:KT_CLIENT_READY_PACK:PLAYBOOK_MD]

#### KT Seed Axioms (verbatim)
1. Node 0 (The Judge) — a deterministic decision valve that fails-closed on ambiguity and enforces policy decisions before outputs are released.
2. Immutable Receipts — every AI output produces a WORM idempotent cryptographic receipt (HMAC attestation) that binds input, model version, prompt, and output.
3. 12-Lobe Architecture — a deterministic routing fabric of 12 specialized adapters (lobes) that handle distinct responsibilities (e.g., Safety Lobe, Compliance Lobe, Explainability Lobe).
4. Adversarial Hardening Suite — a canonical set of 150 adversarial vectors and probes used for red-teaming and risk extraction.
5. Governance Delivery Pack — the commercial artifact sold to clients: an auditable ZIP containing Intake Packet, Evaluation Report, Hardening Plan, Certification Packet, and Audit Trail.

#### Persona Matrix
Plain-English: this table tells each reader where to start and what “good” looks like.

| Persona | Start here | Outcome |
|---|---|---|
| Executive Author | Executive Summary | Approve scope, constraints, and acceptance language. |
| Program Manager | Manager Playbook | Deliver repeatably with artifacts and checkpoints. |
| Systems Architect | Engineer Manual | Implement and verify without violating invariants. |

#### Sealed V1 anchors (reference, read-only)
Plain-English: these anchors are treated as immutable facts for KT V1; the Codex must not instruct operators to modify them. [SRC:NEEDS_VERIFICATION]

- Sealed tag: `KT_V1_SEALED_20260217` [SRC:NEEDS_VERIFICATION]
- Sealed commit: `7b7f6e71d43c0aa60d4bc91be47e679491883871` [SRC:NEEDS_VERIFICATION]
- Law bundle hash (V1): `cd593dee1cc0b4c30273c90331124c3686f510ff990005609b3653268e66d906` [SRC:NEEDS_VERIFICATION]
- Suite registry id (V1): `e7a37cdc2a84b042dc1f594d1f84b4ba0a843c49de4925a06e6117fbac1eff17` [SRC:NEEDS_VERIFICATION]
- Determinism expected root hash (V1): `c574cd28deba7020b1ff41f249c02f403cbe8e045cb961222183880977bdb10e` [SRC:NEEDS_VERIFICATION]
- Authoritative V1 reseal receipt (do not edit): `KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/receipts/KT_CHANGE_RECEIPT_EPIC24_V1_RESEAL_UNDER_CURRENT_LAW_FIX_POST_CANONICAL_HMAC_20260217T225856Z.json` [SRC:NEEDS_VERIFICATION]

```text
[Diagram Spec]
type: doctrine_to_artifacts
nodes:
  - Doctrine (claims)
  - Invariants (rules)
  - Gates (tests + validators)
  - Evidence (WORM artifacts)
  - Verdict (one-line)
edges:
  - Doctrine -> Invariants
  - Invariants -> Gates
  - Gates -> Evidence
  - Evidence -> Verdict
artifacts_minimum:
  - sweep_summary.json
  - LAW_BUNDLE_FL3.sha256
  - SUITE_REGISTRY_FL3.json
  - FL4_DETERMINISM_ANCHOR.v1.json
  - verdict.txt
  - delivery_bundle.zip
```

#### Executive Summary (plain-English)
KT replaces “trust our evaluation” with “reproduce our evidence.” It is not a promise of perfect behavior; it is a promise that behavior is measured, constrained, and provable under pinned rules. The business value is procurement-grade assurance: boards, auditors, and customers can independently verify what happened. [SRC:REG:ISO-9001]

- Action checklist (Executive):
  - Approve the acceptance contract: what artifacts define PASS and what constitutes failure. **Acceptance Criteria** — see Glossary. [SRC:REG:ISO-9001]
  - Approve the non-negotiables: **Fail-Closed** — see Glossary and **Evidence WORM** — see Glossary. [SRC:REG:NIST-AI-RMF-1.0]
  - Require that every external claim is backed by a bundle and source stubs, not slides. **Source Stub** — see Glossary. [SRC:REG:NIST-AI-RMF-1.0]

##### What KT is (and what it is not)
Plain-English: KT is a quality system for AI, not a magical alignment guarantee.

- KT is a **governance contract** that binds inputs, rules, evaluation, outputs, and evidence. **Governance Contract** — see Glossary. [SRC:REG:ISO-IEC-42001]
- KT is not a single model; it is a pipeline that proves what models did under controlled constraints. **Pipeline Blueprint** — see Glossary. [SRC:REG:NIST-SP-800-218-SSDF]
- KT is not “we ran tests”; it is “we ran the official harness, captured transcripts, and can replay.” **Sweep Audit** — see Glossary. [SRC:REG:ISO-9001]

##### Why determinism matters commercially
Plain-English: if results cannot be replayed, you cannot survive scrutiny or change control.

- Determinism turns subjective discussions into objective evidence and reduces audit friction. **Determinism** — see Glossary. [SRC:REG:NIST-AI-RMF-1.0]
- A deterministic fixed point makes “what changed” measurable across releases and vendors. **Fixed Point** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Manager Playbook (plain-English)
You deliver KT as a repeatable engagement with fixed artifacts, fixed gates, and fixed acceptance language. The manager’s job is to keep the system safe, bounded, and audit-ready while maintaining pace. [SRC:REG:ISO-9001]

- Action checklist (Manager):
  - Enforce the run-root contract: every run writes only under exports; collisions fail closed. **Operator Run Root** — see Glossary. [SRC:REG:ISO-9001]
  - Keep a visible risk register and require remediation plans for critical failures. **Risk Register** — see Glossary. [SRC:REG:ISO-31000]
  - Require one-line verdicts for every major run and include them in client communications. **Verdict Line** — see Glossary. [SRC:REG:ISO-9001]

##### Engagement phases (high-level)
Plain-English: the phases are a loop: measure, harden, re-measure, certify.

- Intake: capture constraints, data boundaries, and success criteria; generate an intake manifest. **Work Order** — see Glossary. [SRC:REG:NIST-AI-RMF-1.0]
- Evaluation: run suites, validate outputs, compute risks, and produce an evaluation report. **Evaluation Suite** — see Glossary. [SRC:REG:ISO-IEC-23894]
- Hardening: apply bounded changes and rerun evaluation; stop if regressions appear. **System Audit Mandate** — see Glossary. [SRC:REG:ISO-9001]
- Certification: produce a delivery bundle with hashes and replay instructions. **Client Delivery Bundle** — see Glossary. [SRC:REG:ISO-9001]

##### Acceptance language (what managers standardize)
Plain-English: acceptance is a list of artifacts with hashes, not a vibe.

- PASS requires: sweep PASS, pins match, and required packs verify. **Truth Pin** — see Glossary. [SRC:NEEDS_VERIFICATION]
- FAIL requires: explicit denial evidence (missing prerequisites, mismatched pins, or validator failures). **Fail-Closed** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Engineer Manual (plain-English)
Engineers make KT real by preserving invariants: deterministic execution, strict validation, and non-destructive evidence handling. The engineering standard is “can a third party replay this and get the same bytes?” [SRC:REG:NIST-SP-800-218-SSDF]

- Action checklist (Engineer):
  - Treat any write outside exports as a defect; add guards in the operator boundary, not in sealed law surfaces. **Law Surface** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Prefer schema-bound artifacts and validators; fail closed on unknown schema IDs. **Schema Registry** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Prove determinism with canaries and anchor checks before making claims. **Determinism Canary** — see Glossary. [SRC:NEEDS_VERIFICATION]

##### Doctrine-to-code mapping (what must always be true)
Plain-English: doctrine is only real when it is enforceable.

- Every run has a unique run root; reruns do not overwrite. **Evidence WORM** — see Glossary. [SRC:NEEDS_VERIFICATION]
- Every major decision emits a machine-verifiable summary plus a one-line verdict. **Verdict Line** — see Glossary. [SRC:NEEDS_VERIFICATION]
- Any drift in pinned hashes blocks certification and is recorded as denial evidence. **Pin (Truth Pin)** — see Glossary. [SRC:NEEDS_VERIFICATION]

##### Safe handling of adversarial evaluation
Plain-English: you can test boundary behavior without distributing sensitive payloads.

- Store sensitive payload text only as redpacks referenced by hash; deliverables contain safe summaries. **Confidential Redpack** — see Glossary. [SRC:REG:ISO-IEC-23894]
- Prefer metamorphic testing: generate safe variants and validate invariants. **Variant Pack** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Top 5 Load-Bearing Claims (explicit)
1) LOAD-BEARING CLAIM: A third party can reproduce the PASS determination from the delivery bundle alone. [SRC:REG:ISO-9001]
2) LOAD-BEARING CLAIM: Determinism can be measured and enforced via canaries and pinned anchors. [SRC:NEEDS_VERIFICATION]
3) LOAD-BEARING CLAIM: WORM evidence rules prevent silent corruption and preserve auditability. [SRC:NEEDS_VERIFICATION]
4) LOAD-BEARING CLAIM: Validation and schema boundaries prevent ambiguous “almost-correct” artifacts from passing. [SRC:NEEDS_VERIFICATION]
5) LOAD-BEARING CLAIM: Dual-use content can be handled safely via hash-only references and controlled redpacks. [SRC:REG:ISO-IEC-23894]

#### Sources (stubs used in this chapter)
- [SRC:REG:NIST-AI-RMF-1.0]
- [SRC:REG:ISO-IEC-42001]
- [SRC:REG:ISO-9001]
- [SRC:REG:ISO-IEC-23894]
- [SRC:REG:ISO-31000]
- [SRC:REG:NIST-SP-800-218-SSDF]
- [SRC:NEEDS_VERIFICATION]
