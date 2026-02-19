---
title: "KT Codex - TOC, Persona Matrix, Glossary Seed, Citation Seed"
volume: "KT Codex - Master Initialization"
chapter: "Initialization Output"
author_role: "Editor / Deliverables Engineer"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:NIST-AI-RMF-1.0", "SRC:REG:ISO-IEC-42001", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
This file is the navigation spine for the KT Codex: a single table of contents plus persona mapping, a glossary seed, and a citation seed. It is written to be operationally useful and audit-friendly. [SRC:REG:NIST-AI-RMF-1.0]

## Personas (reference set)
- Executive Author - the buyer-facing narrative and value framing.
- Program Manager - delivery planning, scope control, and acceptance management.
- Systems Architect - technical blueprint and deterministic implementation guidance.
- Governance and Compliance Lead - controls mapping, evidence posture, auditability.
- Security Lead - threat modeling, safe evaluation design, data handling posture.
- Editor / Deliverables Engineer - format discipline, QA gates, and packaging.

## Table of Contents (Volumes I-VI)

### Volume I - Doctrine and Philosophy
#### Chapter 1 - KT Doctrine and Philosophy
- Objective: establish KT as a governance-first system that turns AI claims into replayable evidence. [SRC:REG:NIST-AI-RMF-1.0]
- Persona targets: Executive Author; Program Manager; Systems Architect.
- Expected words: 1,800-2,500.
- Required artifacts: persona blocks; diagram spec; top 5 load-bearing claims; Sources section.
- Acceptance: the chapter can be used as an executive briefing and as an engineering contract description. [SRC:NEEDS_VERIFICATION]

#### Chapter 2 - Dual-Use Handling and Safe Evaluation
- Objective: define safe handling rules for sensitive payloads (hash-only in canonical text; redpack references when needed). [SRC:REG:ISO-IEC-23894]
- Persona targets: Governance Lead; Security Lead; Systems Architect.
- Expected words: 2,000-3,000.
- Required artifacts: safe vector taxonomy; redpack placeholder spec; redaction checklist.
- Acceptance: no operational wrongdoing instructions in the Codex; only safe summaries and placeholders. [SRC:NEEDS_VERIFICATION]

#### Chapter 3 - Determinism as a Contract
- Objective: define determinism levels, anchors, and acceptance language for procurement-grade reproducibility. [SRC:REG:ISO-IEC-42001]
- Persona targets: Executive Author; Systems Architect; Governance Lead.
- Expected words: 2,000-3,200.
- Required artifacts: determinism ladder; replay checklist; failure modes.
- Acceptance: determinism is presented as evidence, not as assertion. [SRC:NEEDS_VERIFICATION]

### Volume II - Business Model, Pricing, and Go-To-Market
#### Chapter 1 - Business Model and Pricing
- Objective: define the three-offer portfolio and how each maps to concrete artifacts and acceptance criteria. [SRC:REG:ISO-9001]
- Persona targets: Executive Author; Program Manager; Editor.
- Expected words: 1,800-2,500.
- Required artifacts: tier table; ROI calculator spec; SOW snippet patterns.
- Acceptance: terms map to deliverables; no vague promises without artifact mapping. [SRC:NEEDS_VERIFICATION]

#### Chapter 2 - Delivery Bundle Spec
- Objective: standardize the contract appendix pack: what is delivered, how to verify it offline, and what constitutes acceptance. [SRC:REG:ISO-9001]
- Persona targets: Program Manager; Governance Lead; Editor.
- Expected words: 1,500-2,500.
- Required artifacts: delivery manifest template; verification steps; replay guide.
- Acceptance: zero ambiguity about what the client receives and how PASS is determined. [SRC:NEEDS_VERIFICATION]

#### Chapter 3 - Qualification and Sales Motion
- Objective: define ICPs, qualification, disqualification, and pilot scope language aligned with KT constraints. [SRC:REG:NIST-AI-RMF-1.0]
- Persona targets: Executive Author; Program Manager.
- Expected words: 1,500-2,500.
- Required artifacts: qualification checklist; objection handling table; pilot scope template.
- Acceptance: avoids unbounded commitments and protects governance posture. [SRC:NEEDS_VERIFICATION]

### Volume III - Technical Stack and Pipeline
#### Chapter 1 - KT Pipeline Blueprint
- Objective: define a stage-by-stage SOP for Intake -> Evaluation -> Hardening -> Certification with deterministic evidence. [SRC:REG:NIST-SP-800-218-SSDF]
- Persona targets: Systems Architect; Program Manager; Security Lead.
- Expected words: 2,200-3,200.
- Required artifacts: pipeline diagram spec; stage SOPs; escalation rules; artifact table.
- Acceptance: a competent engineer can follow the SOP without inventing missing steps. [SRC:NEEDS_VERIFICATION]

#### Chapter 2 - Suite Design and Validator Engineering
- Objective: define suite authorship and validator strictness without leaking sensitive payload text into canonical surfaces. [SRC:REG:ISO-IEC-23894]
- Persona targets: Systems Architect; Security Lead; Governance Lead.
- Expected words: 2,000-3,200.
- Required artifacts: suite schema glossary; validator patterns; metamorphic workflow.
- Acceptance: “almost valid” artifacts fail closed; validators remain deterministic. [SRC:NEEDS_VERIFICATION]

#### Chapter 3 - Evidence, Hashing, and Audit Indexes
- Objective: specify evidence layouts, hash manifests, receipt continuity checks, and audit index conventions. [SRC:REG:NIST-SP-800-53-REV5]
- Persona targets: Systems Architect; Editor; Governance Lead.
- Expected words: 1,800-2,800.
- Required artifacts: evidence tree spec; hash manifest examples; verification checklist.
- Acceptance: evidence artifacts are easy to audit and hard to corrupt. [SRC:NEEDS_VERIFICATION]

### Volume IV - Services Catalog
#### Chapter 1 - Certification Pack Service
- Objective: define a fixed-scope engagement that yields a deterministic certification bundle and verdict line. [SRC:REG:ISO-9001]
- Persona targets: Program Manager; Editor.
- Expected words: 1,500-2,200.
- Required artifacts: intake checklist; run plan; delivery manifest.
- Acceptance: clear PASS/FAIL criteria and replay guide. [SRC:NEEDS_VERIFICATION]

#### Chapter 2 - Continuous Governance Service
- Objective: define recurring governance runs with drift detection and measurable controls. [SRC:REG:NIST-AI-RMF-1.0]
- Persona targets: Governance Lead; Program Manager.
- Expected words: 1,800-2,800.
- Required artifacts: cadence spec; drift report format; escalation rules.
- Acceptance: measurable KPIs and operational playbook. [SRC:NEEDS_VERIFICATION]

#### Chapter 3 - Adversarial Audit Service (Safe)
- Objective: define a bounded adversarial audit that produces risk evidence without distributing sensitive payload text. [SRC:REG:ISO-IEC-23894]
- Persona targets: Security Lead; Governance Lead; Program Manager.
- Expected words: 2,000-3,200.
- Required artifacts: safe vector taxonomy; signal definitions; remediation workflow.
- Acceptance: hash-only references for sensitive items; no sensitive payloads in deliverables. [SRC:NEEDS_VERIFICATION]

### Volume V - Operations
#### Chapter 1 - Operator Console and Runbooks
- Objective: define the operator flow, run roots, and how to produce a client-ready bundle on demand. [SRC:REG:ISO-9001]
- Persona targets: Program Manager; Systems Architect; Editor.
- Expected words: 1,800-2,800.
- Required artifacts: command reference; run-root contract; troubleshooting guide.
- Acceptance: no repo mutation; outputs only under exports run roots. [SRC:NEEDS_VERIFICATION]

#### Chapter 2 - Quality System (QA Gates and Reviews)
- Objective: define QA gates for chapters and evidence packs with deterministic checks. [SRC:REG:ISO-9001]
- Persona targets: Editor; Governance Lead.
- Expected words: 1,800-2,800.
- Required artifacts: QA checklist; review marker rules; change log policy.
- Acceptance: deterministic checks block ship; failures yield explicit next actions. [SRC:NEEDS_VERIFICATION]

#### Chapter 3 - Security and Data Handling
- Objective: define secrets handling, data classification, and customer boundary rules for consulting delivery. [SRC:REG:NIST-SP-800-53-REV5]
- Persona targets: Security Lead; Governance Lead.
- Expected words: 2,000-3,000.
- Required artifacts: data classification table; secure storage guidance; incident triggers.
- Acceptance: no secrets in artifacts; explicit guardrails documented. [SRC:NEEDS_VERIFICATION]

### Volume VI - Appendices
#### Appendix A - Glossary (expanded)
- Objective: expand this glossary seed over time (target 500+ terms). [SRC:NEEDS_VERIFICATION]
- Persona targets: all.
- Expected words: variable.
- Required artifacts: term aliases and crosslinks.
- Acceptance: consistent definitions and stable term naming. [SRC:NEEDS_VERIFICATION]

#### Appendix B - Evidence Artifact Reference
- Objective: enumerate canonical artifact types and their minimum required fields. [SRC:NEEDS_VERIFICATION]
- Persona targets: Systems Architect; Editor.
- Expected words: 1,500-2,500.
- Required artifacts: artifact registry and examples (safe only).
- Acceptance: clear versioning and no ambiguity. [SRC:NEEDS_VERIFICATION]

#### Appendix C - Templates (legal and operational)
- Objective: provide draft templates that require counsel review and are used as scaffolding only. [SRC:NEEDS_VERIFICATION]
- Persona targets: Program Manager; Governance Lead.
- Expected words: variable.
- Required artifacts: NDA outline; MSA outline; SOW template; intake template.
- Acceptance: conspicuous “not legal advice” notice present in each template. [SRC:NEEDS_VERIFICATION]

## Persona Matrix (chapters x personas)
Plain-English: this table says who should read what first.

| Chapter | Executive | Manager | Architect | Governance | Security | Editor |
|---|---:|---:|---:|---:|---:|---:|
| Vol I Ch1 Doctrine | X | X | X |  |  | X |
| Vol I Ch2 Dual-use and safety |  | X | X | X | X | X |
| Vol I Ch3 Determinism contract | X | X | X | X |  | X |
| Vol II Ch1 Business model | X | X |  |  |  | X |
| Vol II Ch2 Delivery bundle | X | X | X | X |  | X |
| Vol II Ch3 Sales motion | X | X |  |  |  |  |
| Vol III Ch1 Pipeline |  | X | X |  | X | X |
| Vol III Ch2 Suites and validators |  | X | X | X | X | X |
| Vol III Ch3 Evidence and hashes |  | X | X | X |  | X |
| Vol IV Ch1 Cert pack service | X | X |  | X |  | X |
| Vol IV Ch2 Continuous governance | X | X |  | X |  | X |
| Vol IV Ch3 Adversarial audit |  | X | X | X | X | X |
| Vol V Ch1 Operator console |  | X | X |  | X | X |
| Vol V Ch2 Quality system |  | X |  | X |  | X |
| Vol V Ch3 Security and data handling |  | X | X | X | X | X |

## Glossary Seed (exactly 120 terms)
Each entry includes a plain-English definition and a technical definition.

1. Admission Gate - Plain: a “front door” that refuses to proceed when required conditions are missing. Technical: a deterministic gate returning an explicit denial code and producing WORM evidence.
2. Attestation Mode - Plain: how a run proves it is authorized. Technical: a configured signing or non-signing mode enforced by the canonical lane.
3. Audit Log - Plain: a record of what was accessed and when. Technical: an append-only event stream capturing reads/writes and tool invocations with stable identifiers.
4. Audit Pack - Plain: the set of files an auditor needs. Technical: a packaged evidence bundle containing manifests, reports, and verification steps with hashes.
5. Audit Trail - Plain: the end-to-end chain of evidence. Technical: linked artifacts (hashes, receipts, summaries) that allow replay and independent verification.
6. Baseline Ledger - Plain: the first recorded set of allowed failures. Technical: a WORM file listing failing commands/tests and permitted fixes until resolved.
7. Canonical Lane - Plain: the official way to run KT. Technical: an execution mode with strict invariants (fail-closed, evidence discipline, attestation rules).
8. Change Receipt - Plain: a signed proof of what changed. Technical: a schema-bound record binding inputs, outputs, hashes, and outcomes for a governance change.
9. CI Lane Simulation - Plain: a dry run that does not sign. Technical: a meta-evaluator mode expected to fail where signatures are required, producing structured denial evidence.
10. Claim (Load-Bearing) - Plain: a statement that drives decisions. Technical: a labeled claim that must be supported by evidence and source stubs.
11. Client Delivery Bundle - Plain: what you hand to the customer. Technical: a ZIP with a manifest, hashes, reports, and replay instructions that can be audited offline.
12. Collision Rule - Plain: what happens if a file already exists. Technical: WORM policy: if bytes differ, stop; if bytes match, treat as a deterministic no-op.
13. Compliance Mapping - Plain: how deliverables relate to known standards. Technical: a table mapping KT artifacts to control objectives in recognized frameworks.
14. Confidential Redpack - Plain: a sealed pack for sensitive test content. Technical: an out-of-band payload container referenced by hash only from canonical text surfaces.
15. Counterpressure - Plain: attempts to push the system to violate rules. Technical: bounded pressure tactics modeled as test inputs with deterministic validators and safe summaries.
16. Coverage Pack - Plain: a bundle of test cases. Technical: a suite or suite-pack manifest plus hashed case files, with deterministic generation provenance.
17. Determinism - Plain: same input yields same output. Technical: byte-identical artifacts across reruns under pinned environment and law surfaces.
18. Determinism Anchor - Plain: the expected fingerprint of a deterministic run. Technical: a law-bound artifact that pins an expected root hash and is checked by canaries.
19. Determinism Canary - Plain: a drift detector. Technical: a deterministic job run twice to prove identical evidence roots and detect environmental changes.
20. Dominance Rule - Plain: safety overrides convenience. Technical: a decision rule where critical-axis failures override aggregate scores in promotion logic.
21. Dual-Use Content - Plain: content that can be used for harm. Technical: information that meaningfully enables wrongdoing; restricted to safe summaries and redpack placeholders.
22. Evidence Root - Plain: the top hash of a run. Technical: a hash of a manifest-of-manifests that commits to all produced artifacts for audit verification.
23. Evidence WORM - Plain: write-once evidence storage. Technical: create-once semantics and collision fail-closed rules for run artifacts.
24. Evaluation Suite - Plain: a set of tests. Technical: schema-bound case definitions with deterministic validators and scoring policies.
25. Fail-Closed - Plain: default to no unless proven safe. Technical: refusal on missing prerequisites or ambiguous states, with denial evidence.
26. Factory Lane - Plain: the governed build-and-evaluate pipeline. Technical: the canonical training/evaluation/promotion surface producing receipts and audit artifacts.
27. Fixed Point - Plain: what must not drift silently. Technical: a pinned expected root hash or contract that changes only via governed amendments.
28. Fragility Gap - Plain: a brittle part that can break. Technical: a ranked weakness with reproducible test vectors and mitigations.
29. Governance Axis - Plain: a scored dimension of behavior. Technical: a bounded metric (0-1) for properties such as format discipline, safety, or robustness.
30. Governance Bundle - Plain: the set of governing rules. Technical: a hash-bound collection of schemas, laws, and invariants defining acceptable operation.
31. Governance Contract - Plain: the agreement for what PASS means. Technical: explicit criteria for determinism, evidence, validators, and thresholds.
32. Governance Gate - Plain: a checkpoint before progress. Technical: a validator that blocks advancement unless conditions are met and evidenced.
33. Governance Law (Law Bundle) - Plain: the canonical rules of KT. Technical: law-surfaced artifacts whose hashes are pinned and verified by tooling.
34. Hash Manifest - Plain: a list of file hashes. Technical: a machine-readable manifest binding paths to SHA256 digests for audit verification.
35. HMAC Attestation - Plain: a keyed signature proof. Technical: an HMAC binding structured content to a signer secret without exposing key material.
36. Identity of Record - Plain: the one true ID for a thing. Technical: a stable identifier (hash or ID field) used to reference artifacts across tools and reports.
37. Immutable Artifact - Plain: a file that never changes. Technical: an artifact protected by WORM rules and referenced by hashes/receipts.
38. Invariant - Plain: a rule that must always hold. Technical: a property enforced by gates and validated by tests; violations stop execution.
39. IO Guard - Plain: a limiter for what code can access. Technical: an enforcement layer that restricts network and write roots in governed lanes.
40. KPI - Plain: a measurable success metric. Technical: a tracked indicator with definition, sampling method, and threshold for acceptance.
41. Law Amendment - Plain: a governed change to rules. Technical: a receipted modification to a law-surfaced artifact requiring updated pins.
42. Law Bundle Hash - Plain: the fingerprint of the law. Technical: a computed digest over law surfaces used to detect drift.
43. Law Surface - Plain: what counts as the rules. Technical: the exact set of files included in law hashing; changing them requires governance.
44. Lobe (Adapter) - Plain: a specialized skill module. Technical: a bounded adapter invoked by deterministic routing for specific responsibilities.
45. Meta-Evaluator - Plain: the judge of the pipeline. Technical: a verification tool that checks pins, invariants, receipts, and determinism claims end-to-end.
46. Minimal Diff - Plain: the smallest change that fixes a problem. Technical: a patch policy that reduces unintended side effects and simplifies audit review.
47. Model Card (Governed) - Plain: a structured model description. Technical: a schema-bound artifact describing capabilities, limits, evaluation results, and governance context.
48. Non-Canonical Run - Plain: an untrusted run. Technical: an execution that does not meet canonical lane requirements and cannot be used for certification.
49. Operator CLI - Plain: the command interface for KT. Technical: a wrapper that runs existing entrypoints and writes run evidence under WORM rules.
50. Operator Run Root - Plain: where an operator run writes files. Technical: a unique directory under exports with transcripts and hashes.
51. Out-of-Repo Output Root - Plain: outputs not written into the repo. Technical: a path policy requiring evidence to land under exports run roots, not tracked code.
52. Pack ID - Plain: a short label for a bundle. Technical: a stable identifier for a pack used in manifests.
53. Pass/Fail Region - Plain: the decision bucket. Technical: thresholds mapping scores and critical fails into promote/hold/quarantine decisions.
54. Persona Layering - Plain: writing for multiple roles. Technical: a chapter format providing executive, manager, and engineer sections with checklists.
55. Pipeline Blueprint - Plain: the map of how work flows. Technical: a stage-by-stage SOP with inputs, outputs, checks, and evidence artifacts.
56. Pin (Truth Pin) - Plain: a value that must match. Technical: a stored hash/ID used to detect drift and enforce immutability.
57. Policy Constant - Plain: a number that defines rules. Technical: a fixed threshold used in scoring and gating.
58. Posture (Non-Destructive) - Plain: do no harm by default. Technical: tools must not mutate production surfaces and must fail-closed.
59. Promotion Decision - Plain: approval to advance. Technical: a mechanized decision based on gates and thresholds, recorded as evidence.
60. Provenance Pointer - Plain: where a claim came from. Technical: a stable reference to an artifact path and hash supporting a statement.
61. QA Gate - Plain: a test before shipping. Technical: a deterministic check that blocks release unless criteria are satisfied.
62. Quarantine Decision - Plain: do not ship this. Technical: a decision state triggered by critical failures requiring remediation.
63. Receipt Continuity - Plain: no gaps in change proofs. Technical: an append-only chain where every governed change has a corresponding receipt.
64. Receipt Schema Perimeter - Plain: receipts must be well-formed. Technical: fail-closed validation requiring known schema IDs.
65. Reducer - Plain: combines shard results. Technical: a deterministic aggregator that rejects overlaps and missing case IDs.
66. Regression - Plain: getting worse over time. Technical: an axis or gate falling below threshold compared to baseline.
67. Replay - Plain: run it again and confirm. Technical: deterministic re-execution that yields identical evidence given the same pins and inputs.
68. Repro Script - Plain: the commands to reproduce. Technical: a minimal command list and environment assumptions that reproduce artifacts and hashes.
69. Risk Register - Plain: the list of risks. Technical: a structured, ranked set of risks with mitigations and evidence pointers.
70. Run ID - Plain: the unique label for a run. Technical: a timestamped identifier used to isolate evidence under WORM rules.
71. Run Manifest - Plain: what happened in a run. Technical: a summary listing commands, inputs, outputs, hashes, and outcomes.
72. Schema ID - Plain: the ID of a document type. Technical: a versioned identifier used for validation and compatibility checks.
73. Schema Registry - Plain: the list of allowed schemas. Technical: a governed catalog of schema definitions used to validate artifacts.
74. Seal Pack - Plain: a sealed bundle of artifacts. Technical: a self-contained directory with hashes and verification reports.
75. Seal Verify - Plain: check a pack is valid. Technical: recompute hashes and check required pack contents.
76. Sealed Commit - Plain: the exact code state. Technical: a git commit hash used as a verification anchor.
77. Sealed Tag - Plain: a human-readable anchor. Technical: an annotated git tag pointing to a sealed commit.
78. Sensitive Payload - Plain: content that must not be shared. Technical: raw case text kept out of canonical surfaces and referenced by hash only.
79. Sharding - Plain: splitting work into pieces. Technical: partition evaluation by case IDs against a sealed manifest.
80. Suite Registry ID - Plain: the ID of the suite list. Technical: a hash-bound identifier representing the set of suites available for evaluation.
81. Sweep Audit - Plain: the full system check. Technical: the harness that runs test batteries and meta-evaluator checks with transcripts.
82. System Audit Mandate - Plain: always prove nothing broke. Technical: require pre/post sweeps for meaningful changes; fail-closed on new failures.
83. Tail Risk - Plain: the worst-case failures. Technical: a risk perspective prioritizing critical cluster failures over averages.
84. Telemetry Vector - Plain: the measured signals. Technical: structured metrics emitted per run for scoring and governance decisions.
85. Test Battery - Plain: a set of automated tests. Technical: unit and integration checks that must pass to maintain system integrity.
86. Threat Model - Plain: what could go wrong and who tries. Technical: a structured model of adversaries, assets, and mitigations.
87. Timebox - Plain: the allowed time window. Technical: an explicit schedule constraint for a phase with defined exit criteria.
88. Tool Surface - Plain: the executable entrypoints. Technical: the minimal set of commands permitted for certification and evidence generation.
89. Traceability - Plain: can you follow the chain. Technical: mapping from requirements to artifacts to evidence and hashes.
90. Transform Spec - Plain: how variants are generated. Technical: deterministic transformation rules plus a seed used to generate variants.
91. Tournament - Plain: head-to-head comparisons. Technical: a deterministic evaluation and dominance process used to rank candidates.
92. Training Lane - Plain: where training runs happen. Technical: a governed execution surface with WORM outputs and gate checks.
93. Training Run Manifest - Plain: record of a training attempt. Technical: a manifest binding dataset hashes, config, outputs, and evaluation artifacts.
94. Truth Pin - Plain: the pinned value you must match. Technical: a stored identifier used to prevent drift and ensure reproducibility.
95. Untrusted Input - Plain: data you should not assume is safe. Technical: external content treated as hostile until validated.
96. Validator - Plain: a checker for correctness. Technical: deterministic logic that evaluates outputs against schema, safety, and policy rules.
97. Validator Catalog - Plain: a library of validators. Technical: a governed set of validation functions with identifiers and documented behavior.
98. Variant Pack - Plain: generated test variants. Technical: a deterministic pack derived from a source suite and transform spec with provenance.
99. Versioned Schema - Plain: schemas change safely. Technical: explicit versioning that prevents silent interpretation shifts.
100. Verdict Line - Plain: the one-line pass/fail string. Technical: a stable verdict containing identifiers and hashes, not secrets.
101. Verification-Only Mode - Plain: check without changing. Technical: a mode that validates artifacts without minting receipts.
102. Work Order - Plain: the instruction contract. Technical: a document defining scope, constraints, and acceptance for an execution.
103. Work Order Schema - Plain: the format of work orders. Technical: the schema that validators use to accept or reject work order artifacts.
104. WORM Writer - Plain: a safe writer. Technical: create-once writes; collisions fail unless byte-identical no-op.
105. Zero-Dependency UI - Plain: a viewer that needs nothing installed. Technical: static files that render run artifacts locally without network calls.
106. Zone of Control - Plain: what you can safely change. Technical: the set of surfaces permitted by a work order without governance amendments.
107. Acceptance Criteria - Plain: what done means. Technical: explicit pass/fail conditions that can be checked deterministically.
108. Budget (Compute Budget) - Plain: resource limits. Technical: constraints on time and compute tracked and enforced.
109. Cost Driver - Plain: what makes it expensive. Technical: a factor (data, compute, review, compliance) determining pricing and effort.
110. Delivery SLA - Plain: delivery promises. Technical: measurable timeline and quality commitments with defined acceptance artifacts.
111. Engagement - Plain: a client project. Technical: a scoped delivery with agreed inputs, outputs, and acceptance criteria.
112. Escalation Path - Plain: who to call when blocked. Technical: decision-makers and required evidence to unblock failures.
113. Evidence Bundle - Plain: the package of proof. Technical: a directory or ZIP containing manifests, hashes, reports, and transcripts.
114. Executive Sponsor - Plain: the buyer who owns the outcome. Technical: accountable stakeholder who approves acceptance and receives the verdict.
115. Fact-Check Stub - Plain: a placeholder to verify later. Technical: a marker indicating a claim requires later verification.
116. Glossary Seed - Plain: the starter glossary. Technical: a deterministic list of terms used for consistent language across chapters.
117. Manager Playbook - Plain: how to run the work. Technical: an operational section defining timeline, roles, KPIs, and acceptance gates.
118. Engineer Manual - Plain: how to build and verify. Technical: an implementation section defining SOPs and evidence outputs.
119. Source Stub - Plain: a placeholder citation. Technical: a structured marker that points to a standard or requires verification.
120. Stitch Pass - Plain: combining chunks safely. Technical: a pass ensuring overlaps match and structure remains consistent.

## Citation Seed (exactly 30 authoritative source stubs)
These stubs are the allowed authoritative anchors to cite without URLs.

1. [SRC:REG:NIST-AI-RMF-1.0]
2. [SRC:REG:ISO-IEC-42001]
3. [SRC:REG:ISO-IEC-23894]
4. [SRC:REG:ISO-IEC-27001]
5. [SRC:REG:ISO-31000]
6. [SRC:REG:NIST-CSF-2.0]
7. [SRC:REG:NIST-SP-800-53-REV5]
8. [SRC:REG:NIST-SP-800-218-SSDF]
9. [SRC:REG:NIST-SP-800-207-ZTA]
10. [SRC:REG:CIS-CONTROLS-V8]
11. [SRC:REG:OWASP-LLM-TOP-10]
12. [SRC:REG:MITRE-ATTACK]
13. [SRC:REG:MITRE-ATLAS]
14. [SRC:REG:OECD-AI-PRINCIPLES-2019]
15. [SRC:REG:EU-AI-ACT]
16. [SRC:REG:GDPR]
17. [SRC:REG:US-EO-14110]
18. [SRC:REG:ACM-CODE-OF-ETHICS]
19. [SRC:REG:IEEE-7000-SERIES]
20. [SRC:REG:SOC2-TSC]
21. [SRC:STD:ISO-IEC-25010]
22. [SRC:STD:ISO-IEC-12207]
23. [SRC:STD:IETF-RFC-2119]
24. [SRC:STD:IETF-RFC-3339]
25. [SRC:STD:SPDX-SBOM]
26. [SRC:REG:NTIA-SBOM]
27. [SRC:REG:US-OMB-M-22-18-ZTA]
28. [SRC:REG:PCI-DSS-4.0]
29. [SRC:REG:HIPAA-SECURITY-RULE]
30. [SRC:REG:ISO-9001]

## Sources (stubs used in this file)
- [SRC:REG:NIST-AI-RMF-1.0]
- [SRC:REG:ISO-IEC-42001]
- [SRC:REG:ISO-IEC-23894]
- [SRC:REG:ISO-9001]
- [SRC:REG:ISO-31000]
- [SRC:REG:NIST-SP-800-53-REV5]
- [SRC:REG:NIST-SP-800-218-SSDF]
- [SRC:NEEDS_VERIFICATION]
