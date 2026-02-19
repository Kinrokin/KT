---
title: "KT Pipeline Blueprint"
volume: "Volume III - Technical Stack and Pipeline"
chapter: "Chapter 1"
author_role: "Systems Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:NIST-SP-800-218-SSDF", "SRC:REG:NIST-SP-800-53-REV5", "SRC:REG:NIST-AI-RMF-1.0", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Volume III - Technical Stack and Pipeline
### Chapter 1 - KT Pipeline Blueprint

#### Chapter intent (plain-English)
This chapter describes the KT pipeline as an auditable system: Intake -> Evaluation -> Hardening -> Certification. The goal is maximum reproducibility under strict constraints, not maximum automation. **Pipeline Blueprint** — see Glossary. [SRC:REG:NIST-SP-800-218-SSDF]

#### Persona Matrix
| Persona | Start here | Outcome |
|---|---|---|
| Program Manager | Manager Playbook | Schedule and deliver with clear gates and artifacts. |
| Systems Architect | Engineer Manual | Implement SOPs and verification checks deterministically. |
| Security Lead | Engineer Manual | Validate constraints, data boundaries, and safe handling rules. |

```text
[Diagram Spec]
type: kt_pipeline_blueprint_v1
stages:
  - Intake
  - Evaluation
  - Hardening
  - Certification
stage_contracts:
  Intake:
    inputs: [work_order.json, system_identifier, data_boundary_notes]
    outputs: [intake_manifest.json, run_plan.json]
    gates: [schema_validate, pin_checks]
  Evaluation:
    inputs: [suite_registry_id, suites, evaluator_config]
    outputs: [suite_results.json, audit_eval_report.json, risk_register.json, verdict.txt]
    gates: [validator_catalog, determinism_canary_if_required]
  Hardening:
    inputs: [remediation_plan.md, patch_set, acceptance_thresholds]
    outputs: [rerun_suite_results.json, delta_report.json]
    gates: [pre_post_sweep, regression_block]
  Certification:
    inputs: [all_run_roots, required_artifacts]
    outputs: [delivery_bundle.zip, hash_manifest.json, verdict.txt]
    gates: [bundle_verify, replay_instructions_complete]
```

#### Executive Summary (plain-English)
KT’s technical blueprint treats evidence as the product. Every stage emits artifacts that are hashed and written under WORM rules. The pipeline fails closed if pins drift or required validators are missing, because silent ambiguity is the enemy of auditability. [SRC:REG:NIST-AI-RMF-1.0]

- Action checklist (Executive):
  - Require the delivery bundle to include verification steps a third party can run offline. **Client Delivery Bundle** — see Glossary. [SRC:REG:ISO-9001]
  - Require deterministic evidence roots and explicit failure logs. **Evidence Root** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Treat any write outside exports as a governance defect. **Out-of-Repo Output Root** — see Glossary. [SRC:NEEDS_VERIFICATION]

#### Manager Playbook (plain-English)
The manager’s job is to keep the pipeline bounded and repeatable: the same inputs yield the same artifacts and the same verdict language. [SRC:REG:ISO-9001]

- Action checklist (Manager):
  - Enforce pre/post sweeps for meaningful changes and archive the summaries. **Sweep Audit** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Keep run roots organized by timestamp and stage; never reuse output directories. **Run ID** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Maintain a single delivery manifest format for all clients. **Client Delivery Bundle** — see Glossary. [SRC:REG:ISO-9001]

##### Phase SOP: Intake
Plain-English: freeze the scope and define acceptance before running anything.

- Inputs:
  - work order (scope, constraints, acceptance)
  - system identifier (commit or version)
  - data boundary notes (what may be processed, stored, and delivered) [SRC:NEEDS_VERIFICATION]
- Outputs:
  - `intake_manifest.json` (what will be evaluated, and under what pins)
  - `run_plan.json` (commands, expected artifacts, run roots)
  - `risk_register.json` (initial risks, including data handling risks) [SRC:REG:ISO-31000]
- Gates:
  - schema validation (fail closed on missing required fields)
  - pin checks (law hash, suite registry ID, determinism anchor) [SRC:NEEDS_VERIFICATION]

##### Phase SOP: Evaluation
Plain-English: run suites deterministically and produce an audit-grade report.

- Inputs:
  - suite registry ID (the exact suite set)
  - evaluator configuration (lane, attestation expectations)
  - run root path for WORM outputs [SRC:NEEDS_VERIFICATION]
- Outputs:
  - `suite_results.json` (case-level outcomes)
  - `audit_eval_report.json` (summary, axis scores, tail-risk clusters)
  - `verdict.txt` (one-line) [SRC:NEEDS_VERIFICATION]
- Gates:
  - validator catalog presence and strict parsing
  - determinism canary when certification-level proof is required [SRC:NEEDS_VERIFICATION]

##### Phase SOP: Hardening
Plain-English: apply bounded changes, prove you did not regress, and rerun evaluation.

- Inputs:
  - remediation plan (what changes and why)
  - patch set (minimal diff)
  - acceptance thresholds [SRC:NEEDS_VERIFICATION]
- Outputs:
  - delta report (what changed in results)
  - rerun suite results
  - updated risk register [SRC:REG:ISO-IEC-23894]
- Gates:
  - pre/post sweeps pass (or expected-fail ledger matches exactly)
  - regression blocks for critical axes (safety/governance) [SRC:NEEDS_VERIFICATION]

##### Phase SOP: Certification
Plain-English: package evidence into a deliverable bundle a third party can verify offline.

- Inputs:
  - required artifacts list
  - all run roots referenced by the engagement [SRC:NEEDS_VERIFICATION]
- Outputs:
  - delivery ZIP (bundle)
  - hash manifest (SHA256 per file)
  - verification guide
  - verdict line [SRC:REG:ISO-9001]
- Gates:
  - bundle verification checks (hashes match; required files present)
  - replay instructions completeness [SRC:NEEDS_VERIFICATION]

#### Engineer Manual (plain-English)
Engineers implement KT by orchestrating existing tools and preserving invariants. This manual focuses on stable execution surfaces, run-root discipline, and verification outputs. [SRC:REG:NIST-SP-800-218-SSDF]

- Action checklist (Engineer):
  - Keep the operator boundary strict: it may read pins and run tools, but it must not mutate repo state. **Verification-Only Mode** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Treat every produced artifact as schema-bound or explicitly labeled “needs verification”; never handwave formats. **Schema ID** — see Glossary. [SRC:NEEDS_VERIFICATION]
  - Emit transcripts for each invoked tool to support debugging without changing evidence. **Audit Log** — see Glossary. [SRC:NEEDS_VERIFICATION]

##### Deterministic run-root layout (recommended)
Plain-English: consistent layouts reduce confusion and speed audits.

- `baseline/` - HEAD, git status, pins snapshot
- `sweeps/` - pre/post sweep summaries and logs
- `qa/` - document and bundle QA reports
- `reports/` - human-readable summaries and verdict lines
- `hashes/` - SHA256 for key artifacts and bundles
- `delivery/` - delivery ZIP and its hash [SRC:NEEDS_VERIFICATION]

##### Minimal pseudo interface (non-executable)
Plain-English: the pipeline can be modeled as pure functions producing artifacts.

```text
intake(work_order, pins) -> intake_manifest
evaluate(intake_manifest, suite_registry) -> suite_results, audit_report, verdict
harden(remediation_plan, rerun_policy) -> delta_report, rerun_results
certify(required_artifacts) -> delivery_zip, hash_manifest, verdict
```

##### Security posture (implementation notes)
Plain-English: do not leak secrets and do not distribute sensitive payload text.

- Secrets handling:
  - Never print key material; log only “present/length”. [SRC:REG:NIST-SP-800-53-REV5]
  - Keep secrets out of receipts, logs, and bundles. [SRC:REG:NIST-SP-800-53-REV5]
- Sensitive payload handling:
  - Store only hash references in canonical docs and reports.
  - Use redpack references for any sensitive case text. **Confidential Redpack** — see Glossary. [SRC:REG:ISO-IEC-23894]

#### Top 5 Load-Bearing Claims (explicit)
1) LOAD-BEARING CLAIM: Evidence artifacts can be defined so that independent verification is possible offline. [SRC:REG:ISO-9001]
2) LOAD-BEARING CLAIM: Determinism can be operationally enforced via run roots, canaries, and anchors. [SRC:NEEDS_VERIFICATION]
3) LOAD-BEARING CLAIM: Fail-closed gates prevent silent drift and reduce governance risk. [SRC:REG:NIST-AI-RMF-1.0]
4) LOAD-BEARING CLAIM: WORM evidence handling reduces audit risk by preventing overwrites. [SRC:NEEDS_VERIFICATION]
5) LOAD-BEARING CLAIM: Safe handling rules can prevent distribution of sensitive adversarial payload text. [SRC:REG:ISO-IEC-23894]

#### Sources (stubs used in this chapter)
- [SRC:REG:NIST-SP-800-218-SSDF]
- [SRC:REG:NIST-SP-800-53-REV5]
- [SRC:REG:NIST-AI-RMF-1.0]
- [SRC:REG:ISO-IEC-23894]
- [SRC:REG:ISO-31000]
- [SRC:REG:ISO-9001]
- [SRC:NEEDS_VERIFICATION]
