---
title: "Statement of Work Template (Draft)"
volume: "KT Codex - Templates"
chapter: "SOW"
author_role: "Program Manager"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:ISO-9001", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Notice (plain-English)
This template is an educational scaffold only and is not legal advice. Engage qualified counsel for any statement of work. [SRC:NEEDS_VERIFICATION]

## 1. Objective
- Deliver a deterministic, auditable governance evidence bundle for the in-scope system version. [SRC:REG:ISO-9001]

## 2. In Scope
- System identifier: <commit/version>.
- Evaluation perimeter: suites defined by a mutually agreed registry ID and run plan. [SRC:NEEDS_VERIFICATION]

## 3. Out of Scope
- Any activity requiring network access or new dependency installs unless explicitly authorized by the customer. [SRC:NEEDS_VERIFICATION]

## 4. Inputs Required from Customer
- Access to an offline-capable evaluation environment.
- Data boundary constraints and redaction requirements.
- Named escalation contact for governance decisions. [SRC:NEEDS_VERIFICATION]

## 5. Deliverables (artifact-based)
- Delivery bundle ZIP containing:
  - `verdict.txt` (one line)
  - `delivery_manifest.txt`
  - `hash_manifest.json`
  - `sweep_summary.json`
  - `reports/` folder [SRC:REG:ISO-9001]

## 6. Acceptance Criteria
- PASS requires: sweeps PASS; pins match; bundle hashes validate; otherwise FAIL with denial evidence. [SRC:NEEDS_VERIFICATION]

## 7. Timeline
- Week 1: intake and baseline evaluation.
- Week 2: hardening and final certification (if applicable). [SRC:NEEDS_VERIFICATION]

