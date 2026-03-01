---
title: "KT Codex - SME Review Checklist (v1)"
volume: "KT Codex - Metadata"
chapter: "SME Review Checklist"
author_role: "Editor / Deliverables Engineer"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
This checklist ensures SME feedback is actionable, bounded, and produces a deterministically improvable Codex without drifting into ungoverned changes. [SRC:NEEDS_VERIFICATION]

## Global checks (all SMEs)
- Does the chapter clearly separate **what KT proves** vs **what KT does not guarantee**? [SRC:NEEDS_VERIFICATION]
- Are “PASS/FAIL” statements grounded in artifacts (verdict line, sweep summary, hash manifest) rather than claims? [SRC:NEEDS_VERIFICATION]
- Are all sensitive/dual-use topics handled as safe summaries with redpack placeholders, not operational payload text? [SRC:NEEDS_VERIFICATION]
- Are source stubs present for claims that would otherwise look like external assertions? [SRC:NEEDS_VERIFICATION]
- Are there exactly 3 action checklist items per persona block, and are they realistic? [SRC:NEEDS_VERIFICATION]

## Legal / Compliance checklist
- Identify any implied warranty language (e.g., “certifies compliance”) and recommend safer phrasing. [SRC:NEEDS_VERIFICATION]
- Confirm disclaimers exist where needed (“not legal advice”; “evidence-based verification only”). [SRC:NEEDS_VERIFICATION]
- Confirm regulatory and standards references are treated as mapping stubs, not claims of conformance unless explicitly evidenced. [SRC:NEEDS_VERIFICATION]
- Ensure templates remain outlines and do not imply enforceable terms without counsel. [SRC:NEEDS_VERIFICATION]

## DevSecOps / Systems Governance checklist
- Confirm the pipeline stages have clear inputs/outputs/gates and fail-closed behavior. [SRC:NEEDS_VERIFICATION]
- Confirm WORM semantics are described as create-once or byte-identical no-op, with collision behavior explicit. [SRC:NEEDS_VERIFICATION]
- Confirm non-mutation guarantees are enforceable (e.g., clean worktree checks; write-root boundaries; outputs only under exports). [SRC:NEEDS_VERIFICATION]
- Confirm the “two planes” boundary (factory vs hat) is explicit and measurable. [SRC:NEEDS_VERIFICATION]

## Annotation format
Use these markers only:
- `>>REVIEW:LEGAL:<comment>`
- `>>REVIEW:DEVSECOPS:<comment>`

