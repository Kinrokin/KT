---
title: "KT Codex Master Prompt v1"
volume: "KT Codex — Program"
chapter: "Initialization"
author_role: "Sovereign Architect"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:NIST-AI-RMF-1.0", "SRC:REG:ISO-IEC-42001", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
This prompt defines the authoring and QA contract for the **KT Codex**: a multi-volume consulting playbook that is auditable, reproducible, and safe-to-ship while remaining faithful to KT’s governance posture. [SRC:REG:NIST-AI-RMF-1.0]

## Constraints (hard)
- Offline execution only: no web browsing, no remote calls, no external APIs. [SRC:NEEDS_VERIFICATION]
- No installs: do not add new dependencies; use only the existing local toolchain. [SRC:NEEDS_VERIFICATION]
- Fail-closed: missing inputs, ambiguous requirements, or QA failures stop the run with a minimal “Next Action” block. [SRC:NEEDS_VERIFICATION]
- WORM evidence: run evidence is create-once under `KT_PROD_CLEANROOM/exports/_runs/KT_CODEX/<UTC_TS>/`. [SRC:NEEDS_VERIFICATION]
- Repo safety: do not modify sealed receipts or law surfaces; Codex content lives under top-level `KT-Codex/`. [SRC:NEEDS_VERIFICATION]
- Dual-use safety: never embed operational wrongdoing instructions or raw sensitive payloads; use safe summaries and redpack placeholders. [SRC:REG:ISO-IEC-23894]
- No emojis.

## Chapter format (persona layering contract)
Every chapter must contain these three persona layers, in this order:
1) Executive Summary
2) Manager Playbook
3) Engineer Manual

Each persona layer must include:
- A 1–3 sentence plain-English summary at the top.
- An action checklist with exactly 3 actions.
- At least one glossary crosslink: `**Term** — see Glossary`.

## Diagram contract
Each chapter must include at least one fenced code block that begins with a literal line `[Diagram Spec]` and then specifies a deterministic diagram in terms of nodes, edges, and artifacts.

```text
[Diagram Spec]
type: <diagram_id>
nodes: []
edges: []
artifacts: []
```

## Evidence and source policy (stubs only)
- Never invent URLs, paper titles, or dataset identifiers.
- Every empirical, regulatory, or standards-based claim must include a source stub:
  - `[SRC:REG:<IDENTIFIER>]` for a known standard/regulatory anchor.
  - `[SRC:NEEDS_VERIFICATION]` when the claim cannot be verified offline.
- Each chapter ends with a Sources section that lists all stubs used.
- Each chapter must label Top 5 Load-Bearing Claims explicitly.

## Safe red-team representation policy
When describing adversarial evaluation, represent vectors only at a safe abstraction level:
- objectives (what is tested)
- detection signals (how failure is detected)
- mitigation patterns (how systems are hardened)
- placeholders for sensitive materials:
  - `[REDACTED_PAYLOAD_HASH:<sha256>]`
  - `[REDPACK_REF:<pack_id>]`
  - `[SAFE_SUMMARY_ONLY]`

Never include step-by-step wrongdoing instructions, long coercive strings, or credential-like markers. [SRC:REG:NIST-AI-RMF-1.0]

## Chunking protocol (for future chapters)
- Target chunk size: 2,500–4,000 words.
- Overlap region: 250–400 words; the final paragraph of the prior chunk and the first paragraph of the next chunk must match verbatim.
- Passes per chapter:
  - Draft
  - Stitch
  - SME review (`>>REVIEW` markers only)
  - Revision
  - Fact-check (top 5 claims)
  - Finalize (metadata, manifest, printable summary)

## Ship/no-ship QA gates (minimum)
- Word count minimum across the initialization file and first three chapters.
- Persona blocks and diagram specs present in each chapter.
- Source stubs present throughout and a Sources section per chapter.
- Dual-use scan passes (no blocked patterns in KT-Codex files).
- Pre/post system sweeps recorded under the KT_CODEX run root.
- V1 pins unchanged and sealed artifacts untouched.

## Operator question (after initial release)
Select:
- The next three chapters to prioritize for SME review.
- The first two SMEs to assign (recommended: Legal and DevSecOps).

