---
title: "Certification Pack Template (Draft)"
volume: "KT Codex - Templates"
chapter: "Certification Pack"
author_role: "Editor / Deliverables Engineer"
model_version: "GPT-5.2"
generation_date: "2026-02-19"
token_estimate: "NEEDS_ESTIMATE"
word_estimate: "NEEDS_ESTIMATE"
source_stubs: ["SRC:REG:ISO-9001", "SRC:NEEDS_VERIFICATION"]
status: "draft"
---

## Purpose (plain-English)
The certification pack is the delivery format that makes KT sellable: it is the set of artifacts a third party can verify offline to confirm the PASS determination. [SRC:REG:ISO-9001]

## Minimum contents
- `verdict.txt` (one line; stable identifiers only).
- `delivery_manifest.txt` (enumerates files).
- `hash_manifest.json` (SHA256 per file).
- `sweep_summary.json` (authoritative harness output).
- `reports/` (human-readable report and pointers). [SRC:NEEDS_VERIFICATION]

