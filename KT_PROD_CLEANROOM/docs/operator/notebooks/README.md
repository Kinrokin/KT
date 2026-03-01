# KT Golden Notebook Suite (v1)

This directory contains **tracked** golden notebook plans (Markdown) and a suite manifest.

These files are designed to be:
- Offline-safe (no network surfaces embedded).
- Deterministic (canonizable via `tools.notebooks.notebook_canonize`).
- Executable by an operator runner that emits per-book `FINAL_REPORT.json` artifacts.

Canonical execution is performed by `python -m tools.operator.books_runner`.

