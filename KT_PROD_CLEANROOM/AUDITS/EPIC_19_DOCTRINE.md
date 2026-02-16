# EPIC_19 — Router Hat Demo v1 (BINDING DOCTRINE)

## Purpose

EPIC_19 defines the minimal, deterministic “Hat plane” routing surface for KT:

- **Router policy** is a schema-bound artifact (`kt.router_policy.v1`).
- **Router demo suite** is a schema-bound artifact (`kt.router_demo_suite.v1`).
- **Routing receipts** are emitted for every case (`kt.routing_receipt.v1`).
- **Router run report** summarizes the run (`kt.router_run_report.v1`).

This EPIC is a **demo** EPIC: it proves routing determinism and receipt lineage. It does **not** run LLM inference.

## Invariants (Fail-Closed)

- **Deterministic routing:** routing decision is a deterministic function of policy + input text only.
- **WORM outputs:** receipts are create-once with byte-identical no-op semantics.
- **Schema-bound:** all router artifacts validate through the FL3 schema registry.
- **No contamination:** no writes to promoted adapter surfaces; routing evidence is isolated to the router output directory.

## Routing Law (v1)

- Match strategy is explicit in the policy. v1 supports:
  - `KEYWORD_SUBSTRING_LEXICOGRAPHIC_MIN`
- Domain selection is deterministic.
- Adapter selection is deterministic:
  - `selected_adapter_ids = adapter_ids ∪ required_adapter_ids`
  - `required_adapter_ids` must be a subset of `selected_adapter_ids`

