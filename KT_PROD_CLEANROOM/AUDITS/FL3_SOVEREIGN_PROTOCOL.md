FL3 COMPLETION ADDENDUM - MECHANICALLY SOVEREIGN EDITION

Status: BINDING WHEN ACTIVATED
Activation Mechanism: CI-enforced `LAW_BUNDLE_FL3` hash pin + meta-evaluator receipt
Scope: Finish Line 3 only
Change Class: Add-Only (no FL1/FL2 spine/router edits)
Supersession Rule: Latest `LAW_BUNDLE_FL3.sha256` is canonical

SECTION 0 - HOW THIS DOCUMENT IS MADE IMMUTABLE

0.1 Canonical Binding

This document is authoritative only when referenced by `KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json`
under:

- `laws[].law_id = "FL3_SOVEREIGN_PROTOCOL"`
- `laws[].law_doc_path` pointing to this file
- `laws[].law_hash` matching `sha256(file_bytes)`

CI rule:
If `LAW_BUNDLE_FL3` changes, a new `kt.law_amendment.v1` artifact MUST exist in `KT_PROD_CLEANROOM/AUDITS/`
whose `bundle_hash` equals the new `LAW_BUNDLE_FL3.sha256`.

0.2 Supersession Rule (No Ambiguity)

Only one FL3 law may be active.

Meta-evaluator asserts:

- `len(laws) == 1`

If multiple exist -> `FL3_T1_HARD_CORRUPTION`.

0.3 SRR/AIR EXCLUSIVITY (NO AMBIGUITY)

SRR/AIR are FL2 runtime receipts.
They are minted only by the canonical spine call site(s) (the spine wrapping `CouncilRouter.plan(...)` / `CouncilRouter.execute(...)`).

FL3 factory artifacts (including SHADOW mode artifacts) MUST NOT:
- emit SRR/AIR
- claim SRR/AIR lineage
- write SRR/AIR sidecars

If any FL3 factory output claims SRR/AIR lineage, classify as `FL3_T1_HARD_CORRUPTION` (fail-closed).

SECTION 1 - DEFINING PARADOX

1.1 Operational Definition

A Paradox Event is structural:

Paradox occurs iff:

- Governor verdict == VETO
- AND `trace_coverage == 1.0`
- AND `schema_valid == true`

Meaning: "The system followed the law perfectly and still failed."

Schema: `kt.paradox_event.v1`

SECTION 2 - FITNESS REGIONS WITHOUT PARALLEL GOVERNANCE

2.1 Fitness Region Is DERIVED - Never Authored

No job, adapter, or human process may write `fitness_region` directly.
It is computed only by the meta-evaluator from existing artifacts and a pinned policy file:

- `KT_PROD_CLEANROOM/AUDITS/FL3_FITNESS_POLICY.json`

Schema: `kt.fitness_region.v1`

2.2 Canonical Region Computation (No Threshold Drift)

Thresholds live in one place only: `FL3_FITNESS_POLICY.json`.
Meta-evaluator recomputes region every run.

2.3 Region Semantics (Enforceable)

Region A: Eligible for tournament + promotion
Region B: Shadow-only, mutation source only
Region C: Immediate quarantine + salvage

Promotion guard:
Factory promotion must refuse unless fitness_region == A.

SECTION 3 - SHADOW BIOS WITHOUT A BACKDOOR

3.1 Shadow Storage Is Cold, Signed, and Non-Executable

Allowed formats:

- safetensors
- jsonl
- npz

Forbidden:

- pickle
- torch.save
- custom loaders

Schema: `kt.shadow_adapter_manifest.v1`

3.2 Shadow Cannot Execute (No SRR/AIR)

Shadow adapters:

- cannot be loaded by router (never registered)
- cannot emit SRR/AIR (no runtime invocation allowed)
- cannot promote

They may only be:

- sampled during breeding
- analyzed offline

Meta-evaluator asserts:

- No runtime registry adapter entry points to `exports/adapters_shadow/`
- Shadow artifacts do not create SRR/AIR lineage

SECTION 4 - VIRAL INJECTION WITHOUT HAND-WAVING

4.1 Definition (Concrete)

Viral injection = 1% of training batches include Shadow-derived gradients.

Schema: `kt.breeding_manifest.v1`

Meta-evaluator recomputes batch stats from training logs.
Mismatch -> `FL3_T2_HARD_GOVERNANCE`.

SECTION 5 - IMMUNE SURVEILLANCE WITHOUT FAIL-OPEN

5.1 Heartbeat Is Informational Only

Async heartbeats are not governance.
No decision may depend on them alone.

5.2 Governance-Relevant Immune Events Are SYNCHRONOUS

Only these events count:

- `kt.paradox_event.v1`
- `kt.trace_violation.v1`
- `kt.schema_violation.v1`

These are blocking, hash-bound, and append-only in the FL3 factory vault.

SECTION 6 - EPIGENETIC PROOFS WITHOUT ID LEAKAGE

6.1 Epigenetic Summary Is ONE-WAY AGGREGATE

Schema: `kt.epigenetic_summary.v1`

Rules:

- No adapter_id
- No raw timestamps beyond coarse created_at
- No order information

SECTION 7 - BLINDNESS WITHOUT SEMANTIC DAMAGE

7.1 No Text Normalization

Text is never modified for blindness.
Blindness is achieved by restricting inputs to the judge, not altering content.

Judge sees:

- prompt
- output
- epigenetic summary (hash-only)

Nothing else.

SECTION 8 - MEMORY WITHOUT SPINE MUTATION

8.1 Lineage Graph Is OBSERVATIONAL ONLY

Schema: `kt.temporal_lineage_graph.v1`

It never feeds back into routing and has no runtime effect.
Used only by meta-evaluator and human audit.

SECTION 9 - TRAINING MODES WITHOUT BYPASS

9.1 SHADOW Mode Definition

SHADOW mode:

- writes only to `exports/adapters_shadow/`
- emits no registry writes
- emits no promotion receipts

SECTION 10 - EVENTS, HASHES, AND CHAINING

10.1 Every New Addendum Artifact Is Hash-Chained

All addendum-era derived artifacts include `parent_hash` and are appended to the FL3 factory vault.

SECTION 11 - UPDATED DEFINITION OF DONE (CHECKABLE)

FL3 is complete iff:

- `LAW_BUNDLE_FL3.sha256` is stable across two clean clones
- meta-evaluator passes (single active law, law hash matches, amendments present)
- no shadow adapter can be routed (no registry entry points to adapters_shadow)
- viral injection manifest validates (if breeding run executed)
- all promotions have fitness_region == A and trace_coverage == 1.0
- no new artifacts exist outside allowlisted paths
- rollback drill passes
