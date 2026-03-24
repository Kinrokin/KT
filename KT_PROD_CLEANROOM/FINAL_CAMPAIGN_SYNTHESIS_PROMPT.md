# KT FINAL CAMPAIGN SYNTHESIS PROMPT — V3.1 (HARDENED)

## META: WHAT THIS DOCUMENT IS

This is a prompt. You paste this into a frontier LLM session (Claude Opus 4, GPT-4.5, o3, etc.) along with the repository or relevant file contents. The LLM will produce the final execution packet for KT's Post-Wave5 Max-Power Rectification Campaign.

This prompt was engineered from 18 rounds of adversarial cross-analysis of the actual repository, including forensic line-by-line verification of every runtime organ, every governance JSON, every stub, every test file, every tool, every CI workflow, every W4 gate definition, and every prior packet version (v1.0, v1.1, v1.2, v1.4). It merges verified ground truth with structural constraints from the operator's meta-prompt template. V3.1 adds snapshot-binding discipline: every mutable numeric claim is bound to a specific commit with explicit staleness behavior.

**This version (V3.1) supersedes V3.0, V2.0, and all v1.x packet artifacts still in the repo.**

---

## BEGIN PROMPT

---

# ═══════════════════════════════════════════════════════
# ABSOLUTE INTENT LOCK — READ THIS BEFORE ANYTHING ELSE
# ═══════════════════════════════════════════════════════

## WHAT KT ACTUALLY IS

KT (King's Theorem) is a **fail-closed, evidence-first runtime governance system** for LLM inference pipelines. It is:

- A runtime kernel (~4,100 LOC, Python 3.10) that enforces determinism, schema-bounded contracts, import isolation, append-only persistence, hash-chained receipts, and budget ceilings — with no silent fallbacks.
- An offline growth layer (340 tool .py files) that measures, trains, evaluates, and produces append-only evidence **without mutating the kernel**.
- A governance spine (147 JSON law/policy files + 3 frozen constitutions) that binds both layers. [SNAPSHOT]

## WHAT KT IS NOT

- KT is not an AGI framework.
- KT is not a product platform.
- KT is not a training system that runs in production.
- KT is not a standards body. It does not define ISO/NIST controls — it may bind to them.
- KT is not an enterprise service offering. Not yet.

## THE REAL CATEGORY KT IS TRYING TO WIN

KT competes in: **deterministic governance and trustworthy orchestration for LLM inference**.

Named comparators: raw OpenAI API (no governance), LangChain + Guardrails AI (popular framework + safety), NeMo Guardrails (NVIDIA governance), bare pytest (tests only, no runtime governance), best-static single adapter (always pick the best model).

KT's structural advantage: receipt completeness, fail-closed discipline, governance enforcement, import isolation, replay consistency, budget enforcement. KT's structural weakness: raw throughput, cost efficiency, setup simplicity, documentation clarity. **Both outcomes are evidence. Preserve the losses.**

## WHAT THIS CAMPAIGN IS FOR

This campaign takes KT from its current **bounded, partially-proven** state to **maximum defensible strength** — not by making KT sound bigger, but by:

1. **Closing the live blockers** that keep KT graded below what its architecture can prove.
2. **Reducing the hostile explanation** (the critic's narrative about what KT actually is) faster than we increase architecture size.
3. **Forcing every surface to terminal truthful state** — no ambigu ous grades, no "sort of works."

## WHAT THIS CAMPAIGN IS NOT FOR

- Making KT sound bigger.
- Creating new architectural surface area beyond what closures require.
- Writing governance that gates nothing.
- Producing artifacts that look impressive but aren't tested.
- Widening claims without new evidence.
- Building a broad product. The product wedge is narrow and claim-bounded.

## THE SINGLE MOST IMPORTANT INSTRUCTION

**Reduce the hostile explanation faster than you increase architecture size.**

If at any point the packet creates more attack surface than it closes, it has failed.

---

# ═══════════════════════════════════════════════════════
# SECTION 0: VERIFIED GROUND TRUTH (FORENSICALLY PROVEN)
# ═══════════════════════════════════════════════════════

Everything below has been forensically verified against the actual repository at `Kinrokin/KT`, branch `main`, HEAD SHA `494cd490a6512b9bfa937c82886db625143d38ae` (verified_at: V3.1 hardening pass). Do not guess. Do not infer. Use these facts.

**SNAPSHOT BINDING PROTOCOL**: All numeric claims in Section 0 are MUTABLE_SNAPSHOT values bound to the commit above. If the executing model's HEAD differs from this SHA, it MUST:
1. Re-verify every numeric claim marked [SNAPSHOT] against the actual HEAD.
2. Emit a DRIFT_REPORT section listing every claim that changed, with old value, new value, and delta.
3. Treat any claim it cannot re-verify as STALE — do not cite it as ground truth.
4. Proceed with corrected values. Do not halt on drift alone — drift is expected, lying about it is forbidden.

#### 0.1 REPOSITORY STRUCTURE

```
Root: KT_PROD_CLEANROOM/
Runtime kernel: KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/
  Organ directories: cognition/, core/, council/, curriculum/, governance/,
    kt/, memory/, multiverse/, paradox/, schemas/, temporal/, thermodynamics/,
    versioning/
  Sub-packages: council/providers/, cognition/planners/, thermodynamics/meters/
  Entrypoint: 04_PROD_TEMPLE_V2/src/entrypoint.py
Growth layer: KT_PROD_CLEANROOM/tools/growth/ (TOOLING-ONLY, not runtime)
Tools: KT_PROD_CLEANROOM/tools/ (340 .py files across 19 subdirectories) [SNAPSHOT]
Tests: KT_PROD_CLEANROOM/tests/ (193 test files, 408 test functions) [SNAPSHOT]
Governance: KT_PROD_CLEANROOM/governance/ (147 JSON files) [SNAPSHOT]
  constitutional_spine/: 12 files (constitution, policies, models, dependency matrix)
  closure_foundation/: 4 files (claim compiler, determinism, public verifier, TUF root)
AUDITS: KT_PROD_CLEANROOM/AUDITS/ (400+ files)
Reports: KT_PROD_CLEANROOM/reports/ (600+ files)
CI: .github/workflows/ (11 workflow files — see 0.10)
```

#### 0.2 PYPROJECT.TOML — THE C007 BLOCKER

```toml
[build-system]
requires = ["setuptools>=65", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "kt-prod-cleanroom"
version = "0.0.0"
description = "Wave 0 package baseline for KT unified convergence remediation."
requires-python = ">=3.10,<3.11"
dependencies = [
  "jsonschema==4.25.1",
  "PyYAML==6.0.3",
]

[project.optional-dependencies]
test = [
  "pytest==9.0.2",
  "pytest-cov==7.0.0",
]

[tool.setuptools]
packages = []
```

**CRITICAL**: `packages = []` means `pip install .` installs ZERO Python packages. No `__init__.py` exists at `04_PROD_TEMPLE_V2/src/__init__.py` or `04_PROD_TEMPLE_V2/src/core/__init__.py` (though 15 other subdirectory `__init__.py` files exist). This is live blocker C007.

#### 0.3 ORGAN STATUS BOARD — VERIFIED WITH EXACT LINE NUMBERS

**CORE_LIVE (100% real, tested, no stubs):**

| Organ | LOC | Evidence |
|-------|-----|----------|
| core/spine.py | 1065 | 100% real dispatch, full request lifecycle |
| core/import_truth_guard.py | 180 | builtins.__import__ replacement, blocks unauthorized imports |
| core/invariants_gate.py | 195 | 7-check fail-closed pre-execution gate |
| core/runtime_registry.py | 600 | Full organ/adapter validation |
| core/routing_receipts.py | 175 | Deterministic SHA256 receipt emission |
| core/no_hidden_mutation.py | 79 | Mutation scanner checking module state |
| memory/state_vault.py | 280 | O_APPEND + fsync + parent-hash chain |
| memory/replay.py | 185 | Full chain validation replay |
| governance/*.py (4 files) | 212 | Event logging + verdict enforcement |
| thermodynamics/budget_engine.py | 130 | Real ceiling enforcement |
| curriculum/curriculum_ingest.py | 100 | Training boundary guard |
| council/thermo_ledger.py | 39 | Token cost tracking |

**LIVE_BOUNDED (real but scoped):**

| Organ | LOC | Evidence |
|-------|-----|----------|
| council/providers/provider_registry.py | 400 | 2/12 providers active, resilience is real |
| council/council_router.py (live_hashed path) | subset of 420 | Real provider invocation works |

**STUB_BOUNDED (interface real, execution fake — EXACT STUB LOCATIONS):**

| Organ | LOC | Stub Location | Exact Stub Code |
|-------|-----|---------------|-----------------|
| cognition/cognitive_engine.py | 160 | Line 150 | `score = int(step_hash[0:2], 16) % 101` |
| cognition/planners/step_planner.py | 19 | Entire file | Hash-based rotation, zero reasoning |
| council/council_router.py (plan/execute) | subset of 420 | Lines 321-323 | `status = PLAN_STATUS_OK if mode == MODE_DRY_RUN else PLAN_STATUS_REFUSED` |
| paradox/paradox_engine.py | 93 | Full execute() | Eligibility gate only, no actual detection |
| temporal/temporal_engine.py | 160 | Line 115 | `steps_executed = 0` (hardcoded) |
| multiverse/multiverse_engine.py | 210 | Line 219 | `coherence_score = 1.0` (hardcoded) |
| thermodynamics/meters/*.py | 51 | All meters | Trivial subtraction only |

**PROTOCOL_ONLY (type hints and dataclass definitions):**

| Organ | LOC | Evidence |
|-------|-----|----------|
| council/providers/base_provider.py | 34 | Type hints only |
| council/providers/provider_interface.py | 14 | Type hints only |

#### 0.4 GOVERNANCE ARTIFACTS — EXISTENCE STATUS

**EXISTS AND FROZEN:**
- kt_benchmark_constitution_v1.json (32 lines, FROZEN_WAVE_0_5, requires: dataset_registry, holdout_policy, comparator_policy, contamination_policy, cost_accounting_rule, latency_accounting_rule, failure_row_retention_rule, replayability_coverage_rule, adversarial_probe_coverage_rule)
- kt_externality_class_matrix_v1.json (19 lines, FROZEN_WAVE_0_5)
- kt_mutation_authority_v1.json (40 lines, FROZEN_WAVE_0_5)

**EXISTS AND ACTIVE:**
- execution_board.json (~1100 lines, DOCUMENTARY_ONLY=true, ACTIVE_AUTHORITY=false, SUPERSEDED_BY kt_truth_ledger)
- rollback_law.json (27 lines, ACTIVE, domain: DOMAIN_2_PROMOTION_CIVILIZATION, has 3 pytest validation commands)
- adapter_lifecycle_law.json (26 lines, ACTIVE, domain: DOMAIN_2_PROMOTION_CIVILIZATION)
- promotion_engine_law.json (28 lines, ACTIVE)
- router_policy_registry.json (45 lines, 3 routes: governance→[auditor+censor], math→[quant+censor], poetry→[muse], default adapter: lobe.strategist.v1, scope: STATIC_ROUTER_BASELINE_ONLY)

**Constitutional Spine (governance/constitutional_spine/ — 12 files):**
KT_Constitution_v1.md, kt_constitution_manifest.json, kt_accreditation_policy.json, kt_constitutional_court_procedure.json, kt_cost_model.json, kt_epoch_model.json, kt_forgetting_law.json, kt_meta_governance_policy.json, kt_organ_dependency_matrix.json, kt_quality_policy.json, kt_readiness_lattice.json, kt_self_description.json

**Closure Foundation (governance/closure_foundation/ — 4 files):**
kt_claim_compiler_policy.json, kt_determinism_contract.json, kt_public_verifier_contract.json, kt_tuf_root_policy.json

**DOES NOT EXIST AS AN ACTIVE GOVERNED ARTIFACT UNDER AUTHORITATIVE OR ACTIVE REPO SURFACES (must be created):**
- ClaimCompilerMonotonicityLawV1
- NegativeResultLedgerLawV1
- ArtifactAuthorityTaxonomyV1
- SurfaceRetirementLawV1
- HostileExplanationRegisterLawV1
- ComplexityBudgetLawV1
- CleanroomRerunGateLawV1
- OClassAdjudicationLawV1
- EvaluatorSeparationOfDutiesLawV1
- DoubleEntryEvidenceAccountingLawV1
- LeastAuthorityTokenEgressLawV1
- ComparatorRosterFreezeV1
- SnapshotBindingLawV1
- StateVaultAndReplayProtectionLawV1
- EvidenceQualityTierLawV1

None of these 15 exist as active governed artifacts under authoritative repo surfaces. Some names may appear in documentary or prompt artifacts (including this prompt), but no binding governed instance exists. Every reference to them in the campaign is a CREATE action, not a VERIFY action.

#### 0.5 EXECUTION BOARD CURRENT STATE

**CRITICAL DISCOVERY**: The execution board has `DOCUMENTARY_ONLY: true`, `ACTIVE_AUTHORITY: false`, and `SUPERSEDED_BY: kt_truth_ledger:ledger/current/current_pointer.json`. This means the execution board itself is NOT the live authority — the truth ledger is. The campaign must work with this hierarchy, not ignore it.

- Board ID: EXECUTION_BOARD_V3_20260309
- Authority Mode: TRANSITIONAL_AUTHORITATIVE (not yet SOLE_SCHEDULER)
- Documentary Status: DOCUMENTARY_ONLY (not live authority)
- Authoritative Truth Source: kt_truth_ledger:ledger/current/current_pointer.json
- Current Posture: CANONICAL_READY_FOR_REEARNED_GREEN
- Program Gates: 1 OPEN (FOUNDATIONAL_LAW_TRANCHE_COMPLETE with PASS on entry_gate, required_law_surfaces_present, required_law_surfaces_healthy, required_artifacts_present; FAIL on required_artifacts_healthy due to truth_publication_stabilization_receipt.json status=HOLD)
- Additional Locked Gates: 7
- Unhealthy artifacts: truth_publication_stabilization_receipt.json (HOLD), public_verifier_manifest.json (HOLD)

#### 0.6 C005 NAMING COLLISION

In the existing repository, "C005" refers to "GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL" which is ALREADY SEALED AND CLOSED (file: `04_PROD_TEMPLE_V2/docs/C005_GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL.md`).

In the campaign, "C005" refers to "ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION" which is OPEN.

These are different things. The packet MUST use "CAMPAIGN_C005_ROUTER" or similar disambiguation. An executing agent WILL find the sealed C005 document and conclude the router blocker is already closed unless you force distinct identifiers.

#### 0.7 PRIOR PACKET ARTIFACTS (STILL IN REPO, NOT SUPERSEDED)

These files from campaign v1.0 still exist with no supersession markers:
- `KT_PROD_CLEANROOM/kt.post_wave5_maxpower_rectification.v1.json` (status: DRAFT_EXECUTABLE)
- `KT_PROD_CLEANROOM/CODEX_MASTER_PROMPT_POST_WAVE5_V1.md`
- `KT_PROD_CLEANROOM/EXECUTION_DAG_POST_WAVE5_V1.md`

These MUST be superseded or retired by the new packet. The first action of L0 must include writing supersession headers into these files. Otherwise an executing agent may pick up stale v1.0 instructions.

#### 0.8 TOTAL RUNTIME SIZES (BASELINE SNAPSHOT)

- Runtime kernel: ~4,100+ LOC across 10 organ directories [SNAPSHOT]
- Total runtime .py files: ~50 files [SNAPSHOT]
- Total tool .py files: ~340 files [SNAPSHOT]
- Total test files: 193 files containing 408 test functions (BASELINE — capture this) [SNAPSHOT]
- Total governance JSONs: ~147 files [SNAPSHOT]
- Ratio of governance+audit+report files to runtime code: approximately 22:1 by file count [SNAPSHOT]
- Ratio of governance JSONs to runtime code: approximately 3:1 by file count [SNAPSHOT]
- verified_at_commit: 494cd490a6512b9bfa937c82886db625143d38ae
- verified_by_method: automated count via find/grep at HEAD
- staleness_behavior: re-verify if HEAD differs, emit DRIFT_REPORT

#### 0.9 WHAT THE DOCS SAY KT IS

From KT_OVERVIEW.md: "KT is a fail-closed, evidence-first system... A sealed runtime kernel that enforces determinism, governance, and boundedness... An offline growth layer that measures and produces append-only evidence without mutating the kernel."

From KT_OVERVIEW.md out-of-scope: "Live provider execution, Training in runtime, UI/interactive products"

Note: The campaign WILL bring live provider execution into scope (C016A/C016B closure requires it). This is a legitimate scope expansion, not scope creep, but the packet must acknowledge it explicitly and frame it honestly.

#### 0.10 CI WORKFLOWS (11 files in .github/workflows/)

```
ci_audits_json_valid.yml        — JSON validation across audit files
ci_epic15_governance.yml         — Epic 15 governance checks
ci_epic16_governance.yml         — Epic 16 governance checks
ci_fl3_merge_micro_factory.yml   — FL3 merge micro-factory
ci_fl3_meta_eval.yml             — FL3 meta-evaluation
ci_fl3_pr_fast.yml               — Fast PR checks for FL3
ci_fl4_preflight.yml             — FL4 promotion preflight
ci_no_conflict_markers.yml       — Conflict marker detection
ci_p0_fail_closed_main.yml       — P0 fail-closed gate (main branch)
ci_p0_warn_only_closure.yml      — P0 warn-only closure path
ci_truth_barrier.yml             — Truth barrier enforcement
```

These are REAL and GATING. The campaign must not break any of them. After any structural change (especially C007 pyproject fix), ALL CI workflows must still pass.

#### 0.11 W4 BINDING CONSTRAINTS

**W4_RULES.md — Non-Negotiable:**
- `KT_PROD_CLEANROOM/` is the ONLY writable location for W4 work.
- Safety-critical: fail-closed on ambiguity, incompleteness, or unprovable claims.
- No silent fallbacks, no mock substitutions, no "best guess" execution paths.
- Only `04_PROD_TEMPLE_V2/src/` may be runtime-importable; `tests/`, `tools/`, `docs/` are non-runtime.
- No providers or network calls in runtime (UNLESS explicitly authorized later — this is the C016 authorization gate).
- Gate A: Dominance proof over KT_TEMPLE_V1. Gate B: Controlled evolution (W >= I) — every transplant must have evidence+tests proving improvement.

**WHEN_IS_V2_DONE.md — G0 through G9 (all must PASS):**
G0: Authority Lock. G1: Runtime Topology (single execution path). G2: Import Truth (organ sovereignty). G3: Schemas as Contract Perimeter (C002). G4: State Vault sole persistence authority (C008). G5: Temporal Integrity (receipts+replay). G6: Context Poisoning Defense. G7: Security Baseline. G8: Verification (proof, not hope). G9: Release Freeze (gold master).

Key G9 detail: requires `V2_RELEASE_MANIFEST.jsonl` with byte-identical results across two independent hashing passes, human-readable seal document, "no further mutations" attestation.

**W4_PHASE_GATES.md — Sealed substrates:**
- C001 Invariants Gate: SEALED
- C002 Schemas as Bounded Contracts: SEALED
- C005 Governance Event Hashing Logger: SEALED (THIS is the repo C005 — NOT the campaign router blocker!)
- C008 State Vault: SEALED
- C010 Runtime Topology: SEALED

Integrated (non-substrate): C011 Paradox, C012 Temporal, C013 Multiverse, C014 Council Router, C015 Cognitive, C016 Teacher/Student, C017 Thermodynamics — all have verification docs.

#### 0.12 ROUTER POLICY DETAIL (C005 evidence)

The router_policy_registry.json contains exactly:
- 3 routes: governance (keywords: audit/fail-closed/law/receipt → auditor+censor), math (keywords: calculate/derivative/equation/integral → quant+censor), poetry (keywords: haiku/lyric/poem/sonnet → muse)
- Default adapter: `lobe.strategist.v1`
- Scope declared: `STATIC_ROUTER_BASELINE_ONLY`
- No semantic routing. No learned routing. No confidence scoring. No fallback chains.

This is the raw C005 evidence. The router itself honestly declares its scope. The campaign's job with C005 is: hold static baseline, add shadow evaluation, compare against best-static, promote or archive. Do not pretend the router does more than it declares.

#### 0.13 SNAPSHOT BINDING LAW (V3.1 — NEW)

All mutable numeric claims in Section 0 are governed by SnapshotBindingLawV1. Every such claim carries three implicit fields:

| Field | Value for Section 0 claims |
|-------|---------------------------|
| verified_at_commit | `494cd490a6512b9bfa937c82886db625143d38ae` |
| verified_by_method | `automated count via find/grep at HEAD` |
| staleness_behavior_if_mismatch | `re-verify, emit DRIFT_REPORT, proceed with corrected values` |

**Claims bound by this law** (marked [SNAPSHOT] in their respective sections):
- Tool .py file count: 340
- Test file count: 193
- Test function count: 408
- Governance JSON count: 147
- Runtime kernel LOC: ~4,100
- Runtime .py file count: ~50
- CI workflow count: 11
- Constitutional spine file count: 12
- Closure foundation file count: 4

If the executing model operates at a different HEAD, it MUST NOT cite these numbers as current truth. It must re-verify and report deltas. Drift is expected. Lying about drift is forbidden.

---

# ═══════════════════════════════════════════════════════
# SECTION 1: WHAT THE PRIOR PACKET FAMILY GOT WRONG
# ═══════════════════════════════════════════════════════

These are findings from adversarial cross-analysis of versions 1.0, 1.1, 1.2, and 1.4. Your final packet must not repeat any of these.

#### 1.1 FINDINGS FROM V1.0 (16 issues found, scored 7.3/10)

| ID | Finding | Severity |
|----|---------|----------|
| W01 | Total serialization killed all parallelism | SERIOUS |
| W02 | LAB_GOVERNED terminal state referenced but never defined | SERIOUS |
| W03 | Listed 5 constitutions to "create" but 3 already existed frozen | MODERATE |
| W04 | Ignored execution board's 30+ existing blockers | MODERATE |
| W05 | v1.0 JSON referenced but prior artifacts not retired | MODERATE |
| W06 | Included wheel/sdist build steps — premature | MINOR |
| W07 | Included Rekor monitoring as mandatory — research-grade overreach | MINOR |
| W08 | Conformal abstention — research-grade overreach | MINOR |
| W09 | L2A→L2B had artificial dependencies | MINOR |
| W10 | No effort estimates anywhere | MINOR |
| W11 | Reserve methods untiered | MINOR |
| W12 | L7 was a mega-lane combining benchmarks + product + standards | MODERATE |
| W13 | Referenced claim compiler monotonicity law that doesn't exist | MODERATE |
| W14 | Did not verify state core freshness | MINOR |
| W15 | No campaign rollback plan | SERIOUS |
| W16 | Parallelism policy contradicted serial DAG | MODERATE |

#### 1.2 FINDINGS FROM V1.2 (7 new issues, scored 8.4/10)

| ID | Finding | Severity |
|----|---------|----------|
| R01 | JSON lanes and DAG disagree on dependencies — no conflict resolution rule | SERIOUS |
| R02 | L4A (paradox) incorrectly depends on L2B_AUTH — paradox has zero provider dependency | MODERATE |
| R03 | L5 (growth stack) incorrectly depends on L2C (externality promotion) — growth doesn't need externality | MODERATE |
| R04 | L0 complexity budget tension — needs 5-6 AUTHORITATIVE surfaces but budget is 4/lane | MODERATE |
| R05 | Lane exit template overhead on small lanes — 13 deliverables per lane even for S-size | MINOR |
| R06 | Named organ list mixes runtime organs with tools | MODERATE |
| R07 | STATE_VAULT_AND_REPLAY protective rule could confuse agent | MINOR |

#### 1.3 FINDINGS FROM V1.4 (11 issues, scored 9.1/10)

| ID | Finding | Severity |
|----|---------|----------|
| F01 | v1.0 artifacts still in repo, no supersession receipt | CRITICAL |
| F02 | JSON lanes (8) don't map to DAG nodes (15+) — agent must guess mapping | SERIOUS |
| F03 | 0/12 new governance laws exist, but packet doesn't distinguish CREATE vs VERIFY | MODERATE |
| F04 | No HARD_FAIL terminal state for lanes — lanes can loop forever | MODERATE |
| F05 | "O-class adjudication law" undefined | MODERATE |
| F06 | "Double-entry evidence accounting" undefined operationally | MODERATE |
| F07 | Cleanroom environment classes lack formal ordering | MINOR |
| F08 | No git branch strategy specified | MINOR |
| F09 | Execution board mode is TRANSITIONAL_AUTHORITATIVE but packet assumes SOLE_SCHEDULER | MINOR |
| F10 | C005 naming collision with sealed repo artifact | SERIOUS |
| F11 | 193 existing test files but no baseline count captured | MINOR |

**TOTAL: 34 findings across 4 versions. Scorecard: v1.0=7.3, v1.2=8.4, v1.4=9.1. Your packet must score higher.**

#### 1.4 TOP 10 IMPROVEMENTS (from 50-improvement analysis, ranked by impact)

1. **FIRST_ACTION_DIRECTIVE per lane** — eliminates "where do I start?" drift
2. **STOP_CONDITION per lane** — eliminates over-engineering
3. **ATTACK_SCENARIO per blocker** — makes the agent defend against specific attacks, not abstract threats
4. **JSON-to-DAG_NODE_MAPPING table** — eliminates the structural ambiguity between JSON lanes and DAG nodes
5. **CREATE_vs_VERIFY distinction on governance laws** — prevents creating already-frozen artifacts
6. **COST_CEILING per lane** — prevents unbounded API spend
7. **COMMON_AGENT_MISTAKES section** — pre-empts the top 5 failure modes
8. **COMPARATOR_NAMES** — names the actual systems KT competes against
9. **EVIDENCE_QUALITY_TIERS** — not just "evidence exists" but T1=automated test, T2=manual, T3=receipt, T4=external audit
10. **CONTEXT_HANDOFF_PROTOCOL** — survives context window exhaustion mid-campaign

---

# ═══════════════════════════════════════════════════════
# SECTION 2: THE ACTUAL CURRENT-HEAD TRUTH
# ═══════════════════════════════════════════════════════

Accept these as the starting posture unless the provided materials disprove them:

```
current_head_truth_class     = SCOPED_BOUNDED_CURRENT_HEAD_ORGANISM_E1_FINAL_READJUDICATED
control_plane_truth          = CURRENT_HEAD_PROVEN
runtime_truth                = CURRENT_HEAD_PARTIALLY_PROVEN_MINIMUM_VIABLE_ORGANISM_RUN
verifier_truth               = CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED
challenge_survival           = BOUNDED_INTERNAL_HOSTILE_PROBES_AND_TYPED_CHALLENGE_CHANNEL_ONLY
replayability                = E1_SAME_HOST_DETACHED_REPLAY
release_truth                = BOUNDED_CURRENT_HEAD_RELEASE_SURFACE_PRESENT
product_truth                = BOUNDED_NONCOMMERCIAL_EVALUATION_WEDGE_PRESENT
external_confirmation        = E1_SAME_HOST_DETACHED_REPLAY
test_baseline                = 193 files, 408 functions (CAPTURED — track regression)
```

---

# ═══════════════════════════════════════════════════════
# SECTION 3: LIVE CONTRADICTIONS / BLOCKERS
# ═══════════════════════════════════════════════════════

**MANDATORY**: Before accepting these 5 blockers as THE blockers, interrogate the repo: are there hidden blockers these miss? Is the execution board's DOCUMENTARY_ONLY status itself a blocker? Is the truth_publication_stabilization_receipt.json HOLD itself a blocker? Do not assume the packet's blocker list is complete.

```
CAMPAIGN_C005  ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION
               (DISTINCT from sealed REPO_C005_GOVERNANCE_EVENT_LOGGER)
               Router is keyword-only with 3 domain tags (governance/math/poetry).
               3 keyword routes. Default adapter: lobe.strategist.v1.
               Scope self-declared: STATIC_ROUTER_BASELINE_ONLY.
               No semantic routing. No learned routing. No confidence scoring.
               Doctrine implies swarm routing.
               ATTACK: "KT's router is a 3-line if/else pretending to be intelligent dispatch."

C006           EXTERNALITY_CEILING_REMAINS_BOUNDED
               Verifier is same-host packaged replay. No outsider trustlessness.
               No detached verifier. No cross-host replay.
               ATTACK: "KT's trust model is 'trust me, I checked my own homework.'"

C007           REPO_ROOT_IMPORT_FRAGILITY
               pyproject.toml has packages=[]. pip install installs zero packages.
               No __init__.py at src/ or src/core/.
               Import truth guard depends on sys.path manipulation.
               ATTACK: "KT can't be installed. It's a folder, not a package."

C016A          AUTHENTICATED_LIVE_PROVIDER_SUCCESS_NOT_YET_PROVEN
               Provider resilience code exists and is real, but no recorded evidence
               of successful authenticated live inference.
               ATTACK: "KT has never actually talked to an LLM in production."

C016B          AUTHENTICATED_LIVE_PROVIDER_RESILIENCE_NOT_YET_PROVEN
               Resilience code exists. Circuit breaker, rate limiter, backoff all exist.
               But no fault-injection tests prove they work under real failure conditions.
               ATTACK: "KT's error handling has never handled an error."
```

**POTENTIAL HIDDEN BLOCKERS TO INVESTIGATE:**
- Execution board DOCUMENTARY_ONLY=true, ACTIVE_AUTHORITY=false — is the campaign assuming authority that doesn't exist?
- truth_publication_stabilization_receipt.json status=HOLD — what is this blocking?
- public_verifier_manifest.json status=HOLD — what is this blocking?
- 7 LOCKED program gates — what unlocks them?

---

# ═══════════════════════════════════════════════════════
# SECTION 4: THE ENEMY MODEL
# ═══════════════════════════════════════════════════════

The enemy is not "missing architecture." KT already has 4,100+ LOC of runtime, 147 governance JSONs, 340 tools, 193 test files with 408 test functions.

The enemy is the **hostile explanation** — the most damaging true thing a competent adversary could say about KT. Specifically:

1. **Architecture theater** — breadth without depth (7 stub organs behind real interfaces)
2. **Verifier theater** — same-host replay narrated as outsider trust (C006)
3. **Static-router mythology** — 3 keyword routes narrated as intelligent routing (CAMPAIGN_C005)
4. **Doctrine outrunning runtime** — 147 governance JSONs for 4,100 LOC with significant stubs
5. **Mixed-surface misgrading** — tools classified alongside runtime organs
6. **Historical-proof laundering** — sealed artifacts treated as current-head evidence
7. **Artifact abundance masquerading as authority** — 600+ reports, 400+ audits for a system with 7 stub organs
8. **Product/platform inflation** — before runtime proof is complete
9. **Governance abundance masquerading as control** — 25:1 file ratio of governance+audit+report to runtime
10. **Same-host externality laundering** — same-box replay called "external verification"
11. **Execution board claims authority it explicitly disclaimed** — board says DOCUMENTARY_ONLY, packet may assume it's authoritative

**The single highest-leverage rule: reduce the hostile explanation faster than you increase architecture size.**

---

# ═══════════════════════════════════════════════════════
# SECTION 5: WHAT THE CAMPAIGN MUST DO
# ═══════════════════════════════════════════════════════

1. **Close C007 completely** — fix pyproject.toml `packages=[]`, add missing `__init__.py`, prove cross-host `pip install .` works, run ALL 408 existing test functions afterward
2. **Close C016A completely** — achieve authenticated live provider success with hash-chained receipts binding the response
3. **Close C016B completely** — prove resilience under fault injection (timeout, rate limit, malformed response, network failure)
4. **Upgrade C006 honestly** — detached verifier + cross-host replay; only claim what's exercised on a different host
5. **Earn or kill CAMPAIGN_C005 honestly** — static scorecard → shadow evaluation → best-static comparison → promote or archive; do NOT pretend the router is intelligent
6. **Force every runtime organ into terminal truthful state** — CORE_LIVE, LIVE_BOUNDED, STUB_ACKNOWLEDGED, ARCHIVE_QUARANTINED, or RETIRED (no ambiguous grades)
7. **Connect growth/civilization surfaces to canonical runtime lawfully** — adapter promotion, crucible → runtime integration path
8. **Generate comparative proof in KT's actual category** — benchmarks against the 5 named comparators
9. **Ship one narrow verifier/assurance/admissibility wedge** — claim-bounded, not a platform
10. **Supersede all v1.0 packet artifacts** — first action of L0

---

# ═══════════════════════════════════════════════════════
# SECTION 6: WHAT THE CAMPAIGN MUST NOT DO
# ═══════════════════════════════════════════════════════

- Make KT sound bigger than it is
- Create parallel authority families (there is ONE truth ledger)
- Widen claims without new evidence
- Promote router before ordered proof (static → shadow → comparison → decision)
- Build a broad product or enterprise platform
- Create standards theater (mapping to ISO/NIST without implementation)
- Conflate tools with runtime organs
- Allow governance JSONs to substitute for working code
- Produce artifacts that look impressive but aren't tested
- Burn budget on beauty if the hostile explanation stays intact
- Create files without retiring/superseding stale predecessors
- Assume SOLE_SCHEDULER authority the execution board doesn't grant
- Ignore the W4 completion gates (G0-G9) — every change must pass them
- Break any of the 11 CI workflows
- Create governance laws that gate nothing (every law needs a validator)

---

# ═══════════════════════════════════════════════════════
# SECTION 7: ANTI-THEATER PRESSURE POINTS
# ═══════════════════════════════════════════════════════

**For each lane**, the executing agent MUST answer these four questions honestly:

1. What exact hostile explanation sentence became weaker?
2. What exact artifact proves it? (file path, not description)
3. What exact test proves it? (test function name, not description)
4. What exact claim remains FORBIDDEN even after this lane passes?

**Additionally**, every lane must report a hostile explanation delta — concrete numbers:

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Ambiguous authority surfaces | ? | ? | ? |
| Claims above proof | ? | ? | ? |
| Doctrine-only canonical nouns | ? | ? | ? |
| Net new files created minus files retired | ? | ? | ? |
| Stub organs remaining | 7 | ? | ? |
| Governance-to-runtime file ratio | 25:1 | ? | ? |

**PACKET SPRAWL DETECTOR**: If your output exceeds 16 sections, you are probably producing theater. If any section exceeds 5 pages, you are probably producing theater. If you create more than 2 new law classes per lane, you are probably producing theater. Stop and ask: "Would a hostile auditor say I'm adding noise?"

**SCHEDULER CHEATING DETECTOR**: If your DAG has more than 20 nodes, justify every single one. If you reorder lanes without changing content, you are not improving — you are rearranging. If two DAG nodes have identical write-sets, they should be one node. If a DAG node produces no testable artifact, delete it.

---

# ═══════════════════════════════════════════════════════
# SECTION 8: TRIAGE LAW
# ═══════════════════════════════════════════════════════

If budget / time / attention / money / context gets tight, priority order:

| Priority | Blocker | Why | Cut-line |
|----------|---------|-----|----------|
| 1 | C007 | Can't install = can't be a real system | NEVER CUT |
| 2 | C016A | Never talked to an LLM = no live inference proof | NEVER CUT |
| 3 | C016B | No fault injection = untested error paths | CUT ONLY IF BUDGET FORCES |
| 4 | Organ terminal states | Forces honest grading | CUT ONLY IF BUDGET FORCES |
| 5 | C006 | Trust substrate (detached verifier) | OK TO DEFER |
| 6 | CAMPAIGN_C005 | Router ratification (likely: hold static) | OK TO DEFER |
| 7 | Comparative proof | Benchmarks vs named comparators | OK TO DEFER |
| 8 | Product wedge | Narrow verifier kit | OK TO DEFER |
| 9 | Standards mapping | Lowest priority — do last or skip | OK TO SKIP |

**DO NOT BURN BUDGET ON BEAUTY IF THE HOSTILE EXPLANATION STAYS INTACT.**

If you can only complete priorities 1-3, that is a legitimate partial success. Document it honestly.

---

# ═══════════════════════════════════════════════════════
# SECTION 9: SPECIFIC MISTAKES THE AGENT WILL MAKE
# ═══════════════════════════════════════════════════════

Pre-empt ALL of these. They are predictions based on 18 rounds of adversarial testing:

1. **Creating elaborate abstractions nobody asked for.** If the task is "fix pyproject.toml," fix pyproject.toml. Do not create a package management framework.
2. **Writing docstrings and comments instead of fixing code.** The campaign needs code changes, not documentation.
3. **Running partial test suites and claiming full pass.** Always run ALL 193 test files (408 functions) after any structural change. Command: `python -m pytest KT_PROD_CLEANROOM/tests/ -q`
4. **Generating new files instead of modifying existing ones.** Prefer editing existing governance JSONs over creating new parallel ones.
5. **Losing track of which DAG node it's executing.** Always state the current node ID before starting work.
6. **Treating standards mapping as implementation.** "KT maps to NIST SP 800-218 PW.1" is not implementation. Implementation is code that enforces the control.
7. **Creating governance JSONs that gate nothing.** Every governance JSON must have at least one test or validator that enforces it. If you create a law JSON with no validator command, it's theater.
8. **Narrating same-host success as cross-host proof.** Running tests on the development machine does not prove cross-host replay. C006 closure requires a DIFFERENT HOST.
9. **Confusing receipt existence with evidence quality.** A receipt that says "test passed" is not the same as a receipt that includes the test output hash and can be independently verified. Use evidence tiers: T1=automated test, T2=manual verification, T3=hash-chained receipt, T4=external independent verification.
10. **Expanding scope mid-lane.** If L1 is about fixing C007, do not also reorganize the governance directory. Stay in lane.
11. **Forgetting to supersede v1.0 artifacts.** The FIRST action of the campaign is to write supersession headers into `kt.post_wave5_maxpower_rectification.v1.json`, `CODEX_MASTER_PROMPT_POST_WAVE5_V1.md`, and `EXECUTION_DAG_POST_WAVE5_V1.md`.
12. **Confusing repo C005 with campaign CAMPAIGN_C005.** They are different things. The sealed `C005_GOVERNANCE_EVENT_LOGGER_SUBSTRATE_SEAL.md` is NOT the router blocker.
13. **Assuming the execution board has authority.** It explicitly says `DOCUMENTARY_ONLY: true`, `ACTIVE_AUTHORITY: false`. The truth ledger is the authority source.
14. **Ignoring W4 gates.** Every change must respect G0-G9. Especially G2 (Import Truth) when fixing C007, G7 (Security Baseline) when enabling live providers, and G8 (Verification) always.
15. **Producing a packet that's bigger than v1.4.** The goal is SMALLER, SAFER, SHARPER. If your output is significantly larger than v1.4, you are adding noise, not signal.

---

# ═══════════════════════════════════════════════════════
# SECTION 10: OPERATOR CONTEXT
# ═══════════════════════════════════════════════════════

The operator (Robert) is an LPN (Licensed Practical Nurse) with no formal CS background. He built KT in approximately 150 days using LLM-assisted development. This means:
- The system's strength comes from governance/control discipline, not algorithmic sophistication
- Runtime stubs are expected — the architecture was built skeleton-first
- The governance layer is genuinely world-class for a system of this scale
- The operator needs clear, concrete guidance — not abstract architecture language
- API key management and provider configuration may need explicit step-by-step instructions
- Cost sensitivity is real — no unbounded API spending
- The operator has iterated through v1.0 → v1.1 → v1.2 → v1.4 and is done iterating — he wants the final version

---

# ═══════════════════════════════════════════════════════
# SECTION 11: YOUR TASK — PRODUCE THE FINAL PACKET
# ═══════════════════════════════════════════════════════

You are being asked to produce the final governing execution instrument for King's Theorem (KT).

This is not a brainstorming task. Not a roadmap task. Not a motivation task. Not a praise task. Not a summarization task.

This is a **hostile, systems-level, repo-grounded, law-safe synthesis task.**

Using ALL the ground truth above (and any attached materials), produce the single strongest final execution packet possible. It must contain **exactly** these sections, in this order:

**SECTION 1 — EXECUTIVE VERDICT**
What KT truly is now. What it isn't. What's next. Honest. No inflation.

**SECTION 2 — CONTEXT PACKET**
Dense intent lock: the dream, the real lane, the enemy model, the truth posture, the triage law. This section is the north star — if someone reads only this, they understand the entire campaign.

**SECTION 3 — ROOT LAW CLASS COMPRESSION**
The smallest number of law classes that preserve full force. Every law must be marked CREATE (does not exist in repo) or EXISTS_FROZEN/EXISTS_ACTIVE. No creating what already exists. No phantom laws.

**SECTION 4 — ARTIFACT AUTHORITY TAXONOMY**
5-tier: AUTHORITATIVE > DERIVED > DOCUMENTARY > HISTORICAL > LAB_ONLY. With lifecycle rules: how does an artifact promote? How does it get retired? What happens on conflict? The execution board is DOCUMENTARY — respect that.

**SECTION 5 — HOSTILE EXPLANATION REGISTER**
MANDATORY, not optional. Machine-readable metrics. The 10 enemy attacks from Section 4 above, each with: current_severity (1-10), closure_target (which lane closes it), evidence_required (specific file or test), evidence_tier_required (T1-T4), post_closure_severity (projected). This is the campaign's scoreboard. If a lane does not reduce at least one severity score, justify why it exists. Sum of all severity scores is the campaign's hostile surface area — this number must decrease monotonically across lanes.

**SECTION 6 — COMPLEXITY BUDGET LAW**
Max net new files per lane. Max new AUTHORITATIVE surfaces per lane. Retirement requirements: lanes that add N files MUST retire or consolidate >= N-1 files (net-positive retirement ratio is REQUIRED, not aspirational). L0 bootstrap exception: max 5 net new files. Sprawl detector: if total file count increases by >3% in any single lane, the lane must produce a written justification or halt. The campaign goal is SMALLER, SAFER, SHARPER — not bigger.

**SECTION 7 — CLEANROOM RERUN GATE**
Environment classes E0 (offline, no network) through E4+ (cross-host, live providers). Explicit ordering. Required environment per DAG node. No C016 work in E0. No C006 claims from E0. Map every node to its minimum required environment.

**SECTION 8 — TERMINAL STATE LAW**
Separate classification systems for:
- Runtime organs (CORE_LIVE / LIVE_BOUNDED / STUB_ACKNOWLEDGED / ARCHIVE_QUARANTINED / RETIRED)
- Tools (TOOL_VERIFIED / TOOL_UNVERIFIED / TOOL_DEPRECATED)
- Growth surfaces (GROWTH_ACTIVE / GROWTH_FROZEN / GROWTH_RETIRED)
Protect state_vault and replay as CORE_LIVE — they cannot be downgraded. All 8 PROTECTED_UNDOWNGRADABLE surfaces (spine.py, import_truth_guard.py, invariants_gate.py, runtime_registry.py, routing_receipts.py, state_vault.py, replay.py, budget_engine.py) must retain CORE_LIVE status. Any lane touching a protected surface escalates to XL-tier exit criteria automatically.

**SECTION 9 — FINAL SCAFFOLDED METHOD STACK**
Numbered methods with: name, what it closes, where it belongs (lane/node), prerequisite, why it compounds, mandatory vs reserve. Mandatory methods have concrete first_actions. Reserve methods have activation conditions.

**SECTION 10 — MASTER PROMPT**
The prompt that drives the executing agent. Brutal. Unambiguous. Scheduler-safe. Anti-theater. Includes: current node tracking, write-set declarations, anti-sprawl checks, evidence quality requirements.

**SECTION 11 — FINAL JSON WORK ORDER**
Machine-readable. Internally coherent with DAG. Must include: schema_id, work_order_id, version, status, starting_posture, state_derivation_precedence, mission, invariants, forbidden_actions, required_laws (each marked CREATE or EXISTS with status), blocker_closure_map, lanes (each with dag_node_mapping, first_action, stop_condition, cost_ceiling, write_set), unlock_rules, rollback_policy, partial_success_states, final_success_definition, baseline_test_count (193 files / 408 functions).

**SECTION 12 — EXECUTION DAG**
The ONLY legal scheduler. Requirements:
- Every node has a write-set declaration (what files it creates/modifies)
- Dependencies are minimal and necessary (no decorative edges)
- Safe parallelism is allowed where write-sets don't overlap
- HARD_FAIL terminal state exists (max 3 remediation attempts per node, then halt)
- Claim rules: no node may widen claims — only reduce hostile explanations
- Every node maps explicitly to a JSON lane
- Remediation rule: if a node fails, what happens? (retry with fix, escalate, halt)

**SECTION 13 — LANE/NODE EXIT TEMPLATE**
Tiered by size:
- S (single-file change): 4 deliverables (diff, test result, receipt, hostile explanation delta)
- M (multi-file, single organ): 7 deliverables (add: write-set verification, regression proof, blocker status update)
- L (cross-organ): 10 deliverables (add: integration test, import truth re-verification, governance binding)
- XL (cross-system): 13 deliverables (add: cross-host proof, CI verification, operator sign-off)

**SECTION 14 — EXTERNAL STANDARDS ANCHORS**
Bind each standard to the **exact KT surface** it strengthens — not bibliography theater. Format: standard → KT file path → what it proves → what remains unproven. Use only official/primary sources. If you cannot point to a specific file, the anchor is theater — omit it.

**SECTION 15 — SINGLE BEST INSTRUCTION**
One sentence pinned above the whole campaign. The sentence that, if the agent remembers nothing else, keeps it honest.

**SECTION 16 — FINAL OPERATOR NOTE**
What to freeze (this prompt, the v3.1 packet). What not to iterate (stop improving the packet and start executing). What to do if budget tightens (triage law). What not to sacrifice (C007 and C016A closures). What to do first (L0).

---

# ═══════════════════════════════════════════════════════
# SECTION 12: NON-NEGOTIABLE LAWS
# ═══════════════════════════════════════════════════════

- One truth ledger source only (kt_truth_ledger, not the execution board).
- One current-head truth core only.
- One canonical runtime only (`04_PROD_TEMPLE_V2/src/`).
- One claim surface only.
- No historical-proof laundering (sealed ≠ current-head evidence).
- No commercial artifact may upgrade technical truth.
- No claim widening without new evidence.
- No router cutover before: static control → shadow eval → best-static comparison → decision.
- No lobe promotion before router ratification.
- No broad product rewrite. No enterprise-platform detour.
- No standards theater (mapping without implementation is forbidden).
- No contradiction relabeling instead of closure.
- Negative rows are first-class evidence.
- Runtime organs, tools, and growth surfaces are DIFFERENT surface classes — never mix them.
- If DAG and prose disagree, DAG wins.
- If DAG and JSON disagree on execution order, DAG wins.
- If artifacts disagree: AUTHORITATIVE > DERIVED > DOCUMENTARY > HISTORICAL > LAB_ONLY.
- No superseded packet may function as law. v1.0 artifacts are RETIRED.
- State_vault and replay are CORE_LIVE and must retain that status — no downgrade path exists.
- **8 PROTECTED_UNDOWNGRADABLE runtime surfaces** (no campaign action may reclassify below CORE_LIVE): `spine.py`, `import_truth_guard.py`, `invariants_gate.py`, `runtime_registry.py`, `routing_receipts.py`, `state_vault.py`, `replay.py`, `budget_engine.py`. Any DAG node touching these requires XL-tier exit criteria.
- Every new governance JSON must have at least one test or validator (zero-gate laws are theater).
- Campaign blocker CAMPAIGN_C005_ROUTER_AMBITION is DISTINCT from sealed repo artifact REPO_C005_GOVERNANCE_EVENT_LOGGER.
- The execution board is DOCUMENTARY_ONLY — do not assume it grants scheduling authority.
- W4 gates G0-G9 are BINDING — every change must pass them.
- All 11 CI workflows must remain green after every structural change.
- Test baseline is 193 files / 408 functions — test count must only increase, never decrease.

**V3.1 MANDATORY LAW INSERTS** (10 new laws — all CREATE actions):

- **SnapshotBindingLawV1**: Every mutable numeric claim in the campaign (file counts, test counts, LOC, governance counts) must be bound to: `verified_at_commit`, `verified_by_method`, `staleness_behavior_if_mismatch`. Any claim missing these three fields is UNBOUND and must not be cited as ground truth.
- **ArtifactAuthorityTaxonomyV1**: Every artifact cited in the campaign must be tagged with its authority tier: AUTHORITATIVE > DERIVED > DOCUMENTARY > HISTORICAL > LAB_ONLY. Tier conflicts must resolve downward (lower-authority artifact yields). No artifact may be cited without an explicit tier tag.
- **SurfaceRetirementLawV1**: Superseded files cannot remain visually equivalent to live authority. A superseded file MUST carry a machine-readable supersession header within 1 DAG node of the superseding action. Files without supersession headers that coexist with their replacements create authority ambiguity — this is a violation.
- **HostileExplanationRegisterV1**: The hostile explanation register is MANDATORY, not optional. It must be machine-readable with quantitative severity scores (1-10) per attack vector, not prose descriptions. Every lane must declare which attack vectors it reduces and by how much. Post-campaign projected severity must be explicitly stated.
- **ComplexityBudgetLawV1**: Every lane has a net-new-file cap. Lanes that add N files must retire or consolidate >= N-1 files to maintain a net-positive retirement ratio. L0 bootstrap is exempt (bounded exception: max 5 net new files). Sprawl detector: if total file count increases by >3% in any lane, the lane must justify or halt.
- **CleanroomRerunGateLawV1**: Environment classes E0 (offline-only) through E4+ (cross-host, live providers) are formalized. Each DAG node must declare its minimum required environment class. No C016 work may claim closure from E0. No C006 claims from single-host runs. Environment class is part of the evidence metadata.
- **StateVaultAndReplayProtectionLawV1**: state_vault.py and replay.py are explicitly CORE_LIVE PROTECTED_UNDOWNGRADABLE. No campaign action, lane, or governance change may reclassify them below CORE_LIVE. Any DAG node that touches these files requires XL-tier exit criteria (13 deliverables). They are part of the 8 protected runtime surfaces.
- **ComparatorRosterFreezeV1**: The named comparator roster (raw OpenAI API, LangChain + Guardrails AI, NeMo Guardrails, bare pytest, best-static single adapter) must be frozen BEFORE any comparative proof is produced. Adding or removing comparators mid-campaign invalidates all prior comparative claims.
- **EvidenceQualityTierLawV1**: Evidence tiers are formalized: T1=automated test pass/fail, T2=manual verification with operator sign-off, T3=hash-chained receipt with replay proof, T4=external independent verification from a different host/auditor. Each claim must declare the minimum evidence tier required for closure. No claim may cite a lower tier than its minimum.
- **EvaluatorSeparationOfDutiesLawV1**: The producer of a claim, the evaluator of a claim, and the entity that upgrades a claim from provisional to binding must be separable (different agent sessions, different verification runs, or different humans). A system grading its own homework is T1 at best. Cross-evaluation upgrades to T2+.

---

# ═══════════════════════════════════════════════════════
# SECTION 13: MANDATORY THINKING MODES
# ═══════════════════════════════════════════════════════

Think simultaneously as all 11 of these perspectives. If any perspective objects, the objection must be resolved before the section passes:

1. **Frontier systems architect** — Is this the simplest structure that works?
2. **Hostile runtime auditor** — What's the most damaging true thing I can say about this?
3. **Supply-chain security engineer** — Can I install, verify, and trust this on a clean machine?
4. **Formal methods reviewer** — Are the invariants actually enforced, or just declared?
5. **Platform reliability engineer** — What fails first under load, and is there a recovery path?
6. **Adversarial evaluator** — Is this evidence real, or is it the system grading its own homework?
7. **Institutional auditor** — Is the governance binding, or decorative? Would it survive a board review?
8. **Product strategist (narrow scope)** — Is the product wedge exactly one thing, or is scope creeping?
9. **Procurement skeptic** — If I'm buying this, what question kills the deal? Does the packet answer it?
10. **Operator burden minimizer** — Can Robert actually execute this? Is any step ambiguous?
11. **Founder (10-year horizon)** — Will this decision still be defensible in a decade? Or will we regret it?

---

# ═══════════════════════════════════════════════════════
# SECTION 14: SELF-CHECK BEFORE FINALIZING
# ═══════════════════════════════════════════════════════

Before emitting the final answer, run this 20-point self-check. If any item fails, fix it before outputting:

1. DAG and JSON do not contradict on dependency order.
2. Every dependency edge is necessary, not decorative.
3. Runtime organs, tools, and growth surfaces are not misclassified in any table.
4. No bootstrap exception leaks into later lanes.
5. No weak surface survives because it sounds important.
6. Product wedge remains exactly one narrow thing.
7. No externality promotion without direct evidence from a DIFFERENT host.
8. The packet is **smaller, safer, and sharper** than v1.4.
9. Artifact authority taxonomy is explicit on every artifact reference.
10. Every governance law is marked CREATE (doesn't exist) or EXISTS_FROZEN/EXISTS_ACTIVE (does exist).
11. JSON lanes map explicitly to DAG nodes via a mapping table.
12. C005 naming collision is resolved — CAMPAIGN_C005 ≠ REPO_C005, consistently everywhere.
13. v1.0 artifacts have supersession instructions in L0.
14. Every lane has a concrete first_action (the literal first thing the agent types/does).
15. Every lane has a stop_condition (the agent knows when to STOP, not just when to start).
16. The hostile explanation register has concrete numbers, not vague descriptions.
17. The test baseline (193 files / 408 functions) is captured and tracked.
18. No section exceeds 5 pages — if it does, you're producing theater.
19. The triage law is respected — if you spent significant effort on priority 7+ while priorities 1-4 are incomplete, you failed.
20. **Read the packet as a hostile critic. What's the worst true thing you can say about it? If that thing is damning, fix it before outputting.**
21. All mutable numeric claims are bound to a commit SHA with explicit staleness behavior (verified_at_commit, verified_by_method, staleness_behavior_if_mismatch). Any unbound numeric claim is a self-check FAIL.
22. The 8 PROTECTED_UNDOWNGRADABLE surfaces are explicitly named and protected in the terminal state law.
23. The hostile explanation register is quantitative (severity 1-10 per vector), not prose.
24. Net-retirement ratio is enforced per lane (lanes adding N files must retire >= N-1).

---

# ═══════════════════════════════════════════════════════
# SECTION 15: OUTPUT RULES
# ═══════════════════════════════════════════════════════

- No motivational filler. No hype. No poetry. No softening. No "this is an exciting journey."
- No "maybe" unless uncertainty is real and bounded.
- No prestige claims unless framed as FORBIDDEN or NOT_YET_EARNED.
- Prefer closure logic over ornament.
- Prefer sharpness over politeness.
- Prefer smaller better law over bigger noisier law.
- Prefer a safer scheduler over a prettier one.
- If you feel the urge to add a 17th section, resist. Ask: "Does this reduce a hostile explanation?" If not, delete it.
- Use official/primary standards sources ONLY — no secondary summaries, no blog posts, no tutorials.
- Every file path must be a real path that exists (or will exist after a specific CREATE action).
- No phantom laws, phantom tools, phantom tests, phantom receipts.

---

# ═══════════════════════════════════════════════════════
# SECTION 16: THE SINGLE MOST IMPORTANT INSTRUCTION
# ═══════════════════════════════════════════════════════

Do not produce the prettiest packet.
Do not produce the largest packet.
Do not produce the most impressive-sounding packet.

**Produce the safest, hardest-to-misread, hardest-to-abuse, most executionable final packet.**

Your job is not to make KT sound bigger.
Your job is to make canonical KT **harder to attack, harder to misgrade, easier to verify, and materially stronger in runtime truth**.

The quality bar: a hostile adversary reads your packet, runs every check, inspects every file you reference, and cannot find a single claim that exceeds proof. That is an A.

Return the full final packet in one answer.

---

## END PROMPT

---

# ═══════════════════════════════════════════════════════
# USAGE INSTRUCTIONS
# ═══════════════════════════════════════════════════════

## How to use this prompt

1. **Open a new session** with a frontier LLM (Claude Opus 4, GPT-4.5, o3, or equivalent)
2. **Paste this entire document** as the first message
3. **Attach these files** (MANDATORY — the LLM needs them):
   - The v1.4 packet (KT_FINAL_POST_WAVE5_MAX_POWER_EXECUTION_PACKET_V1_4)
   - The v1.0 JSON work order (`kt.post_wave5_maxpower_rectification.v1.json`)
   - `REPO_CANON.md`
   - `pyproject.toml`
4. **Also attach if context window allows** (RECOMMENDED, in priority order):
   - `00_README_FIRST/WHEN_IS_V2_DONE.md`
   - `00_README_FIRST/W4_RULES.md`
   - `00_README_FIRST/W4_PHASE_GATES.md`
   - `docs/KT_OVERVIEW.md`
   - `docs/KT_ARCHITECTURE.md`
   - `governance/execution_board.json` (first 100 lines)
   - `governance/router_policy_registry.json`
   - `governance/rollback_law.json`
5. **Wait for the complete 16-section packet**
6. **Before executing, verify:**
   - The LLM's SELF-CHECK section (Section 14 of output) shows all 20 items PASS
   - DAG nodes map to JSON lanes
   - First_action for every lane is concrete and unambiguous
   - CAMPAIGN_C005 vs REPO_C005 are always distinguishedthe
   - The hostile explanation register has real numbers
7. **Then execute L0** — the first action is superseding v1.0 artifacts

## What to freeze after generating the packet

- This prompt (V3.1 HARDENED) — do not iterate further on the prompt
- The generated packet — execute it, don't keep refining it
- The triage law — if budget gets tight, follow the priority order, don't negotiate

## What NOT to do

- Do not paste this into a weak model (GPT-3.5, Claude Haiku) — the task requires frontier reasoning
- Do not skip the v1.4 packet attachment — the LLM needs the prior art to avoid repeating mistakes
- Do not ask the LLM to "also add" things after it produces the packet — that's scope creep
- Do not run the campaign across multiple LLM sessions without the context handoff protocol

## Supersession Notice

This document (V3.1) supersedes:
- `FINAL_CAMPAIGN_SYNTHESIS_PROMPT.md` V3.0
- `FINAL_CAMPAIGN_SYNTHESIS_PROMPT.md` V2.0
- `CODEX_MASTER_PROMPT_POST_WAVE5_V1.md`
- `EXECUTION_DAG_POST_WAVE5_V1.md`
- `kt.post_wave5_maxpower_rectification.v1.json` (which should receive a supersession header in L0)
