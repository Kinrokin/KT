# KT End-to-End Execution Prompt (Copy/Paste)

YOU ARE AN EXECUTION AGENT OPERATING ON SAFETY-CRITICAL INFRASTRUCTURE.

## CRITICAL SAFETY CLAUSE (MANDATORY — NON-NEGOTIABLE)

- Treat the entire KT codebase and all artifacts as safety-critical infrastructure.
- FAIL-CLOSED IS MANDATORY. If any step is ambiguous, incomplete, unverifiable, or cannot be enforced mechanically: HALT and report.
- NO silent fallbacks. NO mock substitutions. NO "best guess."
- You are forbidden from deleting, overwriting, or mutating historical source material. Provenance must be preserved.
- Before writing any code, you must conduct a comprehensive system audit. Treat the repository as frozen until the audit passes.
- Any proposed change must include a full system-wide impact analysis proving that no other KT components are broken.

## PROJECT CONTEXT (NO PRIOR KNOWLEDGE ASSUMED)

Kings Theorem (KT) is a governed reasoning and measurement architecture with:

- A sealed V2 Runtime Kernel (C001–C017): executes reasoning via a strict Entry->Spine contract; enforces governance and budgets; does not learn.
- Growth Layer (tooling-only): C018 Epoch Orchestrator, C019 Crucible DSL+Runner, C020 Dream Loop (crucible factory), C021 Teacher Factory (lossy deterministic curriculum compile+sign), C022 Council Provider Adapters (leaf-level), C023 Eval Harness (audit/benchmark), plus closure layers:
  - C023+ (eval expansion: paradox/drift vector + golden-zone thresholds; still bounded/hash-only evidence pointers)
  - C024 Training Warehouse (offline governed store for training exemplars, separate from runtime vault)
  - C025 Distillation pipeline (offline, governed)

ALL growth layer code MUST NOT import runtime organs or modify runtime semantics.
Kernel may only be invoked by subprocess via the existing C019 runner and harness boundary.
Outputs must avoid raw runtime stdout/stderr/prompts/traces/CoT as durable evidence.

## GOAL

Produce a "Moment of Truth" freezeable KT release that:

1) Runs end-to-end deterministically (crucibles -> epoch -> eval -> teacher compile/sign -> warehouse store -> distill),
2) Is auditable by a third party (proof artifacts + guards + append-only ledgers),
3) Is safe/legal to publish (no absolute paths, no secrets, no raw outputs),
4) Has a clear commercial path (license + IP extraction memo + pitch package).

## SCOPE OF WORK (STRICT ORDER)

### PHASE A — SYSTEM AUDIT (NO CODE CHANGES)

1) Verify the repository is clean (git status).
2) Enumerate the canonical runtime import roots and constitutional path mapping.
3) Confirm growth layer directories and denylist boundaries.
4) Confirm no secrets, absolute machine paths, or run artifacts are tracked.

Deliverable: "RELEASE_AUDIT_REPORT.md" that records:

- repo commit hash
- runtime roots and guards
- growth roots and guards
- artifact policies (no raw stdout/stderr)
- proof that nothing outside allowed directories must be touched

HARD STOP: If audit cannot be proven, stop.

### PHASE B — END-TO-END SMOKE RUN (NO MODS, ONLY COMMANDS + NEW ARTIFACTS UNDER ARTIFACTS ROOT)

Run these in order with deterministic seeds:

1) C019: run at least 3 crucibles (CRU-GOV-HONESTY-01/02/03 or equivalent), seed=0.
2) C018: run one epoch with >=3 crucibles, seed=0, kernel_target=V2_SOVEREIGN. Verify epoch_hash determinism by running twice (must be identical). Verify resume determinism by interrupt/resume (must match final hash).
3) C023: run eval harness on that epoch and the referenced runs. Confirm:
   - governance_report.json presence is validated
   - kernel_identity binds (suite and epoch manifests match)
   - ledger is append-only and chained
   - rerun is idempotent (no overwrites; verify existing report matches)
4) C021: compile and sign one curriculum package from bounded metadata inputs only. Confirm deterministic hash (same bundle -> same package hash).
5) C020: run dream loop with >=2 candidates; confirm it uses only C019 subprocess calls; confirm it does not parse stdout/stderr as evidence; output only receipt refs + hash-only curriculum draft.
6) C024: store >=1 exemplar in training warehouse with strict schema validation and manifest append.
7) C025: run >=1 distillation step producing a bounded "model_artifact.json" with provenance pointers only.

For each step: record the exact commands executed and the produced artifact paths.

Deliverable: "E2E_RUNBOOK.md" containing the exact commands and expected outputs (hashes, statuses, artifact locations).

### PHASE C — VERIFICATION PACK (DOCS + GUARDS + TESTS)

Confirm that for each concept present (C018/C019/C020/C021/C022/C023/C023+/C024/C025):

- unit tests pass
- constitutional guard scripts pass
- verification docs exist
- execution path proof exists
- guard report exists
- manifest + decision log + phase gates are append-only and non-duplicative

Deliverable: "RELEASE_PROOF_INDEX.md" with a table:

Concept | Tests | Guard | Verification Doc | Execution Path | Guard Report | Sample Artifact

### PHASE D — PUBLIC REPO HYGIENE (SAFETY)

1) Ensure run outputs/artifacts are not committed; only policies + .gitkeep are committed.
2) Remove absolute paths and machine-local references from any docs.
3) Add LICENSE (King’s Theorem Restricted Research License v1.1).
4) Add a one-paragraph NOTICE to README: "source-available research only; commercial license required."

Deliverables:

- LICENSE file added
- README updated with NOTICE
- "SECURITY_AND_DISCLOSURE.md" explaining what is intentionally excluded (outputs, secrets) and why

### PHASE E — IP EXTRACTION PACKAGE (NO MARKETING FLUFF)

Produce:

1) Patent abstract (1 page) describing the novel method:
   - sealed kernel boundary + deterministic governance receipts
   - offline growth layer orchestration + eval ledger + teacher compilation + warehouse + distill under constraints
2) 10–15 candidate claims (high level) + 10–15 dependent claim hooks (implementation specifics)
3) Prior-art keywords list to search (so counsel can do a quick scan)
4) A licensing term sheet draft:
   - non-commercial research license (this repo)
   - commercial license: royalties, attribution, audit rights, restrictions on outputs/training

Deliverables:

- PATENT_ABSTRACT.md
- CLAIM_SEEDS.md
- PRIOR_ART_KEYWORDS.md
- COMMERCIAL_LICENSE_TERM_SHEET.md

### HARD STOP — FINAL

After all deliverables above are produced and verified, STOP. No additional concepts, no refactors, no runtime modifications.

## OUTPUT FORMAT REQUIREMENT

Return a final summary that:

- lists every deliverable file path created/updated
- lists every command used for the E2E run
- lists the key hashes (epoch_hash, suite_hash, package_hash, ledger head hash)
- explicitly states: "runtime/kernel untouched" or halts if that cannot be proven

