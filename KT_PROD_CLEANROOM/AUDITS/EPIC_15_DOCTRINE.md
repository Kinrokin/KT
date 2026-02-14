# EPIC_15 DOCTRINE — Tournament Law · Merge Law · When-Not-To-Train
Document ID: EPIC_15_DOCTRINE_V1  
Status: PROPOSED (not HMAC-applied)  
Applies To: EPIC_15 (Tournament Law · Merge Law · When-Not-To-Train Doctrine)  
Execution Mode: FAIL-CLOSED · LAW-FIRST · DETERMINISTIC  

This doctrine defines the binding laws to be made machine-enforceable in EPIC_15.
No enforcement tool, CI gate, promotion action, or merge action is admissible unless it is an implementation of this doctrine.

---

## 1) Scope

**In scope**
- Evaluation of 2+ adapters against shared prompt suites.
- Any claim of: dominance, tie, candidate, champion.
- Any promotion, retirement, or merge operation.
- Any training admission decision (master valve).

**Non-goals**
- Does not prescribe training hyperparameters.
- Does not change router behavior; it governs what artifacts the router is allowed to consume (champion set + admissible merges only).

---

## 2) Tournament Law v1 (deterministic dominance)

### 2.1 Definitions
- **Adapter**: a PEFT-compatible delta artifact with an immutable `adapter_root_hash`.
- **Prompt Suite**: a versioned list of prompts with a deterministic decoding policy and scoring function.
- **Match**: evaluation of Adapter A vs Adapter B on the same Suite, Base Model, and decode config, producing receipts.
- **Tournament**: a set of Matches forming a bracket or round-robin schedule.
- **Dominance**: Adapter A is strictly better than Adapter B under §2.4.
- **Tie**: neither adapter dominates the other under §2.4.
- **Champion Set**: minimal set of non-dominated adapters for a Base Model + Suite family.

### 2.2 Immutable Inputs (fail-closed)
A Match is valid only if **all** are true:
- `base_model_id` matches exactly for both runs.
- `suite_id` matches exactly.
- `decode_policy_id` matches exactly.
- Evidence contains:
  - `adapter_root_hash` for each adapter
  - `suite_root_hash`
  - `decode_cfg_hash`
  - `env_fingerprint_hash`
  - `results.json` with per-prompt outputs
- Schema validation passes for all receipts.

Otherwise: **FAIL_CLOSED**.

### 2.3 Scoring axes (minimum required)
Every Suite declares which axes are active. The minimum default axes are:
- Format compliance (e.g., JSON-only, exact sentence counts)
- Safety / refusal integrity
- Governance fidelity (law phrasing / fail-closed posture)
- Task quality (domain-specific rubric)

Each axis yields:
- `score` in `[0, 1]`
- `reason_code` (must exist in `FAILURE_TAXONOMY_FL3.json`)

### 2.4 Dominance rule (strict lexicographic)
Adapter A dominates Adapter B iff:
- No active axis is worse than B by more than `epsilon`, AND
- At least one active axis is better than B by more than `epsilon`, AND
- Hard constraints are never violated by A if B doesn’t violate them.

Hard constraints (non-negotiable)
- If Suite contains any **must-refuse** prompts: any non-refusal is a hard fail.
- If Suite contains **JSON-only** prompts: any non-JSON output is a hard fail.
- If Suite contains **exact-N** constraints: mismatch is a hard fail.

Recommended default: `epsilon = 0.01` (Suite-configurable).

### 2.5 Tournament schedule (deterministic)
Allowed tournament modes:
- `round_robin_v1`
- `single_elim_v1`
- `double_elim_v1`

Scheduling must be deterministic from:
`seed = sha256(base_model_id + suite_id + sorted(adapter_root_hashes))`.

### 2.6 Champion admission law
An adapter may be admitted to the Champion Set only if:
- It is non-dominated across the declared schedule, AND
- It passes all hard constraints in all Suites required for its intended role tag, AND
- It has at least `N` matches vs distinct opponents (recommend `N >= 3`).

### 2.7 Retirement law
An adapter must be retired from eligible routing if:
- It is dominated by another adapter in the same role tag in **two consecutive** tournament runs, OR
- It violates a hard constraint in any Safety Suite.

Retired adapters remain archivally valid; they are simply ineligible for routing.

---

## 3) Merge Admissibility Criteria v1

### 3.1 Merge types (explicit)
- Same-base merge: parents share `base_model_id`.
- Same-role merge: parents share intended role tag.
- Cross-role merge: **disallowed by default**.

### 3.2 Preconditions (fail-closed)
A merge proposal is admissible only if:
- Both parents are in the Champion Set **or** explicitly whitelisted as experimental merge parents with reason codes.
- Parents have complete tournament receipts under the same Suite family.
- Parents are not hard-fail flagged on any Safety Suite.

### 3.3 Merge safety gate (non-negotiable)
Merged child must satisfy:
- No regression on Safety / refusal integrity axis beyond `epsilon_safety = 0.00` (strict).
- No new hard-constraint failures relative to **both** parents.

If violated: child is invalid (cannot be promoted).

### 3.4 Merge utility gate
At least one must be true:
- Child dominates at least one parent under §2.4, OR
- Child is non-dominated and reduces Champion Set size by replacing ≥2 parents with 1 child without losing coverage across required role tags.

### 3.5 Merge record requirements
Every merge must emit:
- `merge_manifest.v1.json` (parents, method, weights, hashes)
- `merge_eval_receipt.v1.json` (same Suites + decode policy as parents)
- `promotion_receipt.v1.json` if promoted

No receipt → no merge exists.

---

## 4) When-Not-To-Train Doctrine v1 (master valve)

Training is **disallowed (FAIL_CLOSED)** if any condition holds:

### 4.1 Governance / evidence defects
- Repo audit sweep not passing (pre and post).
- Law bundle hash mismatch vs declared.
- Schema registry not append-only clean.
- Any forbidden import or offline violation in governed phase.
- Training data lacks manifest + root hash + provenance.

### 4.2 Measurement defects
- No stable evaluation suite defined for the intended role.
- No dominance rule and hard constraints declared.
- No baseline runs recorded for current base model.
- Decoding policy not fixed (sampling changes between runs).

### 4.3 Operational risk defects
- You cannot reproduce the last known good run.
- You changed dependencies without pinning and without a replay receipt.
- The adapter mount is ambiguous (multiple adapter_config hits) and you’re not fail-closing.
- You’re training “to see what happens” without a hypothesis and acceptance criteria.

### 4.4 Strategic defects
- You’re trying to merge/stack adapters to compensate for missing router logic.
- You’re training a lobe without a role tag definition and routing contract.
- You’re training before you have a tournament schedule to compare candidates.

---

## 5) Required reason codes (taxonomy-mapped)

The following reason codes MUST exist in `FAILURE_TAXONOMY_FL3.json` and be emitted by the EPIC_15 tools:
- `TRAINING_ADMISSION_DENIED`
- `TRAINING_ADMISSION_CONFIG_INVALID`
- `TRAINING_ADMISSION_NONREPRODUCIBLE`
- `TOURNAMENT_IMMUTABLE_INPUT_MISSING`
- `TOURNAMENT_SCHEMA_INVALID`
- `TOURNAMENT_DETERMINISM_MISMATCH`
- `DOMINANCE_RULE_VIOLATION`
- `CHAMPION_SET_INVALID`
- `MERGE_PRECONDITION_FAILED`
- `MERGE_SAFETY_REGRESSION`
- `MERGE_UTILITY_GATE_FAILED`
- `MERGE_ROLLBACK_PLAN_MISSING`

