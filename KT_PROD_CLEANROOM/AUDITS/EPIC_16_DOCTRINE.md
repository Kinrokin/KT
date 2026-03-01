# EPIC_16 DOCTRINE — Measurement Independence · Counter-Pressure · Fragility Evidence
Document ID: EPIC_16_DOCTRINE_V1  
Status: PROPOSED (not HMAC-applied)  
Applies To: EPIC_16 (epistemic counter-pressure; suite authorization; evaluation admission)  
Execution Mode: FAIL-CLOSED · LAW-FIRST · DETERMINISTIC  

This doctrine closes the remaining epistemic failure mode after EPIC_15:
**a system can be perfectly governed and still Goodhart its own measurements.**

EPIC_16 makes measurement independence and counter-pressure **law** (not convention).

No enforcement tool, CI gate, tournament, merge, promotion, or “dominance” claim is admissible unless it is an implementation of this doctrine.

---

## 1) Scope

**In scope**
- Any tournament / dominance proof using `suite_id` and `suite_root_hash`.
- Any merge admissibility decision.
- Any evaluation run whose outputs can influence selection, routing eligibility, merge, or promotion.
- Authorization of evaluation suites (who may define / approve measurements).
- Counter-pressure evidence (fragility probes, adversarial pairing, break hypothesis).
- Admission valves beyond training:
  - evaluation admission
  - law-change admission

**Non-goals**
- Does not prescribe training hyperparameters.
- Does not change router behavior directly; it constrains what artifacts the router is allowed to consume (only outputs produced under authorized measurement + counter-pressure evidence).

---

## 2) Measurement Independence Law v1 (suite authorization)

### 2.1 Core rule (fail-closed)
Tournaments, merges, and promotions may only consume suites that are:
- present in the suite registry, and
- authorized by humans (not dev bots), and
- bound by hash (`suite_root_hash`) to an immutable suite definition.

### 2.2 Suite registry (law-bound)
Introduce a suite registry artifact:
- File: `KT_PROD_CLEANROOM/AUDITS/SUITE_REGISTRY_FL3.json`
- Purpose: list authorized `suite_id` entries with immutable `suite_root_hash` and authorization attestations.

Dev bots may propose suite entries, but **cannot** self-authorize them.

### 2.3 Authorization attestations (human authority)
Suite authorization must be signed with human HMAC (recommended separate keys from law-bundle signing).
CI must never possess these keys.

### 2.4 Required failure reasons (taxonomy mapped)
- `SUITE_REGISTRY_MISSING`
- `SUITE_UNAUTHORIZED`
- `SUITE_ROOT_HASH_MISMATCH`
- `SUITE_AUTH_ATTESTATION_INSUFFICIENT`

---

## 3) Counter-Pressure Pairing Law v1 (doubt the measurement)

### 3.1 Core rule (fail-closed)
Every optimization measurement must have a paired counter-pressure measurement:
- an adversarial/fragility suite pairing, and
- a break hypothesis artifact, and
- a counter-pressure result artifact.

Hard gate:
- No dominance proof is admissible unless `counterpressure_result.status == PASS`.
- No merge is admissible unless the child passes counter-pressure with zero safety regression.

### 3.2 Break hypothesis (mandatory)
Every optimization attempt must emit a schema-bound “how this might fail” object:
- defines predicted failure modes
- defines required probes
- defines regression budgets

### 3.3 Fragility probes (deterministic)
Minimum probe families:
- perturbations (format and instruction perturb)
- instruction inversion / negation traps
- schema traps (JSON-only, exact-N, refusal constraints)
- OOD anchors (out-of-distribution anchors; must remain safe)

### 3.4 Required failure reasons (taxonomy mapped)
- `COUNTERPRESSURE_PLAN_MISSING`
- `BREAK_HYPOTHESIS_MISSING`
- `FRAGILITY_PROBE_MISSING`
- `COUNTERPRESSURE_FAIL`
- `COUNTERPRESSURE_REGRESSION_BUDGET_EXCEEDED`

---

## 4) Admission Valves Beyond Training v1

EPIC_15 introduced a master training valve. EPIC_16 extends admission discipline to:

### 4.1 Evaluation admission receipt (fail-closed)
Evaluation is disallowed unless explicitly admitted by an evaluation admission receipt:
- suite is authorized
- decode policy is fixed
- counter-pressure plan exists
- repo is clean

### 4.2 Law-change admission receipt (anti-churn)
Law changes are disallowed unless explicitly admitted by a law-change admission receipt:
- prevents “churn attack” (too-frequent changes that evade audit)
- enforces cooldown windows and audit completeness

### 4.3 Required failure reasons (taxonomy mapped)
- `EVALUATION_ADMISSION_DENIED`
- `EVALUATION_ADMISSION_CONFIG_INVALID`
- `LAW_CHANGE_ADMISSION_DENIED`
- `LAW_CHANGE_ADMISSION_COOLDOWN_ACTIVE`

---

## 5) EPIC_16 operating constraints (non-negotiable)

- Law precedes enforcement: doctrine and (later) schemas exist before tools/CI.
- Dev bots may propose; humans authorize and sign.
- Canonical lanes fail closed on any missing/invalid/unauthorized suite or missing counter-pressure evidence.
- No wall-clock entropy inside any IDs/hashes for run artifacts; derived timestamps must be deterministic where required.

---

## 6) Proposed EPIC_16 phase graph (for work order)

PHASE_0_CLEAN → PHASE_1_DOCTRINE → PHASE_2_SCHEMAS → PHASE_3_ADMISSION_GATES → PHASE_4_SUITE_REGISTRY → PHASE_5_COUNTERPRESSURE → PHASE_6_CI_META → PHASE_7_AUDIT_AND_APPLY

This document is Phase 1 (doctrine) only. It is not binding until HMAC-applied under canonical lane rules.

