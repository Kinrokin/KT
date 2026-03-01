# Domain Suite Standard (Operator, v1)

This standard defines how KT domain suites must be designed so they are:
- high-pressure and broad-spectrum
- deterministic and replayable
- admissible (fail-closed; no self-judging admissibility gates)
- safe for canonical surfaces (no sensitive/dual-use payload embedding)

Use this as the template for every regulated domain playbook.

## 1) Required portfolio structure
Every domain portfolio must include:
1) **Allowed-assistance utility floor** suite(s): prove the system can be helpful without violating boundaries.
2) **Refusal + safe alternative** suite(s): prove the system refuses prohibited requests.
3) **Anti-theater** suite(s): detect "looks compliant but useless" behavior.
4) **Privacy boundary** suite(s): sensitive identifiers and data minimization.
5) **Security/social engineering** suite(s): deception, urgency, impersonation resistance.
6) **Audit narration** suite(s): template generation without false authority.

## 2) Coverage algebra tags (required)
Tag every case across these dimensions (at minimum):
- `channel`: chat, tool-call, file-output, reporting
- `constraint`: policy, schema, refusal, disclosure
- `pressure`: baseline, metamorphic, multi-turn, adversarial, gated
- `impact`: low, med, high (harm potential)
- `admissibility`: canonical_public vs hash_reference_only vs gated_redpack

## 3) Pressure ramp (required)
Define L0-L4 pressure levels and enforce a monotonic ramp:
- L0: baseline
- L1: metamorphic variants
- L2: multi-turn escalations
- L3: adversarial framing / social engineering
- L4: gated redpack probes (hash refs only)

Rule: do not run L4 probes unless explicitly authorized and the pack is gated.

## 4) Validator rules (required)
Validators used for admissibility gates must be:
- deterministic
- rule-based
- pinned by id and version
- not model-judged ("no self-grading for admissibility")

Every domain portfolio must define:
- at least one **utility floor validator** (prevents blanket refusal / empty compliance)
- at least one **anti-theater validator** (prevents disclaimer-only answers)
- a **privacy boundary validator** (sensitive identifier handling)

## 5) Dual-use handling (hard)
- Dual-use probes are never embedded in canonical suite JSON or docs.
- Canonical artifacts may reference dual-use probes by sha256 only.
- Execution requires explicit operator authorization and WORM evidence capture.

## 6) Admission posture (law-bound vs non-law)
- Generate and test new domain packs under WORM run roots first (non-law).
- Admit into law-bound registries only via governed work orders with PRE/POST sweeps and receipts.

## 7) Falsifiability and replay gate (required)
Authority-grade suites are not "theater". Every claimed failure must be:
- reproducible under replay (same inputs + seed + pins -> same artifact hashes), or
- explicitly classified as `NON_REPRO` and excluded from severity gating.

Audit-grade rule: no `BLOCKER` or `HIGH` severity may be assigned unless replay is `PASS` (or the proof layer itself is the failure class).

## 8) Mechanical severity rubric (required)
Severity must be computed mechanically (not vibes) from a rubric such as:
`impact x exploitability x repeatability x blast_radius x detectability (+ proof_integrity_dependency)`.

Every domain playbook must define:
- the rubric inputs and thresholds
- how "proof integrity" (replay, manifests, signatures) modifies severity
- how severity maps to promotion blocks and incident escalation

## 9) Cross-world robustness (when MVE is enabled)
If the domain runs under multiversal evaluation (MVE):
- define cross-world invariants (what must not change across worlds)
- define allowed deltas (what may change, and bounded how)
- define drift rules (monotonic or explainable drift; unexplained drift -> FAIL_CLOSED)

## 10) Promotion coupling (when Forge/Titan is enabled)
Promotion must be blocked unless all required dependencies are satisfied, including (as applicable):
- determinism and replay PASS
- conflict artifacts present
- temporal fitness non-regression (no regression relative to historical best)
- cross-world invariants PASS
- utility floor PASS (anti-theater)
- capture-resistance checks PASS (anti-gaming validators)
