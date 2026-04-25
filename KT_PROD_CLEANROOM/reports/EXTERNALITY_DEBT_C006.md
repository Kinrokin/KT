# EXTERNALITY DEBT - C006

**Status:** OPEN - DEFERRED (RESOURCE CONSTRAINT)  
**Class:** Externality / Cross-Host Proof  
**Severity:** P0 WHEN HARDWARE AVAILABLE  
**Deferral Date:** 2026-03-22  
**Current HEAD:** 494cd490a6512b9bfa937c82886db625143d38ae  

---

## What C006 Is

C006 = `EXTERNALITY_CEILING_REMAINS_BOUNDED`

KT's verifier is same-host packaged replay. No outsider trustlessness. No detached cross-host verifier. No independent hostile replay. The hostile one-liner: *"KT's trust model is 'trust me, I checked my own homework.'"*

Current externality ceiling: **E1 (Same-Host Detached Replay)**

---

## What C006 Blocks

| Surface | Blocked? | Why |
|---------|----------|-----|
| E2 (Cross-Host Friendly Replay) | **YES** | No second host has run the verifier |
| E3 (Independent Hostile Replay) | **YES** | Requires E2 first + hostile reviewer |
| E4 (Public Challenge Survival) | **YES** | Requires E3 first + public interface |
| Comparative superiority claims | **YES** | Cannot compare without external proof |
| Commercial externality claims | **YES** | Enterprise readiness requires E2+ |
| Press-ready / product-launch language | **YES** | Claim ceiling locked at E1 |
| "Independently verified" language | **YES** | Same-host != independent |
| "Cross-platform proven" language | **YES** | Only one platform tested |

---

## What C006 Does NOT Block

| Surface | Blocked? | Status |
|---------|----------|--------|
| Internal runtime improvements | **NO** | Full speed ahead |
| Lawful evolution (adapters, promotion) | **NO** | LAB_GOVERNED lanes open |
| Router/lobe experiments | **NO** | LAB only |
| Capability atlas compilation | **NO** | Bounded to E1 evidence |
| Claim compiler operation | **NO** | Bounded to E1 ceiling |
| MVCR live execution | **NO** | Canonical paths open |
| Organ disposition work | **NO** | Terminal-state register open |
| Packaging and installer | **NO** | Ship it |
| Documentation | **NO** | Write it |
| Operator UX | **NO** | Build it |
| Demos and proof bundles | **NO** | Same-host evidence packs OK |
| Business model | **NO** | Design it |
| Investor materials | **NO** | With E1 claim ceiling |
| Customer pilot flow | **NO** | Bounded to E1 truth |
| Omega gate internals | **NO** | Governance hardening open |
| Benchmark constitution work | **NO** | Dataset registry, holdouts, contamination |
| Tournament execution | **NO** | LAB_GOVERNED |
| Training warehouse | **NO** | LAB_GOVERNED |

---

## Why It's Deferred

Single-operator lab. One machine. No cloud VM, no second laptop, no university lab access, no VPS currently provisioned. The C006 infrastructure is **fully built** - trust prep receipt passes (8/8), handoff pack passes (6/6), execution receipt passes (4/5 with only `second_host_return_present` failing), submission template ready, three operator validators tested. The only missing thing is a second physical host.

---

## Reentry Path (When Hardware Appears)

1. Obtain access to **any** second host (cloud VM, RPi, friend's laptop, university machine, $5 VPS)
2. Copy the detached verifier package to it using `kt_independent_replay_recipe.md`
3. Run the detached verifier entrypoint - no hidden secrets required
4. Capture result + runtime receipt + host environment metadata
5. Fill in `post_wave5_c006_second_host_submission_template.json`
6. Import to `reports/imports/post_wave5_c006_second_host_return.json`
7. Run: `python tools/operator/post_wave5_c006_second_host_execute_validate.py`
8. If PASS -> externality rises from E1 to E2, deferral removed

Estimated effort once hardware is available: **< 2 hours.**

---

## Existing Infrastructure (All Built, All Tested)

| Artifact | Status |
|----------|--------|
| `reports/post_wave5_c006_trust_prep_receipt.json` | PASS (8/8) |
| `reports/post_wave5_c006_friendly_host_handoff_pack.json` | PASS (6/6) |
| `reports/post_wave5_c006_second_host_execution_receipt.json` | 4/5 PASS (awaiting return) |
| `reports/post_wave5_c006_second_host_submission_template.json` | Template ready |
| `reports/kt_independent_replay_recipe.md` | Written |
| `tools/operator/post_wave5_c006_trust_prep_validate.py` | Tested |
| `tools/operator/post_wave5_c006_friendly_host_handoff_validate.py` | Tested |
| `tools/operator/post_wave5_c006_second_host_execute_validate.py` | Tested |

---

## Forbidden Language Until C006 Resolved

Do not use any of the following in any KT surface until E2 is earned:

- "independently verified"
- "cross-platform proven"
- "externally reproducible"
- "enterprise ready" (in externality sense)
- "commercially proven"
- "SOTA" / "beyond state of the art"
- "frontier"
- "category-leading" (comparative)
- "outsider-verified"

---

## Machine Reference

- Formal deferral register: `reports/deferred_blockers.json`
- Deferral heartbeat: `reports/c006_deferral_heartbeat.json`
- Truth lock: `governance/current_head_truth_lock.json`
- Externality matrix: `governance/kt_externality_class_matrix_v1.json`
- Campaign anchor: `governance/kt_unified_convergence_max_power_campaign_v2_1_1_anchor.json`
