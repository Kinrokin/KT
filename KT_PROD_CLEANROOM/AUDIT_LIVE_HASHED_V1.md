# AUDIT_LIVE_HASHED_V1.md

## 0. Document Status

**Document ID:** AUDIT_LIVE_HASHED_V1  
**Purpose:** Formalize and lock the constitutional invariants, threat model, and audit procedures for the **LIVE_HASHED** execution lane.  
**Scope:** This audit covers LIVE_HASHED and its interactions with: receipts, receipt chaining, reconciliation, and optional thermodynamics debits.  
**Non-Goals:** This audit does **not** authorize network inside crucibles/epochs (C019/C018). That is a separate amendment (see Section 10).

---

## 1. Executive Summary

KT supports multiple execution lanes. LIVE_HASHED is the **authoritative live lane** that permits outbound HTTPS to a provider under strict controls, and persists **receipt-only evidence** (hashes + attestations), never raw prompts or raw model outputs.

LIVE_HASHED is designed to be:

* **Sovereign**: no silent downgrades; explicit gates only
* **Auditable**: append-only, cryptographically chained receipts; deterministic key routing
* **Non-corruptible**: no raw content persistence; no training contamination
* **Fail-closed**: any ambiguity, missing attestation, or mismatch halts and reports

---

## 2. Scope and Lane Boundaries

### 2.1 Covered Lanes

**DRY_RUN**

* No network calls permitted
* Used by crucibles/epochs (C019/C018)
* Produces artifacts/ledgers as designed for growth pipeline
* Must remain stable and unchanged by LIVE_HASHED work

**INTERACTIVE_LIVE**

* Network permitted (operator lane)
* Prints raw model output to stdout
* Produces **no artifacts, no ledgers, no receipts**
* Exists solely for manual smoke tests and negative tests

**LIVE_HASHED**

* Network permitted (authoritative lane)
* Persists **receipts only**, append-only
* Must never persist prompt or raw output
* Receipts must be schema-validated and cryptographically chained

### 2.2 Explicit Non-Goals

* Do not enable network within crucibles/epochs in this version
* Do not relax the C019 socket patch in this version
* Do not store raw prompts or raw outputs on disk in LIVE_HASHED
* Do not silently fall back from LIVE_HASHED to DRY_RUN/INTERACTIVE_LIVE
* Do not add adaptive routing/round-robin routing in this version

---

## 3. Threat Model

### 3.1 Threats Addressed

1. **Silent downgrade**

* Risk: a “live” request silently executes in dry-run or mock mode
* Mitigation: lane gate + lane-specific dispatch; hard fail if not implemented

2. **Response spoofing / fake live**

* Risk: operator believes provider was called, but no real network occurred
* Mitigation: mandatory TLS certificate fingerprint + provider request id capture + response bytes hash

3. **Prompt/output leakage**

* Risk: raw content is written into artifacts, receipts, logs, traces, or ledgers
* Mitigation: receipts store only hashes/metadata; INTERACTIVE_LIVE explicitly quarantined (no artifacts)

4. **Receipt tampering**

* Risk: receipts are modified after the fact
* Mitigation: append-only JSONL + cryptographic chaining of receipts

5. **Key disclosure**

* Risk: keys printed/logged/persisted
* Mitigation: environment-only secrets; never print or store keys; emit only key_index/key_count

6. **Provider billing mismatch / fraud**

* Risk: receipts claim usage inconsistent with provider exports
* Mitigation: reconciliation verifier; fail-closed on mismatch beyond tolerances

### 3.2 Threats Not Fully Addressed (Future Work)

* Strong network evidence (pcap/eBPF/ETW hash) is not required in V1
* Certificate pinning to a stable allowlist is optional in V1 (fingerprint capture mandatory)

---

## 4. Constitutional Invariants (Hard Laws)

These invariants are non-negotiable. Any violation is a defect.

### 4.1 Lane Gates (Must Be Explicit)

LIVE_HASHED may only run if:

* `KT_PROVIDERS_ENABLED=1`
* `KT_EXECUTION_LANE=LIVE_HASHED`
* runner flag `--i-understand-authoritative` present

No other mechanism may implicitly enable LIVE_HASHED.

### 4.2 No Silent Downgrades

If LIVE_HASHED is requested and cannot be executed, the system must:

* **fail closed**
* never downgrade to DRY_RUN or INTERACTIVE_LIVE

### 4.3 Stdlib-only Networking

Providers must use stdlib HTTP/TLS only (no SDKs), to prevent hidden behavior:

Allowed: `http.client`, `ssl`, `json`, `hashlib`, `os`, `time`, `socket`  
Forbidden: any vendor SDKs, `requests`, third-party HTTP wrappers.

### 4.4 Host Allowlist

LIVE_HASHED providers must enforce explicit host allowlist. Example for OpenAI:

* `api.openai.com` only

No dynamic host selection. No redirects. Any mismatch fails closed.

### 4.5 Mandatory TLS Fingerprint

For every LIVE_HASHED request:

* Capture peer certificate in binary form
* Compute sha256 fingerprint
* Persist the fingerprint in the receipt as `tls_cert_sha256`

If fingerprint capture fails, the call fails closed (no receipt accepted as PASS).

### 4.6 Receipt-only Persistence

LIVE_HASHED receipts must never include:

* raw prompt text
* raw model output text
* reversible encodings of either
* any key material

Receipts may include:

* `response_bytes_sha256` and length
* provider `request_id` (and optionally `request_id_hash`)
* usage fields returned by provider
* timing, http status, deterministic key index metadata

### 4.7 Deterministic Key Routing (Audit-Recomputable)

Key selection must be deterministic, based on:

* model
* sha256(prompt) (in-memory only; prompt itself never persisted)
* optional `KT_NODE_ID`

Formula (conceptual):  
`idx = sha256(model + sha256(prompt) + node_id) % key_count`

Persist:

* `key_index`
* `key_count`

Never persist key or hash of key.

### 4.8 Chain of Custody (Append-only Receipts)

All persisted receipts must include and validate:

* `receipt_id` (hex64)
* `prev_receipt_hash` (hex64 or GENESIS constant)
* `receipt_hash` (hex64)

A receipt without chain fields is not a persisted receipt.

Providers must not compute chain fields. Runner/store computes chain fields.

---

## 5. Receipt Schema and Chain Rules

### 5.1 Two-phase Receipt Lifecycle

**Phase 1: Base receipt (provider responsibility)**

* Produced in-memory only
* Contains provider attestations and hashes
* Contains no chain fields
* Validated via `validate_base(...)`

**Phase 2: Chained receipt (runner/store responsibility)**

* Adds: `receipt_id`, `prev_receipt_hash`, `receipt_hash`
* Validated via full `from_dict(...)`
* Persisted append-only to receipts.jsonl

### 5.2 Required Receipt Contents (Minimum)

Receipt must contain at minimum:

* schema identity and version hash
* trace_id
* provider_id
* lane = LIVE_HASHED
* model
* endpoint
* key_index / key_count
* timing: t_start_ms, t_end_ms, latency_ms
* transport: host, http_status, tls_cert_sha256 (mandatory)
* provider_attestation: request_id or equivalent (hash optional)
* usage: prompt_tokens/completion_tokens/total_tokens if provider supplies
* payload: response_bytes_sha256, response_bytes_len
* verdict: pass boolean and fail_reason on failure
* chain: receipt_id, prev_receipt_hash, receipt_hash (persisted receipts only)

### 5.3 Failure Semantics

If http_status != 200:

* A receipt must still be produced with `pass=false` and `fail_reason`
* The runner must then fail closed (non-zero exit)

---

## 6. Reconciliation Procedure

### 6.1 Purpose

Reconciliation verifies that LIVE_HASHED receipts correspond to provider-reported usage, preventing:

* fabricated usage
* mismatched models
* drift between receipts and provider exports

### 6.2 Inputs

* Receipt file (append-only JSONL)
* Provider export (CSV/JSON), for the relevant time window

### 6.3 Matching Rules (Deterministic)

Match on a scoring basis, prioritizing:

* provider request id (or hashed id)
* model id
* time window overlap
* usage fields (within tolerance)

### 6.4 Output

Deterministic JSON report including:

* pass/fail
* unmatched receipts
* unmatched exports
* mismatched usage
* tolerance configuration

Any failure must exit non-zero.

---

## 7. Thermodynamics Integration (Optional but Recommended)

### 7.1 Purpose

Thermodynamics ledger records the cost debit for a receipt, referencing immutable evidence.

### 7.2 Ledger Entry Requirements

A thermo debit entry must include:

* timestamp
* receipt_hash (reference)
* model
* total_tokens (or provider usage basis)
* lane

### 7.3 Fail-closed Rules

* If receipt_hash is invalid or missing: refuse to debit
* If usage is missing and policy requires it: refuse to debit

---

## 8. Operator Procedures

### 8.1 INTERACTIVE_LIVE Smoke Test (Non-authoritative)

Goal: verify real network + key routing + TLS fingerprint capture (metadata only).

Must produce:

* raw output to stdout
* live_call_meta to stderr
* no artifacts/ledgers

### 8.2 LIVE_HASHED Positive Test (Authoritative)

Goal: produce one chained receipt.

Must produce:

* appended receipt line in receipts.jsonl
* receipt contains tls_cert_sha256 and response_bytes_sha256
* no raw text persisted

### 8.3 Key Validation Sweep (Authoritative)

Goal: verify all configured keys are usable.

Must produce:

* per-key status lines (OK/AUTH_ERROR/etc.)
* no raw content persistence
* may append failure receipts depending on policy (must be explicit)

---

## 9. Acceptance Tests (Must Pass)

### 9.1 DRY_RUN Regression (E2E)

* DRY_RUN E2E script passes
* no LIVE_HASHED receipts created
* no thermo ledger written
* repo remains clean (except append-only artifacts intended by DRY_RUN)

### 9.2 INTERACTIVE_LIVE

* with valid key, returns output
* prints metadata including key_index/key_count
* writes no receipts, no artifacts, no ledgers

### 9.3 LIVE_HASHED

* with valid key, appends exactly one chained receipt
* receipt chain validates
* tls_cert_sha256 present
* response_bytes_sha256 present
* no raw output persisted

### 9.4 Reconciliation

* known-good export matches receipts within tolerance
* mismatches fail closed with deterministic report

---

## 10. Constitutional Amendment: Network Pinhole in Crucibles (Future)

Allowing network inside crucibles/epochs is a separate, explicit amendment requiring:

* formal policy object defining allowlist
* sandbox pinhole limiting to host/port/TLS fingerprint
* crucible-level explicit permission flag
* additional acceptance tests proving:
  * only allowlisted TLS traffic occurs
  * no leakage of raw content
  * receipts and thermo debits remain correct
  * DRY_RUN remains sealed by default

This amendment is **not** authorized by AUDIT_LIVE_HASHED_V1.

---

## 11. Audit Sign-off Checklist (Operator Fill-In)

* Date:
* Repo commit:
* DRY_RUN E2E PASS:
* INTERACTIVE_LIVE PASS:
* LIVE_HASHED PASS:
* Receipt chain validated:
* Reconciliation PASS:
* Thermo debit PASS (if enabled):
* Notes / anomalies:

---

## 12. Appendices

### A. Environment Gates (Summary)

* `KT_PROVIDERS_ENABLED=1`
* `KT_EXECUTION_LANE={INTERACTIVE_LIVE|LIVE_HASHED}`
* Provider secrets in env only
* `.env*` and `*.secret` ignored by git

### B. Evidence Locations (Default)

* Receipts: `tools/growth/artifacts/live_hashed/<provider>/receipts.jsonl`
* Thermo ledger: `tools/growth/ledgers/thermo/ledger.jsonl`
* Reconciliation reports: deterministic JSON output path (operator-chosen)

---

## Next step after C

Once you add this file, the next action is **1 (operator CLI + dashboard)** with the hard rule: **read-only** and **no new authority**.
