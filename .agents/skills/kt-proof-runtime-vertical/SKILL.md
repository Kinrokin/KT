---
name: kt-proof-runtime-vertical
description: Prove one bounded KT runtime path is actually called, gated, evidenced, consumed, and rollback-able. Use for PR-B-style work where code existence must become proof-carrying runtime integration.
---

# KT Proof Runtime Vertical

## Purpose

Stop fake integration. This skill proves a component is not merely present in the repository, but actually participates in a bounded runtime invocation.

It is the controlling skill for PR-B-style work:

```text
KT_CORE_LIVEWIRE_V2_2_PR_B_PROOF_CARRYING_RUNTIME_VERTICAL
```

## Core question

```text
Can one real runtime path carry its own proof from entry point to output, gate, consumer, claim posture, and rollback?
```

## Non-negotiable rule

```text
No component is runtime-integrated until one real invocation proves caller, configuration, gate, output, consumer, proof, measured effect, and rollback.
```

## Failure classes blocked

```text
component exists but is never called
test exists but runtime does not invoke it
receipt exists but was generated post hoc
schema exists but no proof object is emitted
gate exists but is optional or bypassable
output exists but no consumer acknowledgement exists
claim posture is written by narrative instead of derived from proof
rollback path is documented but not executable
coverage reports 1.0 with zero denominators
mutation tests declare PASS without execution evidence
```

## Required bounded scope

The skill must select one smallest canonical runtime path. It must not claim global KT runtime coverage.

Required scoping fields:

```text
vertical_id:
entry_point:
invocation_command:
input_fixture:
component_under_test:
mandatory_gates:
consumer:
claim_surface:
rollback_or_disable_surface:
out_of_scope:
```

## Mandatory proof chain

A passing vertical must include:

```text
INPUT_ACCEPTED
COMPONENT_INVOKED
CONFIGURATION_BOUND
GATE_APPLICABILITY_EVALUATED
GATE_DECISION_RECORDED
FALLBACK_DECISION_RECORDED
OUTPUT_PRESERVED
OUTPUT_DELIVERED
CONSUMER_ACKNOWLEDGED
EFFECT_MEASURED
CLAIM_POSTURE_DERIVED
ROLLBACK_OR_DISABLE_TESTED
EXECUTION_CLOSED
```

Each event must bind:

```text
sequence
monotonic timestamp or deterministic sequence counter
payload SHA
previous event SHA
event SHA
evidence reference
repo head
```

## Required coverage metrics

These must pass with nonzero denominators:

```text
static_gate_reachability_coverage = 1.0
dynamic_gate_invocation_coverage = 1.0
mutation_gate_kill_rate = 1.0

mandatory_gate_count > 0
static_path_count > 0
dynamic_invocation_count > 0
mutation_count > 0
unknown_execution_path_count = 0
unclassified_applicability_count = 0
unauthorized_bypass_count = 0
```

If any denominator is zero, the vertical is blocked.

## Required artifacts

```text
RUNTIME_VERTICAL_MANIFEST.json
PROOF_OBJECT.schema.json
PROOF_OBJECT.json
EVENT_CHAIN.jsonl
CALLER_CHAIN_RECEIPT.json
CONFIGURATION_BINDING_RECEIPT.json
GATE_COVERAGE_RECEIPT.json
MUTATION_KILL_RECEIPT.json
OUTPUT_CONSUMER_RECEIPT.json
ROLLBACK_DISABLE_RECEIPT.json
CLAIM_PROJECTION_FROM_PROOF.json
VALIDATION_RECEIPT.json
RETURN_CONTRACT.md
```

## Proof object minimum schema

A proof object must bind:

```text
schema_id
vertical_id
repo_head
entry_point
invocation_command_hash
input_hash
component_identity
configuration_hash
gate_decisions
output_hash
consumer_ack_hash
event_chain_root
mutation_receipt_hash
rollback_receipt_hash
claim_projection_hash
claim_ceiling_status
```

## Mutation requirements

The vertical must include fail-closed mutations for:

```text
missing gate event
wrong gate decision
missing consumer acknowledgement
broken event-chain hash
modified output after proof
zero coverage denominator
unauthorized bypass
rollback path missing
claim projection with forbidden claim
```

Every mutation record must include:

```text
mutation_id
fixture_hash
command_id
expected_blocker
observed_blocker
exit_status
stdout_hash
stderr_hash
implementation_hash
execution_timestamp_or_sequence
```

## Claim boundary

Allowed:

```text
one bounded proof-carrying runtime vertical passed
internal evidence workflow improved
component invocation and gate path proven for the scoped vertical
```

Forbidden:

```text
global runtime coverage
production authority
commercial authorization
certification
7B proof
S-tier / beyond-SOTA
selector deployment
training success
PR C lobe claims
```

## Output format

Return:

```text
VERTICAL_ID:
ENTRY_POINT:
COMPONENT_UNDER_TEST:
GATES:
CONSUMER:
PROOF_OBJECT_STATUS:
EVENT_CHAIN_STATUS:
STATIC_GATE_REACHABILITY_COVERAGE:
DYNAMIC_GATE_INVOCATION_COVERAGE:
MUTATION_GATE_KILL_RATE:
UNKNOWN_EXECUTION_PATH_COUNT:
UNCLASSIFIED_APPLICABILITY_COUNT:
UNAUTHORIZED_BYPASS_COUNT:
ROLLBACK_DISABLE_STATUS:
CLAIM_PROJECTION_STATUS:
CLAIM_CEILING_STATUS:
GO_OR_BLOCK:
NEXT_LAWFUL_MOVE:
```

## End condition

The skill ends when either:

```text
PASS_ONE_BOUNDED_PROOF_CARRYING_RUNTIME_VERTICAL
```

or a named blocker is produced:

```text
BLOCK_NO_CANONICAL_ENTRY_POINT
BLOCK_GATE_DENOMINATOR_ZERO
BLOCK_COMPONENT_NOT_CALLED
BLOCK_CONSUMER_NOT_PROVEN
BLOCK_MUTATION_SURVIVED
BLOCK_ROLLBACK_NOT_PROVEN
BLOCK_CLAIM_PROJECTION_UNSAFE
```
