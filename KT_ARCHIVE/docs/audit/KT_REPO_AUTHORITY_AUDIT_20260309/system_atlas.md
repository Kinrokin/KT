# System Atlas

## Major Systems

| System | Primary Surfaces | Zone | Role |
| --- | --- | --- | --- |
| canonical runtime | `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/**`, `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/**` | canonical | deterministic runtime kernel |
| governance and law | `KT_PROD_CLEANROOM/governance/**`, `KT_PROD_CLEANROOM/00_README_FIRST/**` | canonical | authority, posture, scope, and boundary contracts |
| operator plane | `KT_PROD_CLEANROOM/tools/operator/**` | canonical | execution, certification, posture derivation, and promotion controls |
| evidence plane | `KT_PROD_CLEANROOM/tools/verification/**`, `KT_PROD_CLEANROOM/reports/**`, `KT_PROD_CLEANROOM/AUDITS/**` | canonical plus generated/runtime truth | test execution and evidence emission |
| delivery/security | `KT_PROD_CLEANROOM/tools/delivery/**`, `KT_PROD_CLEANROOM/tools/security/**`, `ci/**`, `.github/**` | canonical | packaging, redaction, scanning, and release discipline |
| lab/adaptive stack | `KT_PROD_CLEANROOM/03_SYNTHESIS_LAB/**`, `KT_PROD_CLEANROOM/tools/{growth,training,router,merge,tournament,eval,feedback,governance,live,probes,suites,canonicalize}/**`, `KT_PROD_CLEANROOM/policy_c/**` | lab | experimental growth, routing, training, and adaptive work |
| commercial/docs | `KT-Codex/**`, `docs/**`, `KT_PROD_CLEANROOM/docs/commercial/**` | commercial | explanation, packaging, and outward narrative |
| archive lineage | `KT_TEMPLE_ROOT/**`, `KT_LANE_LORA_PHASE_B/**`, `KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**`, root operation artifacts | archive | sealed lineage and historical work |
| quarantined surfaces | `KT_PROD_CLEANROOM/05_QUARANTINE/**`, `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**`, `KT_PROD_CLEANROOM/AUDIT_LIVE_HASHED_V1.md` | quarantined | surfaces that must not re-enter canonical truth |

## Entrypoints

- runtime entrypoint: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py`
- canonical spine: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py`
- runtime registry: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json`
- operator front door: `KT_PROD_CLEANROOM/tools/operator/kt_cli.py`
- truth derivation: `KT_PROD_CLEANROOM/tools/operator/run_truth_matrix.py` then `KT_PROD_CLEANROOM/tools/operator/truth_engine.py`
- receipt resync: `KT_PROD_CLEANROOM/tools/operator/truth_surface_sync.py`
- delivery pack generation: `KT_PROD_CLEANROOM/tools/delivery/generate_delivery_pack.py`

## Runtime Flows

1. `kt.entrypoint.invoke` loads the runtime registry, installs import truth guards, asserts invariants, and hands off to `core.spine.run`.
2. `core.spine.run` dispatches the canonical organs: cognition, council, curriculum, governance, multiverse, paradox, temporal, thermodynamics, and ledger surfaces.
3. state and governance artifacts are emitted through runtime artifact paths and tracked evidence surfaces.
4. runtime import roots are bounded by `governance/runtime_boundary_contract.json` and the registry import matrix.

## Operator Flows

1. `kt_cli.py` exposes `status`, `certify`, `safe-run`, `red-assault`, `continuous-gov`, `overlay-apply`, `forge`, `report`, and demo lanes.
2. operator lanes emit WORM receipts under `KT_PROD_CLEANROOM/exports/_runs/KT_OPERATOR/**`.
3. operator truth is supposed to be summarized into tracked receipts only after live validation is current for the pinned head.

## Evidence Flows

1. tests and verification scripts execute suites against canonical and selected lab surfaces.
2. `run_truth_matrix.py` writes `live_validation_index.json` style evidence.
3. `truth_engine.py` derives posture from live evidence plus tracked receipts and the posture contract.
4. `truth_surface_sync.py` is the bridge that should re-ratify tracked truth surfaces from current evidence.

## Delivery Flows

1. canonical operator lanes produce receipts and manifests.
2. delivery tooling assembles bundles, hashes, manifests, redaction outputs, and replay materials.
3. secret-scan and delivery-contract validation guard client-facing outputs.

## Trust Flows

1. authority starts from tier locators and authority bundles under `KT_PROD_CLEANROOM/governance/**`.
2. runtime scope is bounded by `canonical_scope_manifest.json` and `runtime_boundary_contract.json`.
3. posture is derived through `truth_engine_contract.json` and `posture_contract.json`.
4. current tracked trust-zone modeling is incomplete because it omits explicit generated/runtime truth and explicit quarantine.

## Promotion Flows

1. lab surfaces can generate evidence and tooling but are not promotion-authoritative.
2. generated/runtime truth can describe posture only when its `validated_head_sha` matches the pinned head.
3. canonical promotion should be clean-clone and clean-worktree anchored before any green claim is re-earned.
4. archive and quarantined surfaces must never become upstream truth inputs again.

## Dependencies And Import Boundaries

- canonical runtime roots: `cognition`, `core`, `council`, `curriculum`, `governance`, `kt`, `memory`, `multiverse`, `paradox`, `schemas`, `temporal`, `thermodynamics`, `versioning`
- compatibility allowlist root: `tools`
- canonical runtime exclusion: `KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/tools/**`
- negative-space exception: repo-level `KT_PROD_CLEANROOM/tools/**` imports are not runtime namespace violations

## Truth Authorities

- tier 0 immutables: authority bundles, WORM write surface, redaction rules
- tier 1 law: `governance/program_catalog.json`, `ci/gates/p0_gate_definitions.json`
- tier 2 statute: `governance/sku_registry.json`, `tools/operator/delta_proof.py`, `tools/operator/serious_layer/continuous_gov_serious_v1.py`
- tier 3 admin policy: selected operator docs under `KT_PROD_CLEANROOM/docs/operator/**`
- derived truth: the posture and runtime receipts under `KT_PROD_CLEANROOM/reports/**`

## Stale Surfaces

- four tracked truth receipts are stale against `HEAD`
- `governance/execution_board.json` still points at `4cf1b9d100f8699fa192d6a5409c69bc6e94761d`
- `readiness_scope_manifest.json` still models readiness without separate generated or quarantined zones

## Contradiction Surfaces

- git reports no tracked edits, but the checkout contains large ignored runtime residue and `.env.secret`
- the tracked truth surfaces claim a dirtier and older posture than the fresh head validation
- the tracked trust-zone validator passes because it validates the older four-zone model, not the stronger six-zone split required by this audit
- `KT_PROD_CLEANROOM/tools/operator/truth_engine.py` still forces `live_validation_index_path.relative_to(root)`, which breaks the claimed support for truth inputs outside tracked reports
