from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

from tools.operator.titanium_common import load_json, utc_now_iso_z


TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
BENCHMARK_CONSTITUTION_REL = "KT_PROD_CLEANROOM/governance/kt_benchmark_constitution_v1.json"
COMPARATOR_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/kt_comparator_registry.json"
CAPABILITY_ATLAS_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/capability_atlas_contract.json"
ECONOMIC_TRUTH_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/economic_truth_plane_contract.json"
ORGAN_REGISTER_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_organ_disposition_register.json"
USEFUL_OUTPUT_BENCHMARK_REL = "KT_PROD_CLEANROOM/reports/useful_output_benchmark.json"
UNIVERSAL_ADAPTER_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/universal_adapter_receipt.json"
CIVILIZATION_LOOP_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/civilization_loop_receipt.json"
LEARNING_RESPONSE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/learning_response_receipt.json"
ROLLBACK_DRILL_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/rollback_drill_receipt.json"
E2_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/e2_cross_host_replay_receipt.json"
DETACHED_VERIFIER_TRUTH_REL = "KT_PROD_CLEANROOM/reports/kt_wave5_verifier_truth_surface.json"
PROVIDER_PATH_INTEGRITY_REL = "KT_PROD_CLEANROOM/reports/provider_path_integrity_receipt.json"
ROUTER_RATIFICATION_REL = "KT_PROD_CLEANROOM/reports/post_wave5_c005_router_ratification_receipt.json"
ROUTER_ORDERED_PROOF_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/router_ordered_proof_receipt.json"
ROUTER_SUPERIORITY_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"
COGNITIVE_PACK_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_cognitive_provenance_pack.json"
PARADOX_PACK_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_paradox_engine_pack.json"
TEMPORAL_PACK_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_temporal_engine_pack.json"
MULTIVERSE_PACK_REL = "KT_PROD_CLEANROOM/reports/kt_wave2c_multiverse_engine_pack.json"
MVCR_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/mvcr_live_execution_receipt.json"
NEGATIVE_LEDGER_REL = "KT_PROD_CLEANROOM/reports/benchmark_negative_result_ledger.json"
DEPLOYMENT_PROFILES_REL = "KT_PROD_CLEANROOM/reports/deployment_profiles.json"
ECONOMIC_TRUTH_PLANE_REL = "KT_PROD_CLEANROOM/reports/economic_truth_plane.json"
EXTERNAL_CHALLENGE_PROTOCOL_REL = "KT_PROD_CLEANROOM/reports/kt_external_challenge_protocol.json"

ACTUAL_CATEGORY = "GOVERNED_RECEIPT_BACKED_FAIL_CLOSED_AI_EXECUTION_WITH_ADAPTIVE_IMPROVEMENT_UNDER_LAW"
CANONICAL_RUNTIME_ECONOMIC_PROFILE = "canonical_same_host_runtime_lane"
VERIFIER_WEDGE_ECONOMIC_PROFILE = "bounded_verifier_handoff_lane"
MUTATION_ECONOMIC_PROFILE = "bounded_mutation_civilization_lane"
EXTERNALITY_ECONOMIC_PROFILE = "c006_cross_host_reentry_lane"


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status_is(value: Any, expected: str) -> bool:
    return str(value).strip().upper() == expected.strip().upper()


def _load(root: Path, rel: str) -> Dict[str, Any]:
    return load_json(root / rel)


def benchmark_required_fields() -> tuple[str, ...]:
    return (
        "dataset_registry",
        "holdout_policy",
        "comparator_policy",
        "contamination_policy",
        "cost_accounting_rule",
        "latency_accounting_rule",
        "failure_row_retention_rule",
        "replayability_coverage_rule",
        "adversarial_probe_coverage_rule",
    )


def _truth_lock(root: Path) -> Dict[str, Any]:
    return _load(root, TRUTH_LOCK_REL)


def _default_e2_receipt(root: Path) -> Dict[str, Any]:
    return _load(root, E2_RECEIPT_REL)


def _surface_bindings() -> Dict[str, Dict[str, str]]:
    return {
        "router": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/router_policy_registry.json",
            "challenge_pack_ref": ROUTER_ORDERED_PROOF_RECEIPT_REL,
            "benchmark_pack_ref": ROUTER_SUPERIORITY_SCORECARD_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "council": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_registry.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "challenge_pack_ref": PROVIDER_PATH_INTEGRITY_REL,
            "benchmark_pack_ref": USEFUL_OUTPUT_BENCHMARK_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "cognition": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "challenge_pack_ref": COGNITIVE_PACK_REL,
            "benchmark_pack_ref": USEFUL_OUTPUT_BENCHMARK_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "paradox": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/kt_claim_proof_ceiling_compiler_policy_v2.json",
            "challenge_pack_ref": PARADOX_PACK_REL,
            "benchmark_pack_ref": MVCR_RECEIPT_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "temporal": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "challenge_pack_ref": TEMPORAL_PACK_REL,
            "benchmark_pack_ref": MVCR_RECEIPT_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "multiverse": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "challenge_pack_ref": MULTIVERSE_PACK_REL,
            "benchmark_pack_ref": MVCR_RECEIPT_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "memory": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/truth_engine_contract.json",
            "challenge_pack_ref": MVCR_RECEIPT_REL,
            "benchmark_pack_ref": USEFUL_OUTPUT_BENCHMARK_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "adapter_layer": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/adapter_abi_runtime.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/kt_adapter_abi_v2.json",
            "challenge_pack_ref": UNIVERSAL_ADAPTER_RECEIPT_REL,
            "benchmark_pack_ref": UNIVERSAL_ADAPTER_RECEIPT_REL,
            "economic_profile_id": MUTATION_ECONOMIC_PROFILE,
        },
        "tournament_promotion": {
            "execution_path_ref": "KT_PROD_CLEANROOM/tools/training/fl3_factory/run_job.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/civilization_loop_contract.json",
            "challenge_pack_ref": CIVILIZATION_LOOP_RECEIPT_REL,
            "benchmark_pack_ref": LEARNING_RESPONSE_RECEIPT_REL,
            "economic_profile_id": MUTATION_ECONOMIC_PROFILE,
        },
        "teacher_growth_surfaces": {
            "execution_path_ref": "KT_PROD_CLEANROOM/tools/growth/crucibles/CRUCIBLE_REGISTRY.yaml",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/promotion_engine_law.json",
            "challenge_pack_ref": NEGATIVE_LEDGER_REL,
            "benchmark_pack_ref": NEGATIVE_LEDGER_REL,
            "economic_profile_id": MUTATION_ECONOMIC_PROFILE,
        },
        "toolchain_only_orchestrators": {
            "execution_path_ref": "KT_PROD_CLEANROOM/tools/operator/omega_gate.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/tools_runtime_boundary_rule.json",
            "challenge_pack_ref": "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json",
            "benchmark_pack_ref": NEGATIVE_LEDGER_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "detached_verifier": {
            "execution_path_ref": "KT_PROD_CLEANROOM/tools/operator/public_verifier.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/kt_externality_class_matrix_v1.json",
            "challenge_pack_ref": DETACHED_VERIFIER_TRUTH_REL,
            "benchmark_pack_ref": E2_RECEIPT_REL,
            "economic_profile_id": VERIFIER_WEDGE_ECONOMIC_PROFILE,
        },
        "claim_compiler": {
            "execution_path_ref": "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/claim_compiler.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/kt_claim_proof_ceiling_compiler_policy_v2.json",
            "challenge_pack_ref": MVCR_RECEIPT_REL,
            "benchmark_pack_ref": USEFUL_OUTPUT_BENCHMARK_REL,
            "economic_profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
        },
        "detached_verifier_externality_lane": {
            "execution_path_ref": "KT_PROD_CLEANROOM/tools/operator/post_wave5_c006_second_host_execute_validate.py",
            "governing_law_ref": "KT_PROD_CLEANROOM/governance/kt_externality_class_matrix_v1.json",
            "challenge_pack_ref": E2_RECEIPT_REL,
            "benchmark_pack_ref": NEGATIVE_LEDGER_REL,
            "economic_profile_id": EXTERNALITY_ECONOMIC_PROFILE,
        },
    }


def _surface_profiles() -> Dict[str, Dict[str, str]]:
    return {
        "router": {
            "allowed_claim_class": "STATIC_CANONICAL_BASELINE_ONLY",
            "claim_ceiling": "STATIC_CANONICAL_BASELINE_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": ROUTER_RATIFICATION_REL,
            "validator": "python -m tools.operator.post_wave5_c005_router_ratification_validate",
            "zone": "CANONICAL",
        },
        "council": {
            "allowed_claim_class": "CANONICAL_SAME_HOST_LIVE_HASHED_AND_BOUNDED_DRY_RUN_ONLY",
            "claim_ceiling": "CANONICAL_SAME_HOST_LIVE_HASHED_AND_BOUNDED_DRY_RUN_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": PROVIDER_PATH_INTEGRITY_REL,
            "validator": "python -m tools.operator.w1_runtime_realization_validate",
            "zone": "CANONICAL",
        },
        "cognition": {
            "allowed_claim_class": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": MVCR_RECEIPT_REL,
            "validator": "python -m tools.operator.runtime_organ_realization_validate",
            "zone": "CANONICAL",
        },
        "paradox": {
            "allowed_claim_class": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": PARADOX_PACK_REL,
            "validator": "python -m tools.operator.runtime_organ_realization_validate",
            "zone": "CANONICAL",
        },
        "temporal": {
            "allowed_claim_class": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": TEMPORAL_PACK_REL,
            "validator": "python -m tools.operator.runtime_organ_realization_validate",
            "zone": "CANONICAL",
        },
        "multiverse": {
            "allowed_claim_class": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": MULTIVERSE_PACK_REL,
            "validator": "python -m tools.operator.runtime_organ_realization_validate",
            "zone": "CANONICAL",
        },
        "memory": {
            "allowed_claim_class": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": MVCR_RECEIPT_REL,
            "validator": "python -m tools.operator.w1_runtime_realization_validate",
            "zone": "CANONICAL",
        },
        "adapter_layer": {
            "allowed_claim_class": "CURRENT_HEAD_BOUNDED_UNIVERSAL_ADAPTER_CONTRACT_ONLY",
            "claim_ceiling": "CURRENT_HEAD_BOUNDED_UNIVERSAL_ADAPTER_CONTRACT_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": UNIVERSAL_ADAPTER_RECEIPT_REL,
            "validator": "python -m tools.operator.universal_adapter_validate",
            "zone": "CANONICAL",
        },
        "tournament_promotion": {
            "allowed_claim_class": "CURRENT_HEAD_BOUNDED_INTERNAL_CIVILIZATION_LOOP_ONLY",
            "claim_ceiling": "CURRENT_HEAD_BOUNDED_INTERNAL_CIVILIZATION_LOOP_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "LIVE_BOUNDED",
            "receipt": CIVILIZATION_LOOP_RECEIPT_REL,
            "validator": "python -m tools.operator.civilization_loop_validate",
            "zone": "CANONICAL",
        },
        "teacher_growth_surfaces": {
            "allowed_claim_class": "LAB_GOVERNED_ONLY",
            "claim_ceiling": "LAB_GOVERNED_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "QUARANTINED",
            "reality_class": "SCAFFOLDED",
            "receipt": "KT_PROD_CLEANROOM/reports/kt_wave0_quarantine_receipts.json",
            "validator": "python -m tools.operator.w1_runtime_realization_validate",
            "zone": "LAB",
        },
        "toolchain_only_orchestrators": {
            "allowed_claim_class": "TOOLCHAIN_PROVING_ONLY",
            "claim_ceiling": "TOOLCHAIN_PROVING_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "QUARANTINED",
            "reality_class": "TOOLCHAIN_PROVING",
            "receipt": "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json",
            "validator": "python -m tools.operator.omega_gate",
            "zone": "TOOLCHAIN_PROVING",
        },
        "detached_verifier": {
            "allowed_claim_class": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED",
            "claim_ceiling": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED",
            "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "CURRENT_HEAD_PROVEN",
            "receipt": DETACHED_VERIFIER_TRUTH_REL,
            "validator": "python -m tools.operator.post_wave5_c006_second_host_execute_validate",
            "zone": "CANONICAL",
        },
        "claim_compiler": {
            "allowed_claim_class": "BOUNDED_RUNTIME_VOCABULARY_GATE_ONLY",
            "claim_ceiling": "BOUNDED_RUNTIME_VOCABULARY_GATE_ONLY",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": "CURRENT_HEAD_PROVEN",
            "receipt": MVCR_RECEIPT_REL,
            "validator": "python -m tools.operator.w1_runtime_realization_validate",
            "zone": "CANONICAL",
        },
    }


def _organ_rows_by_id(root: Path) -> Dict[str, Dict[str, Any]]:
    register = _load(root, ORGAN_REGISTER_REL)
    rows = register.get("rows", [])
    indexed: Dict[str, Dict[str, Any]] = {}
    if not isinstance(rows, list):
        return indexed
    for row in rows:
        if not isinstance(row, dict):
            continue
        organ_id = str(row.get("organ_id", "")).strip()
        if organ_id:
            indexed[organ_id] = row
    return indexed


def build_benchmark_negative_result_ledger(*, root: Path) -> Dict[str, Any]:
    truth_lock = _truth_lock(root)
    e2_receipt = _default_e2_receipt(root)
    return {
        "schema_id": "kt.benchmark_negative_result_ledger.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS",
        "actual_category": ACTUAL_CATEGORY,
        "rows": [
            {
                "row_id": "cross_host_replay_current_head",
                "reason": "C006 remains open until a fresh admissible second-host return is imported and passes.",
                "source_ref": E2_RECEIPT_REL,
                "status": str(e2_receipt.get("e2_outcome", "NOT_EARNED")).strip() or "NOT_EARNED",
                "surface_id": "detached_verifier_externality_lane",
            },
            {
                "row_id": "comparative_widening_current_head",
                "reason": "Comparative widening remains forbidden while externality is capped at E1 and no category-leading benchmark wins exist.",
                "source_ref": TRUTH_LOCK_REL,
                "status": "BLOCKED_PENDING_C006_AND_CATEGORY_WINS",
                "surface_id": "claim_compiler",
            },
            {
                "row_id": "router_superiority_current_head",
                "reason": "Static router hold remains canonical until shadow eval, best-static comparison, and superiority proof pass.",
                "source_ref": ROUTER_RATIFICATION_REL,
                "status": "BLOCKED_PENDING_ORDERED_PROOF_CHAIN",
                "surface_id": "router",
            },
            {
                "row_id": "multi_lobe_execution_current_head",
                "reason": "No live multi-lobe execution receipt exists on current head.",
                "source_ref": ROUTER_RATIFICATION_REL,
                "status": "NOT_EARNED",
                "surface_id": "router",
            },
            {
                "row_id": "runtime_cutover_from_generated_candidate",
                "reason": "W3 proved bounded internal civilization only; generated candidates may not silently cut over active runtime.",
                "source_ref": CIVILIZATION_LOOP_RECEIPT_REL,
                "status": "FORBIDDEN_PENDING_SEPARATE_GATE",
                "surface_id": "tournament_promotion",
            },
            {
                "row_id": "hostile_replay_current_head",
                "reason": "No independent hostile replay receipt exists.",
                "source_ref": E2_RECEIPT_REL,
                "status": "NOT_EARNED",
                "surface_id": "detached_verifier_externality_lane",
            },
            {
                "row_id": "enterprise_product_claims",
                "reason": "Commercial widening remains forbidden above the bounded trust wedge.",
                "source_ref": TRUTH_LOCK_REL,
                "status": str(truth_lock.get("claim_ceiling_enforcements", {}).get("commercial_widening", "FORBIDDEN")).strip() or "FORBIDDEN",
                "surface_id": "detached_verifier",
            },
        ],
        "claim_boundary": (
            "This ledger preserves blocked, failed, or not-yet-earned rows that must remain visible while current head is bounded. "
            "It is negative evidence, not a superiority scorecard."
        ),
        "source_refs": [
            TRUTH_LOCK_REL,
            E2_RECEIPT_REL,
            ROUTER_RATIFICATION_REL,
            CIVILIZATION_LOOP_RECEIPT_REL,
        ],
    }


def build_capability_atlas(*, root: Path, e2_receipt: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    contract = _load(root, CAPABILITY_ATLAS_CONTRACT_REL)
    truth_lock = _truth_lock(root)
    bindings = _surface_bindings()
    profiles = _surface_profiles()
    organ_rows = _organ_rows_by_id(root)
    active_e2 = dict(e2_receipt) if e2_receipt is not None else _default_e2_receipt(root)
    comparative_status = "BLOCKED_PENDING_C006_E2_AND_FROZEN_BENCHMARK_WINS"

    topology: list[Dict[str, Any]] = []
    for surface_id, binding in bindings.items():
        if surface_id == "detached_verifier_externality_lane":
            continue
        profile = profiles.get(surface_id)
        if profile is None:
            continue
        row = organ_rows.get(surface_id, {})
        topology.append(
            {
                "actual_category": ACTUAL_CATEGORY,
                "allowed_claim_class": profile["allowed_claim_class"],
                "benchmark_pack_ref": binding["benchmark_pack_ref"],
                "challenge_pack_ref": binding["challenge_pack_ref"],
                "claim_ceiling": profile["claim_ceiling"],
                "comparative_widening_status": comparative_status,
                "economic_profile_id": binding["economic_profile_id"],
                "execution_path_ref": binding["execution_path_ref"],
                "externality_class": str(row.get("externality_class", profile["externality_class"])).strip() or profile["externality_class"],
                "governing_law_ref": binding["governing_law_ref"],
                "plane": profile["plane"],
                "reality_class": str(row.get("reality_class", profile["reality_class"])).strip() or profile["reality_class"],
                "receipt": profile["receipt"],
                "surface_id": surface_id,
                "validator": profile["validator"],
                "zone": profile["zone"],
            }
        )

    externality_binding = bindings["detached_verifier_externality_lane"]
    topology.append(
        {
            "actual_category": ACTUAL_CATEGORY,
            "allowed_claim_class": "DETACHED_VERIFIER_EXTERNALITY_TYPED_ONLY",
            "benchmark_pack_ref": externality_binding["benchmark_pack_ref"],
            "challenge_pack_ref": externality_binding["challenge_pack_ref"],
            "claim_ceiling": "DETACHED_VERIFIER_EXTERNALITY_TYPED_ONLY",
            "comparative_widening_status": comparative_status,
            "economic_profile_id": externality_binding["economic_profile_id"],
            "execution_path_ref": externality_binding["execution_path_ref"],
            "externality_class": str(active_e2.get("current_externality_class", "")).strip() or "E1_SAME_HOST_DETACHED_REPLAY",
            "governing_law_ref": externality_binding["governing_law_ref"],
            "plane": "GENERATED_RUNTIME_TRUTH",
            "reality_class": str(active_e2.get("current_externality_class", "")).strip() or "E1_SAME_HOST_DETACHED_REPLAY",
            "receipt": E2_RECEIPT_REL,
            "surface_id": "detached_verifier_externality_lane",
            "validator": "python -m tools.operator.w3_externality_and_comparative_proof_validate",
            "zone": "CANONICAL",
        }
    )

    status = (
        "PASS"
        if _status_is(contract.get("status"), "ACTIVE")
        and truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening") == "FORBIDDEN"
        and bool(topology)
        else "FAIL"
    )
    return {
        "schema_id": "kt.capability_atlas.v1",
        "status": status,
        "topology": topology,
        "evidence_refs": [
            CAPABILITY_ATLAS_CONTRACT_REL,
            ORGAN_REGISTER_REL,
            BENCHMARK_CONSTITUTION_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
            E2_RECEIPT_REL,
        ],
    }


def build_economic_truth_plane(*, root: Path, atlas: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    truth_lock = _truth_lock(root)
    contract = _load(root, ECONOMIC_TRUTH_CONTRACT_REL)
    deployment_profiles = _load(root, DEPLOYMENT_PROFILES_REL)
    active_atlas = dict(atlas) if atlas is not None else _load(root, "KT_PROD_CLEANROOM/reports/capability_atlas.json")
    atlas_surface_ids = [str(row.get("surface_id", "")).strip() for row in active_atlas.get("topology", []) if isinstance(row, dict)]

    profiles = [
        {
            "applies_to_surface_ids": [surface for surface in atlas_surface_ids if surface in {"router", "council", "cognition", "paradox", "temporal", "multiverse", "memory", "claim_compiler", "toolchain_only_orchestrators"}],
            "claim_boundary": "This lane is economically acceptable only while claims remain bounded at same-host canonical runtime reality.",
            "compute_cost_units": 3,
            "escalation_triggers": [
                "provider_path_ambiguity",
                "runtime_claim_boundary_conflict",
                "unexpected_fail_closed_transition",
            ],
            "fallback_action": "hold_same_host_runtime_lane_and_narrow_claims",
            "profile_id": CANONICAL_RUNTIME_ECONOMIC_PROFILE,
            "remediation_burden_minutes": 30,
            "review_burden_minutes": 10,
            "route_mode": "CANONICAL_SAME_HOST_RUNTIME",
            "source_refs": [
                ECONOMIC_TRUTH_CONTRACT_REL,
                DEPLOYMENT_PROFILES_REL,
                TRUTH_LOCK_REL,
            ],
            "supportability_class": "BOUNDED_OPERATOR_MANAGED",
            "uncertainty_cost_index": 8,
        },
        {
            "applies_to_surface_ids": [surface for surface in atlas_surface_ids if surface in {"detached_verifier"}],
            "claim_boundary": "Verifier economics are favorable only for the bounded E1 trust wedge and do not justify commercial widening.",
            "compute_cost_units": 2,
            "escalation_triggers": [
                "verifier_manifest_drift",
                "buyer_requests_cross_host_claims",
            ],
            "fallback_action": "retain_e1_trust_wedge_only",
            "profile_id": VERIFIER_WEDGE_ECONOMIC_PROFILE,
            "remediation_burden_minutes": 20,
            "review_burden_minutes": 15,
            "route_mode": "BOUNDED_VERIFIER_HANDOFF",
            "source_refs": [
                ECONOMIC_TRUTH_CONTRACT_REL,
                DEPLOYMENT_PROFILES_REL,
                E2_RECEIPT_REL,
            ],
            "supportability_class": "BUYER_SAFE_E1_WEDGE",
            "uncertainty_cost_index": 6,
        },
        {
            "applies_to_surface_ids": [surface for surface in atlas_surface_ids if surface in {"adapter_layer", "tournament_promotion", "teacher_growth_surfaces"}],
            "claim_boundary": "Mutation economics are acceptable only for bounded internal improvement; they do not justify live runtime cutover or product widening.",
            "compute_cost_units": 6,
            "escalation_triggers": [
                "generated_candidate_requests_cutover",
                "promotion_decision_conflicts_with_rollback_law",
                "learning_response_shows_regression",
            ],
            "fallback_action": "reject_or_rollback_mutation_and_preserve_active_runtime",
            "profile_id": MUTATION_ECONOMIC_PROFILE,
            "remediation_burden_minutes": 60,
            "review_burden_minutes": 35,
            "route_mode": "INTERNAL_CIVILIZATION_MUTATION",
            "source_refs": [
                ECONOMIC_TRUTH_CONTRACT_REL,
                CIVILIZATION_LOOP_RECEIPT_REL,
                ROLLBACK_DRILL_RECEIPT_REL,
                LEARNING_RESPONSE_RECEIPT_REL,
            ],
            "supportability_class": "INTERNAL_RESEARCH_ONLY",
            "uncertainty_cost_index": 9,
        },
        {
            "applies_to_surface_ids": [surface for surface in atlas_surface_ids if surface in {"detached_verifier_externality_lane"}],
            "claim_boundary": "Externality economics become acceptable only after fresh second-host proof; until then the cost of uncertainty is maximal.",
            "compute_cost_units": 4,
            "escalation_triggers": [
                "second_host_hardware_missing",
                "return_file_mismatch",
                "cross_host_replay_fails",
            ],
            "fallback_action": "keep_C006_deferred_visible_and_hold_claims_at_E1",
            "profile_id": EXTERNALITY_ECONOMIC_PROFILE,
            "remediation_burden_minutes": 90,
            "review_burden_minutes": 45,
            "route_mode": "SECOND_HOST_REENTRY_AND_EXTERNALITY",
            "source_refs": [
                ECONOMIC_TRUTH_CONTRACT_REL,
                TRUTH_LOCK_REL,
                E2_RECEIPT_REL,
            ],
            "supportability_class": "HARDWARE_BLOCKED_REENTRY",
            "uncertainty_cost_index": 10,
        },
    ]

    status = (
        "PASS"
        if _status_is(contract.get("status"), "ACTIVE")
        and _status_is(deployment_profiles.get("status"), "ACTIVE")
        and truth_lock.get("claim_ceiling_enforcements", {}).get("externality_class_max") == "E1_SAME_HOST_DETACHED_REPLAY"
        and bool(profiles)
        else "FAIL"
    )
    return {
        "schema_id": "kt.economic_truth_plane.v1",
        "status": status,
        "profiles": profiles,
    }


def build_competitive_scorecard(*, root: Path, e2_receipt: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    constitution = _load(root, BENCHMARK_CONSTITUTION_REL)
    comparator_registry = _load(root, COMPARATOR_REGISTRY_REL)
    truth_lock = _truth_lock(root)
    useful_output_benchmark = _load(root, USEFUL_OUTPUT_BENCHMARK_REL)
    challenge_protocol = _load(root, EXTERNAL_CHALLENGE_PROTOCOL_REL)
    active_e2 = dict(e2_receipt) if e2_receipt is not None else _default_e2_receipt(root)
    negative_ledger = build_benchmark_negative_result_ledger(root=root)
    economic_truth_plane_status = "PENDING_W4"
    if (root / ECONOMIC_TRUTH_PLANE_REL).exists():
        economic_truth_plane_status = str(_load(root, ECONOMIC_TRUTH_PLANE_REL).get("status", "")).strip() or "PENDING_W4"

    return {
        "schema_id": "kt.w3.competitive_scorecard.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": "PASS",
        "actual_category": ACTUAL_CATEGORY,
        "comparative_widening_status": "BLOCKED_PENDING_C006_AND_E2",
        "comparative_widening_unlock": False,
        "benchmark_constitution_status": str(constitution.get("status", "")).strip(),
        "comparator_registry_status": str(comparator_registry.get("status", "")).strip(),
        "comparative_widening_enforcement": str(truth_lock.get("claim_ceiling_enforcements", {}).get("comparative_widening", "")).strip(),
        "economic_truth_plane_status": economic_truth_plane_status,
        "public_challenge_protocol_ref": EXTERNAL_CHALLENGE_PROTOCOL_REL,
        "public_challenge_protocol_status": str(challenge_protocol.get("challenge_window_status", "")).strip() or str(challenge_protocol.get("status", "")).strip(),
        "e2_outcome": str(active_e2.get("e2_outcome", "")).strip(),
        "positive_benchmark_row_count": sum(1 for row in useful_output_benchmark.get("rows", []) if isinstance(row, dict) and bool(row.get("pass"))),
        "negative_benchmark_row_count": len(list(negative_ledger.get("rows", []))),
        "negative_result_ledger_ref": NEGATIVE_LEDGER_REL,
        "reasons": [
            "Current head has a frozen benchmark constitution but no lawful comparative widening while C006 remains open.",
            "Useful-output probes prove bounded same-host value, not category leadership or external superiority.",
            "Negative benchmark rows are preserved and keep blocked claims machine-visible.",
            "Economic truth now treats cross-host and mutation uncertainty as material cost, not optional commentary.",
        ],
        "claim_boundary": (
            "This scorecard remains a blocker surface. It freezes evaluation law and preserves negative evidence, "
            "but does not narrate superiority, category leadership, or product readiness."
        ),
        "source_refs": [
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            E2_RECEIPT_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
            TRUTH_LOCK_REL,
        ],
        "forbidden_claims_not_made": [
            "category_leading_superiority_earned",
            "router_superiority_earned",
            "hostile_replay_earned",
            "commercial_widening_unlocked",
            "frontier_or_beyond_sota_unlocked",
        ],
    }


def required_atlas_row_fields() -> tuple[str, ...]:
    return (
        "surface_id",
        "execution_path_ref",
        "governing_law_ref",
        "receipt",
        "validator",
        "challenge_pack_ref",
        "benchmark_pack_ref",
        "claim_ceiling",
        "allowed_claim_class",
        "economic_profile_id",
    )


def row_missing_fields(row: Mapping[str, Any], *, required_fields: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for field in required_fields:
        value = row.get(field)
        if value is None:
            missing.append(str(field))
            continue
        if isinstance(value, str) and not value.strip():
            missing.append(str(field))
        elif isinstance(value, (list, dict)) and not value:
            missing.append(str(field))
    return missing


def required_economic_profile_fields() -> tuple[str, ...]:
    return (
        "profile_id",
        "applies_to_surface_ids",
        "route_mode",
        "compute_cost_units",
        "review_burden_minutes",
        "remediation_burden_minutes",
        "uncertainty_cost_index",
        "supportability_class",
        "escalation_triggers",
        "fallback_action",
        "claim_boundary",
        "source_refs",
    )
