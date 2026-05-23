from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "AUTHOR_KT_LOBE_GATE_COURT_TAXONOMY_RECONCILIATION_PACKET_V1"
TARGET_OUTCOME = "KT_LOBE_GATE_COURT_TAXONOMY_RECONCILED__13_LOBE_SUPERLANE_READY__NO_CLAIM_EXPANSION"
NEXT_LAWFUL_MOVE = "RUN_13_LOBE_7B_TRANCHE"

BLOCKED_CLAIMS = {
    "external_audit_accepted": False,
    "external_audit_complete": False,
    "commercial_claim_authorized": False,
    "seven_b_amplification_proven": False,
    "s_tier_claim_authorized": False,
    "beyond_sota_claim_authorized": False,
    "category_leadership_claim_authorized": False,
    "kimi_parity_claim_authorized": False,
    "frontier_parity_claim_authorized": False,
    "router_superiority_claim_authorized": False,
    "multi_lobe_superiority_claim_authorized": False,
    "full_adaptive_orchestration_production_ready": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
}

CANONICAL_LOBES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("strategic_synthesis_lobe", "Synthesizes strategy, priorities, and high-level execution plans.", ("strategy", "planning", "tradeoff_synthesis")),
    ("audit_reasoning_lobe", "Reviews receipts, lineage, evidence completeness, and proof-court consistency.", ("audit", "receipt_review", "evidence_inventory")),
    ("formal_proof_reasoning_lobe", "Handles formal proof, logic, invariants, and theorem-like reasoning.", ("formal_proof", "logic", "invariant_reasoning")),
    ("contradiction_paradox_lobe", "Applies contradiction pressure, paradox handling, and inconsistency detection.", ("contradiction", "paradox", "inconsistency_pressure")),
    ("temporal_chronology_lobe", "Reasons over chronology, causality, stale heads, and ordered gates.", ("temporal", "chronology", "causal_order")),
    ("cross_domain_patterncraft_lobe", "Finds lawful cross-domain patterns and transfer opportunities.", ("cross_domain", "patterncraft", "transfer")),
    ("grounded_evidence_lobe", "Grounds outputs in current evidence, cited inputs, and observed runtime facts.", ("grounding", "source_binding", "evidence_trace")),
    ("regulated_domain_lobe", "Routes sensitive or regulated-domain work to stricter boundaries and refusal where needed.", ("regulated_domain", "sensitive_surface", "scope_boundary")),
    ("commercial_operator_lobe", "Translates bounded KT state into buyer/operator-safe language and workflows.", ("commercial_operator", "runbook", "customer_safe_language")),
    ("execution_tool_lobe", "Plans and monitors terminal/tool execution without bypassing gates.", ("execution", "tool_use", "operator_runtime")),
    ("context_memory_compression_lobe", "Compresses, packs, and retrieves context while canonical JSON remains authoritative.", ("context_packing", "memory", "compression")),
    ("learning_delta_lobe", "Models deltas, scar tissue, adapter learning, retention, and forgetting guards.", ("learning_delta", "scar_tissue", "adapter_delta")),
    ("adversarial_red_assault_lobe", "Attacks claims, receipts, routers, benchmarks, and runtime paths before promotion.", ("adversarial", "red_team", "attack_survival")),
)

FORBIDDEN_CANONICAL_LOBE_LABELS = (
    "claim_boundary",
    "proof_validator",
    "truth_engine",
    "bio_med_firewall",
    "evaluator_integrity",
    "primitive_invariance",
    "metacognitive_admission",
    "runtime_execution_chain",
    "delta_to_primitive",
    "router_control",
    "router_controller",
    "adapter_forge",
    "lobe_trainer",
    "benchmark_evaluator",
    "external_attestation",
    "commercial_boundary",
    "truth_grounding",
    "claim_compiler",
    "detached_verifier",
    "supply_chain_gate",
)

GATE_COMPONENTS: tuple[tuple[str, str, bool], ...] = (
    ("truth_lock", "current_state_lock", False),
    ("claim_compiler", "claim_boundary_gate", True),
    ("detached_verifier", "verification_gate", True),
    ("supply_chain_gate", "supply_chain_gate", True),
    ("external_attestation_gate", "external_review_gate", True),
    ("bio_med_firewall_gate", "regulated_domain_firewall", True),
    ("commercial_boundary_gate", "commercial_claim_gate", True),
    ("benchmark_court", "benchmark_court", True),
    ("proof_validator", "proof_court", True),
    ("reality_grounding_screen", "grounding_screen", True),
    ("evaluator_integrity_screen", "evaluator_integrity_court", True),
    ("runtime_execution_chain_screen", "runtime_chain_validator", True),
    ("prospective_metacognition_gate", "admission_gate", True),
    ("primitive_invariance_screen", "primitive_screen", True),
    ("categorical_boundary_screen", "category_boundary_screen", True),
    ("compositional_generalization_screen", "composition_screen", True),
    ("delta_to_primitive_compiler_screen", "delta_compiler_screen", True),
    ("truth_engine", "truth_engine", False),
)

MAPPING: tuple[tuple[str, str, str, str], ...] = (
    ("strategic_synthesis_lobe", "CANONICAL_COGNITIVE_LOBE", "strategic_synthesis_lobe", "canonical"),
    ("audit_reasoning_lobe", "CANONICAL_COGNITIVE_LOBE", "audit_reasoning_lobe", "canonical"),
    ("formal_proof_reasoning_lobe", "CANONICAL_COGNITIVE_LOBE", "formal_proof_reasoning_lobe", "canonical"),
    ("contradiction_paradox_lobe", "CANONICAL_COGNITIVE_LOBE", "contradiction_paradox_lobe", "canonical"),
    ("temporal_chronology_lobe", "CANONICAL_COGNITIVE_LOBE", "temporal_chronology_lobe", "canonical"),
    ("cross_domain_patterncraft_lobe", "CANONICAL_COGNITIVE_LOBE", "cross_domain_patterncraft_lobe", "canonical"),
    ("grounded_evidence_lobe", "CANONICAL_COGNITIVE_LOBE", "grounded_evidence_lobe", "canonical"),
    ("regulated_domain_lobe", "CANONICAL_COGNITIVE_LOBE", "regulated_domain_lobe", "canonical"),
    ("commercial_operator_lobe", "CANONICAL_COGNITIVE_LOBE", "commercial_operator_lobe", "canonical"),
    ("execution_tool_lobe", "CANONICAL_COGNITIVE_LOBE", "execution_tool_lobe", "canonical"),
    ("context_memory_compression_lobe", "CANONICAL_COGNITIVE_LOBE", "context_memory_compression_lobe", "canonical"),
    ("learning_delta_lobe", "CANONICAL_COGNITIVE_LOBE", "learning_delta_lobe", "canonical"),
    ("adversarial_red_assault_lobe", "CANONICAL_COGNITIVE_LOBE", "adversarial_red_assault_lobe", "canonical"),
    ("routing_control_lobe", "ROUTER_LAYER", "router_composition_advisor", "historical staging alias, not a lobe"),
    ("evidence_auditor_lobe", "HISTORICAL_COMPAT_ALIAS", "audit_reasoning_lobe", "rename to canonical cognitive lobe"),
    ("claim_boundary_lobe", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "claim_compiler_advisor", "gate scorer only"),
    ("benchmark_eval_lobe", "BENCHMARK_LAYER", "benchmark_court_advisor", "court advisor only"),
    ("context_efficiency_lobe", "HISTORICAL_COMPAT_ALIAS", "context_memory_compression_lobe", "rename to canonical cognitive lobe"),
    ("rollback_quarantine_lobe", "GATE_COURT_VALIDATOR", "rollback_quarantine_gate_advisor", "validator advisor only"),
    ("claim_boundary", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "claim_compiler_advisor", "gate scorer only"),
    ("truth_grounding", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "truth_grounding_advisor", "signal only"),
    ("primitive_invariance", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "primitive_invariance_advisor", "signal only"),
    ("metacognitive_admission", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "admission_gate_advisor", "signal only"),
    ("runtime_execution_chain", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "runtime_chain_validator_advisor", "signal only"),
    ("evaluator_integrity", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "evaluator_integrity_court_advisor", "signal only"),
    ("delta_to_primitive", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "delta_scar_compiler_advisor", "signal only"),
    ("router_control", "ROUTER_LAYER", "router_composition_advisor", "router composes cognition"),
    ("router_controller", "ROUTER_LAYER", "router_composition_advisor", "router composes cognition"),
    ("bio_med_firewall", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "regulated_domain_firewall_advisor", "no medical authority"),
    ("proof_validator", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "proof_court_advisor", "signal only"),
    ("benchmark_evaluator", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "benchmark_court_advisor", "signal only"),
    ("external_attestation", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "external_validation_advisor", "cannot self-attest"),
    ("commercial_boundary", "TRAINED_GATE_COURT_EVALUATOR_ADVISOR", "commercial_claim_gate_advisor", "signal only"),
    ("adapter_forge", "TRAINING_FACTORY", "adapter_factory_layer", "factory layer"),
    ("lobe_trainer", "TRAINING_FACTORY", "training_academy_layer", "factory layer"),
    ("truth_engine", "GATE_COURT_VALIDATOR", "truth_engine", "code-owned truth engine"),
    ("claim_compiler", "GATE_COURT_VALIDATOR", "claim_compiler", "code-owned claim compiler"),
    ("detached_verifier", "GATE_COURT_VALIDATOR", "detached_verifier", "code-owned verifier"),
    ("supply_chain_gate", "GATE_COURT_VALIDATOR", "supply_chain_gate", "code-owned gate"),
)

OUTPUTS = {
    "cognitive_lobe_registry": "adaptive/cognitive_lobe_registry.json",
    "cognitive_lobe_schema": "adaptive/cognitive_lobe_registry.schema.json",
    "gate_registry": "governance/gate_court_validator_registry.json",
    "gate_schema": "governance/gate_court_validator_registry.schema.json",
    "mapping": "adaptive/lobe_gate_mapping.json",
    "advisor_schema": "governance/gate_advisor_interface.schema.json",
    "lobe_target_matrix": "KT_PROD_CLEANROOM/reports/kt_lobe_target_matrix.json",
    "adapter_target_matrix": "KT_PROD_CLEANROOM/reports/kt_adapter_target_matrix.json",
    "reconciliation_receipt": "KT_PROD_CLEANROOM/reports/kt_lobe_gate_court_taxonomy_reconciliation_receipt.json",
    "taxonomy_next_move": "KT_PROD_CLEANROOM/reports/kt_13_lobe_superlane_next_lawful_move.json",
    "registry": "registry/artifact_authority_registry.json",
    "registry_delta": "registry/artifact_authority_registry_delta_receipt.json",
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _hash_or_none(root: Path, raw: str) -> str | None:
    path = root / raw
    return file_sha256(path) if path.is_file() else None


def _lobe_registry() -> dict[str, Any]:
    required_receipts = [
        "dataset_provenance_manifest",
        "training_run_receipt",
        "eval_receipt",
        "adapter_lineage_manifest",
        "rollback_or_quarantine_receipt",
        "claim_ceiling_preservation_receipt",
    ]
    return {
        "schema_id": "kt.adaptive.cognitive_lobe_registry.v1",
        "artifact_id": "KT_COGNITIVE_LOBE_REGISTRY",
        "authority": "PREP_SHADOW_TRAINING_TARGETS_ONLY",
        "generated_utc": utc_now_iso_z(),
        "canonical_lobe_count": len(CANONICAL_LOBES),
        "lobes": [
            {
                "lobe_id": lobe_id,
                "role": role,
                "training_target": True,
                "canonical_lobe": True,
                "gate_or_court": False,
                "historical_aliases": list(aliases),
                "allowed_training_surfaces": [
                    "adapter",
                    "lora",
                    "qlora_memory_gated",
                    "router_trace_features",
                    "shadow_eval_only",
                ],
                "required_receipts": required_receipts,
                "rollback_required": True,
                "claim_ceiling_preserved": True,
                "production_claim_allowed": False,
            }
            for lobe_id, role, aliases in CANONICAL_LOBES
        ],
        **BLOCKED_CLAIMS,
    }


def _lobe_schema() -> dict[str, Any]:
    canonical_ids = [lobe_id for lobe_id, _, _ in CANONICAL_LOBES]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.adaptive.cognitive_lobe_registry.schema.v1",
        "type": "object",
        "required": ["schema_id", "lobes"],
        "properties": {
            "schema_id": {"const": "kt.adaptive.cognitive_lobe_registry.v1"},
            "lobes": {
                "type": "array",
                "minItems": 13,
                "maxItems": 13,
                "items": {
                    "type": "object",
                    "required": [
                        "lobe_id",
                        "role",
                        "training_target",
                        "canonical_lobe",
                        "gate_or_court",
                        "historical_aliases",
                        "allowed_training_surfaces",
                        "required_receipts",
                        "rollback_required",
                        "claim_ceiling_preserved",
                    ],
                    "properties": {
                        "lobe_id": {"enum": canonical_ids},
                        "role": {"type": "string"},
                        "training_target": {"const": True},
                        "canonical_lobe": {"const": True},
                        "gate_or_court": {"const": False},
                        "historical_aliases": {"type": "array"},
                        "allowed_training_surfaces": {"type": "array"},
                        "required_receipts": {"type": "array"},
                        "rollback_required": {"const": True},
                        "claim_ceiling_preserved": {"const": True},
                    },
                },
            },
            "forbidden_as_canonical_lobe": {"enum": list(FORBIDDEN_CANONICAL_LOBE_LABELS)},
        },
        "not": {
            "properties": {
                "lobes": {
                    "contains": {
                        "properties": {
                            "lobe_id": {"enum": list(FORBIDDEN_CANONICAL_LOBE_LABELS)},
                        }
                    }
                }
            }
        },
    }


def _gate_registry() -> dict[str, Any]:
    return {
        "schema_id": "kt.governance.gate_court_validator_registry.v1",
        "artifact_id": "KT_GATE_COURT_VALIDATOR_REGISTRY",
        "authority": "CODE_OWNED_GOVERNANCE_LAYER",
        "generated_utc": utc_now_iso_z(),
        "components": [
            {
                "component_id": component_id,
                "component_type": component_type,
                "code_authority": True,
                "fail_closed": True,
                "advisory_adapter_allowed": advisory_allowed,
                "receipt_required": True,
                "claim_ceiling_required": True,
                "production_claim_allowed": False,
            }
            for component_id, component_type, advisory_allowed in GATE_COMPONENTS
        ],
        **BLOCKED_CLAIMS,
    }


def _gate_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.governance.gate_court_validator_registry.schema.v1",
        "type": "object",
        "required": ["schema_id", "components"],
        "properties": {
            "schema_id": {"const": "kt.governance.gate_court_validator_registry.v1"},
            "components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "component_id",
                        "component_type",
                        "code_authority",
                        "fail_closed",
                        "advisory_adapter_allowed",
                        "receipt_required",
                        "claim_ceiling_required",
                        "production_claim_allowed",
                    ],
                    "properties": {
                        "component_id": {"type": "string"},
                        "component_type": {"type": "string"},
                        "code_authority": {"const": True},
                        "fail_closed": {"const": True},
                        "advisory_adapter_allowed": {"type": "boolean"},
                        "receipt_required": {"const": True},
                        "claim_ceiling_required": {"const": True},
                        "production_claim_allowed": {"const": False},
                    },
                },
            },
        },
    }


def _mapping() -> dict[str, Any]:
    return {
        "schema_id": "kt.adaptive.lobe_gate_mapping.v1",
        "artifact_id": "KT_LOBE_GATE_MAPPING",
        "authority": "TAXONOMY_RECONCILIATION",
        "generated_utc": utc_now_iso_z(),
        "allowed_classes": [
            "CANONICAL_COGNITIVE_LOBE",
            "TRAINED_GATE_COURT_EVALUATOR_ADVISOR",
            "GATE_COURT_VALIDATOR",
            "ROUTER_LAYER",
            "TRAINING_FACTORY",
            "KT_HAT_RUNTIME",
            "BENCHMARK_LAYER",
            "HISTORICAL_COMPAT_ALIAS",
            "ARCHIVE_ONLY",
        ],
        "mappings": [
            {
                "source_label": source,
                "taxonomy_class": taxonomy_class,
                "corrected_target": target,
                "reason": reason,
                "canonical_lobe": taxonomy_class == "CANONICAL_COGNITIVE_LOBE",
                "advisor_only": taxonomy_class == "TRAINED_GATE_COURT_EVALUATOR_ADVISOR",
            }
            for source, taxonomy_class, target, reason in MAPPING
        ],
        "prior_gate_scaffold_adapters_preserved_as_advisors": True,
        **BLOCKED_CLAIMS,
    }


def _advisor_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.governance.gate_advisor_interface.schema.v1",
        "type": "object",
        "required": [
            "schema_id",
            "advisor_id",
            "signal_only",
            "may_authorize_claims",
            "may_promote_adapters_or_lobes",
            "may_certify_benchmark_results",
            "may_override_code_owned_gates",
            "pass_fail_authority",
            "receipt_required",
        ],
        "properties": {
            "schema_id": {"const": "kt.governance.gate_advisor_interface.v1"},
            "advisor_id": {"type": "string"},
            "signal_only": {"const": True},
            "allowed_outputs": {
                "type": "array",
                "items": {"enum": ["risk_flag", "uncertainty_score", "repair_suggestion", "escalation_recommendation"]},
            },
            "may_authorize_claims": {"const": False},
            "may_promote_adapters_or_lobes": {"const": False},
            "may_certify_benchmark_results": {"const": False},
            "may_override_code_owned_gates": {"const": False},
            "pass_fail_authority": {"const": "CODE_OWNED_SCHEMA_BOUND_RECEIPT_BOUND_FAIL_CLOSED_ONLY"},
            "receipt_required": {"const": True},
        },
        "additionalProperties": True,
    }


def _lobe_target_matrix() -> dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.lobe_target_matrix.v2",
        "artifact_id": "KT_LOBE_TARGET_MATRIX",
        "authority": "TRAINING_STAGING_ONLY_13_CANONICAL_LOBES",
        "generated_utc": utc_now_iso_z(),
        "taxonomy_reconciled": True,
        "canonical_lobe_count": 13,
        "lobes": [
            {
                "lobe_id": lobe_id,
                "objective": aliases[0],
                "production_authority_after_training": False,
                "requires_dataset_provenance": True,
                "requires_eval_gate": True,
                "requires_receipt": True,
                "requires_recipe": True,
                "requires_rollback": True,
                "trainable_surface": "adapter_or_lora_qlora_shadow_only",
                "advisor_gate_outputs_allowed": True,
            }
            for lobe_id, _, aliases in CANONICAL_LOBES
        ],
        "forbidden_training_targets": list(FORBIDDEN_CANONICAL_LOBE_LABELS),
        "prior_gate_scaffold_training_preserved_as_advisors": True,
        **BLOCKED_CLAIMS,
    }


def _adapter_target_matrix() -> dict[str, Any]:
    return {
        "schema_id": "kt.gpu_conversion.adapter_target_matrix.v2",
        "artifact_id": "KT_ADAPTER_TARGET_MATRIX",
        "authority": "TRAINING_STAGING_ONLY_13_CANONICAL_LOBES",
        "generated_utc": utc_now_iso_z(),
        "taxonomy_reconciled": True,
        "adapters": [
            {
                "adapter_id": lobe_id.replace("_lobe", "_adapter"),
                "parent_lobe": lobe_id,
                "default_recipe": "LORA_SMOKE_V1",
                "optional_recipe": "QLORA_MEMORY_GATED_V1",
                "objective": f"shadow-train {role}",
                "promotion_authorized_by_this_packet": False,
                "requires_eval_receipt": True,
                "requires_lineage_manifest": True,
                "requires_rollback_plan": True,
                "requires_tournament_entry_receipt": True,
            }
            for lobe_id, role, _ in CANONICAL_LOBES
        ],
        "advisor_adapters_preserved_not_promoted": [target for _, taxonomy_class, target, _ in MAPPING if taxonomy_class == "TRAINED_GATE_COURT_EVALUATOR_ADVISOR"],
        **BLOCKED_CLAIMS,
    }


def _receipt(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.lobe_gate_court.taxonomy_reconciliation_receipt.v1",
        "artifact_id": "KT_LOBE_GATE_COURT_TAXONOMY_RECONCILIATION_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "selected_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "exactly_13_canonical_cognitive_lobes": True,
        "gate_court_validator_layer_separate": True,
        "prior_gate_scaffold_adapters_preserved_as_advisors": True,
        "advisor_adapters_own_pass_fail_authority": False,
        "future_kaggle_training_restricted_to_13_lobe_ids": True,
        "router_superiority_order_preserved": [
            "static_baseline",
            "shadow_evaluation",
            "best_static_comparison",
            "learned_router_candidate",
            "statistical_evidence",
            "multi_lobe_orchestration",
        ],
        **BLOCKED_CLAIMS,
    }


def _next_move(current_head: str) -> dict[str, Any]:
    return {
        "schema_id": "kt.13_lobe_superlane.next_lawful_move.v1",
        "artifact_id": "KT_13_LOBE_SUPERLANE_NEXT_LAWFUL_MOVE",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "selected_outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "uses_13_canonical_cognitive_lobes_only": True,
        "inherits_t4_safe_repair_settings": True,
        "clean_7b_smoke_or_tranche_claim_not_yet_earned": True,
        **BLOCKED_CLAIMS,
    }


def _registry_entry(root: Path, artifact_id: str, path: str, role: str) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "path": path,
        "role": role,
        "authority_state": "LIVE_CURRENT_HEAD_PREP_ONLY",
        "validation_status": "PASS",
        "controls_execution": True,
        "claim_authority": "INTERNAL_SHADOW",
        "sha256": _hash_or_none(root, path),
        "supersedes": [],
        "superseded_by": None,
        "notes": "Taxonomy reconciliation artifact; no claim expansion or production authority.",
    }


def _update_registry(root: Path, current_head: str) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_json(root / OUTPUTS["registry"])
    taxonomy_ids = {
        "KT_COGNITIVE_LOBE_REGISTRY",
        "KT_GATE_COURT_VALIDATOR_REGISTRY",
        "KT_LOBE_GATE_MAPPING",
        "KT_GATE_ADVISOR_INTERFACE_SCHEMA",
        "KT_LOBE_GATE_COURT_TAXONOMY_RECONCILIATION_RECEIPT",
        "KT_13_LOBE_SUPERLANE_NEXT_LAWFUL_MOVE",
    }
    artifacts = [artifact for artifact in registry.get("artifacts", []) if artifact.get("artifact_id") not in taxonomy_ids]
    for artifact in artifacts:
        if artifact.get("artifact_id") == "KT_7B_Q_LORA_SMOKE_REPAIR_NEXT_LAWFUL_MOVE":
            artifact["controls_execution"] = False
            artifact["authority_state"] = "SUPERSEDED"
            artifact["superseded_by"] = OUTPUTS["taxonomy_next_move"]
            artifact["notes"] = "Superseded as direct next move by 13-lobe taxonomy reconciliation; repair settings remain incorporated into the 13-lobe tranche run policy."
    artifacts.extend(
        [
            _registry_entry(root, "KT_COGNITIVE_LOBE_REGISTRY", OUTPUTS["cognitive_lobe_registry"], "canonical_13_cognitive_lobe_registry"),
            _registry_entry(root, "KT_GATE_COURT_VALIDATOR_REGISTRY", OUTPUTS["gate_registry"], "gate_court_validator_registry"),
            _registry_entry(root, "KT_LOBE_GATE_MAPPING", OUTPUTS["mapping"], "lobe_gate_taxonomy_mapping"),
            _registry_entry(root, "KT_GATE_ADVISOR_INTERFACE_SCHEMA", OUTPUTS["advisor_schema"], "gate_advisor_interface"),
            _registry_entry(root, "KT_LOBE_GATE_COURT_TAXONOMY_RECONCILIATION_RECEIPT", OUTPUTS["reconciliation_receipt"], "taxonomy_reconciliation_receipt"),
            _registry_entry(root, "KT_13_LOBE_SUPERLANE_NEXT_LAWFUL_MOVE", OUTPUTS["taxonomy_next_move"], "seven_b_training_next_move"),
        ]
    )
    duplicates = _duplicate_controllers(artifacts)
    if duplicates:
        raise RuntimeError(f"Duplicate controlling artifacts after taxonomy reconciliation: {duplicates}")
    registry["current_head"] = current_head
    registry["generated_utc"] = utc_now_iso_z()
    registry["artifacts"] = artifacts

    delta = {
        "schema_id": "kt.artifact_authority_registry_delta_receipt.v2",
        "artifact_id": "KT_ARTIFACT_AUTHORITY_REGISTRY_DELTA_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "current_head": current_head,
        "artifacts_added": [
            OUTPUTS["cognitive_lobe_registry"],
            OUTPUTS["cognitive_lobe_schema"],
            OUTPUTS["gate_registry"],
            OUTPUTS["gate_schema"],
            OUTPUTS["mapping"],
            OUTPUTS["advisor_schema"],
            OUTPUTS["reconciliation_receipt"],
            OUTPUTS["taxonomy_next_move"],
        ],
        "artifacts_modified": [
            OUTPUTS["lobe_target_matrix"],
            OUTPUTS["adapter_target_matrix"],
            OUTPUTS["registry"],
            OUTPUTS["registry_delta"],
        ],
        "artifacts_superseded": ["KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_repair_next_lawful_move.json"],
        "old_labels_reclassified": [source for source, _, _, _ in MAPPING if source not in {lobe_id for lobe_id, _, _ in CANONICAL_LOBES}],
        "prior_gate_scaffold_adapters_preserved_as_advisors": True,
        "claim_ceiling_unchanged": True,
        "production_commercial_external_superiority_authority_added": False,
        "duplicate_controlling_artifacts": [],
    }
    return registry, delta


def _duplicate_controllers(artifacts: Sequence[Mapping[str, Any]]) -> list[str]:
    roles: dict[str, int] = {}
    for artifact in artifacts:
        if artifact.get("controls_execution") is True and artifact.get("superseded_by") is None:
            role = str(artifact.get("role", ""))
            roles[role] = roles.get(role, 0) + 1
    return sorted(role for role, count in roles.items() if count > 1)


def run(*, output_root: Path | None = None) -> dict[str, Any]:
    root = output_root or repo_root()
    current_head = _git_head(root)
    changed: list[str] = []
    payloads = {
        OUTPUTS["cognitive_lobe_registry"]: _lobe_registry(),
        OUTPUTS["cognitive_lobe_schema"]: _lobe_schema(),
        OUTPUTS["gate_registry"]: _gate_registry(),
        OUTPUTS["gate_schema"]: _gate_schema(),
        OUTPUTS["mapping"]: _mapping(),
        OUTPUTS["advisor_schema"]: _advisor_schema(),
        OUTPUTS["lobe_target_matrix"]: _lobe_target_matrix(),
        OUTPUTS["adapter_target_matrix"]: _adapter_target_matrix(),
        OUTPUTS["reconciliation_receipt"]: _receipt(current_head),
        OUTPUTS["taxonomy_next_move"]: _next_move(current_head),
    }
    for raw, obj in payloads.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)
    registry, delta = _update_registry(root, current_head)
    if write_json_stable(root / OUTPUTS["registry"], registry):
        changed.append(OUTPUTS["registry"])
    if write_json_stable(root / OUTPUTS["registry_delta"], delta):
        changed.append(OUTPUTS["registry_delta"])
    return {
        "current_head": current_head,
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "changed_outputs": changed,
        "claim_ceiling": "unchanged",
        "blockers": [],
    }


def main(argv: Sequence[str] | None = None, *, output_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Author KT lobe/gate/court taxonomy reconciliation packet.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run(output_root=output_root)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(TARGET_OUTCOME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
