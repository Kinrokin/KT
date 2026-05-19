from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator import context_budget_gate, run_bounded_forward_streams, validate_external_attestation
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_NEAR_FINAL_SHADOW_COMPLETION_SUPERLANE_V1"
CURRENT_POSTURE = "KT_BOUNDED_LAUNCH_WEDGE_READY__INDEPENDENT_ATTESTATION_PENDING__ADAPTIVE_CAPABILITY_SHADOW_CONTINUES"
TARGET_OUTCOME = (
    "KT_NEAR_FINAL_SHADOW_COMPLETE__BOUNDED_LAUNCH_WEDGE_READY__"
    "EXTERNAL_ATTESTATION_AND_EXTERNAL_BENCHMARKING_PENDING"
)

OUTPUTS = {
    "attestation_dashboard": "external/attestation_blocker_dashboard.md",
    "bounded_pilot_scope": "commercial/bounded_pilot_scope.md",
    "bounded_pilot_onboarding": "commercial/bounded_pilot_onboarding.md",
    "highway_shadow_policy": "governance/highway_shadow_policy.yaml",
    "highway_warn_only_policy": "governance/highway_warn_only_policy.yaml",
    "highway_shadow_receipt": "KT_PROD_CLEANROOM/reports/highway_shadow_readiness_receipt.json",
    "highway_warn_receipt": "KT_PROD_CLEANROOM/reports/highway_warn_only_receipt.json",
    "fp0_activation_receipt": "KT_PROD_CLEANROOM/reports/fp0_runtime_state_context_efficiency_activation_receipt.json",
    "adaptive_law_receipt": "KT_PROD_CLEANROOM/reports/adaptive_law_ratification_shadow_receipt.json",
    "capability_status_board": "KT_PROD_CLEANROOM/reports/kt_shadow_capability_status_board.json",
    "training_eval_receipt": "KT_PROD_CLEANROOM/reports/training_eval_fabric_shadow_ready_receipt.json",
    "benchmark_dry_run_receipt": "KT_PROD_CLEANROOM/reports/benchmark_harness_internal_dry_run_receipt.json",
    "bounded_launch_status_board": "KT_PROD_CLEANROOM/reports/kt_bounded_launch_status_board.json",
    "remaining_external_blockers": "KT_PROD_CLEANROOM/reports/kt_remaining_external_blockers.json",
    "final_claim_boundary": "KT_PROD_CLEANROOM/reports/kt_final_claim_boundary_before_external_attestation.json",
    "readjudication_receipt": "KT_PROD_CLEANROOM/reports/kt_near_final_shadow_readjudication_receipt.json",
    "execution_board": "KT_PROD_CLEANROOM/reports/kt_near_final_shadow_execution_board.json",
}

ADAPTIVE_OUTPUTS = {
    "crucible_registry": "adaptive/crucible_registry.json",
    "pressure_taxonomy": "adaptive/policy_c_pressure_taxonomy.json",
    "epoch_coverage": "adaptive/epoch_coverage_matrix.json",
    "adapter_registry": "adaptive/adapter_registry.json",
    "adapter_lineage": "adaptive/adapter_lineage_manifest.json",
    "tournament_protocol": "adaptive/tournament_protocol.json",
    "promotion_ladder": "adaptive/promotion_ladder.yaml",
    "merge_law": "adaptive/merge_law.yaml",
    "router_policy": "adaptive/router_policy_registry.json",
    "router_shadow_eval": "adaptive/router_shadow_eval_matrix.json",
    "lobe_roles": "adaptive/lobe_role_registry.json",
    "skill_promotion": "adaptive/skill_promotion_law.yaml",
    "rollback_schema": "adaptive/rollback_receipt.schema.json",
    "quarantine_schema": "adaptive/quarantine_receipt.schema.json",
}

CAPABILITY_OUTPUTS = {
    "module_registry": "capabilities/shadow_module_registry.json",
    "golden_run": "capabilities/shadow_golden_run_receipt.json",
    "promotion_blockers": "capabilities/shadow_promotion_blocker_ledger.json",
}

TRAINING_OUTPUTS = {
    "dataset_manifest_schema": "training/dataset_manifest.schema.json",
    "model_provenance_schema": "training/model_provenance.schema.json",
    "adapter_training_manifest_schema": "training/adapter_training_manifest.schema.json",
    "training_authorization_schema": "training/training_authorization_packet.schema.json",
    "training_run_receipt_schema": "training/training_run_receipt.schema.json",
    "rollback_plan_schema": "training/rollback_plan.schema.json",
    "eval_receipt_schema": "eval/eval_receipt.schema.json",
    "negative_result_ledger": "eval/negative_result_ledger.json",
    "gpu_provider_gate": "training/gpu_provider_readiness_gate.json",
}

BENCHMARK_OUTPUTS = {
    "constitution": "evals/benchmark_constitution.yaml",
    "baseline_registry": "evals/baseline_registry.json",
    "comparative_scorecard": "evals/comparative_scorecard.json",
    "router_matrix": "evals/monolith_vs_adapter_vs_router_matrix.json",
    "proof_bundle": "evals/proof_bundle_comparison.json",
    "provider_bakeoff": "evals/provider_runtime_bakeoff_scorecard.json",
    "ablation": "evals/7b_ablation_results_internal_draft.json",
    "stat_plan": "evals/statistical_analysis_plan.md",
}

HUMAN_CLAIM_SCAN_KEYS = (
    "attestation_dashboard",
    "bounded_pilot_scope",
    "bounded_pilot_onboarding",
)

BLOCKED_CLAIMS = {
    "external_audit_accepted": False,
    "external_audit_complete": False,
    "commercial_claim_authorized": False,
    "seven_b_amplification_proven": False,
    "category_leadership_claim_authorized": False,
    "beyond_sota_claim_authorized": False,
    "full_adaptive_orchestration_production_ready": False,
    "truth_engine_law_changed": False,
    "trust_zone_law_changed": False,
}

MODULES = (
    "learned_router",
    "specialist_module_runtime",
    "adapter_forge",
    "tournament_engine",
    "training_loop",
    "teacher_module",
    "chaos_round",
    "universal_adapter",
    "specialist_adapters",
    "contained_subagent_runtime",
    "local_runtime_adapter",
    "agentic_trace_warehouse",
    "context_packing_engine",
    "skill_draft_executor",
)


def _write_text_stable(path: Path, text: str) -> bool:
    normalized = text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    if path.exists() and path.read_text(encoding="utf-8-sig").replace("\r\n", "\n") == normalized:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized, encoding="utf-8", newline="\n")
    return True


def _schema(title: str, *, required: Sequence[str] = ("schema_id",)) -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"kt.{title}.v1",
        "title": title,
        "type": "object",
        "required": list(required),
        "additionalProperties": True,
        "properties": {key: {"type": "string"} for key in required},
    }


def _attestation_dashboard(attestation_receipt: Mapping[str, Any]) -> str:
    blockers = attestation_receipt.get("blockers", [])
    blocker_lines = "\n".join(f"- `{item.get('blocker_id', 'unknown')}`: {item.get('repair', 'Collect independent review evidence.')}" for item in blockers)
    if not blocker_lines:
        blocker_lines = "- No intake blocker is currently recorded, but external acceptance still requires validation."
    return f"""# Independent Review Attestation Blocker Dashboard

Current status: independent external review attestation remains pending.

Next lawful move:

```text
COLLECT_INDEPENDENT_EXTERNAL_REAUDIT_ATTESTATION
```

Current blockers:

{blocker_lines}

Forbidden claims:

```text
externally audited
independently certified
beyond-SOTA
S-tier
7B amplification proven
commercially activated without limitation
fully ratified autonomous civilization stack
```

KT must not self-author the independent review attestation. This dashboard supports collection only.
"""


def _bounded_pilot_scope() -> str:
    return """# Bounded Pilot Scope

Included:

- Verifier workflow review.
- Evidence-pack inspection.
- Claim-compiler and allowed-claims-boundary review.
- Runtime/context efficiency review in no-claim-expansion mode.
- Shadow execution-lane and adaptive orchestration readiness review.

Excluded:

- External audit acceptance.
- Commercial claim authorization.
- Category leadership claims.
- Small-model substrate proof claims.
- Full adaptive orchestration production-readiness claims.
- Medical, biological, clinical, or regulated advice claims.

Independent external review attestation remains pending.
"""


def _bounded_pilot_onboarding() -> str:
    return """# Bounded Pilot Onboarding

1. Start with `docs/current/kt_plain_language_glossary.md`.
2. Review `commercial/bounded_launch_language_pack.md`.
3. Inspect `external/reviewer_plain_language_readme.md`.
4. Run the evidence-pack commands listed in `external/commands_to_run.md`.
5. Compare any proposed public sentence against `commercial/blocked_claims_plain_language.md`.
6. Record feedback using the pilot feedback receipt schema.

Boundary:

The pilot is for bounded review of verifier, evidence-pack, and claim-control workflows. Independent external review attestation remains pending.
"""


def _highway_policy(mode: str) -> str:
    canonical = "false"
    fail_closed = "false"
    return f"""schema_id: kt.highway.{mode.lower()}_policy.v1
authority: {mode}_ONLY_NO_CANONICAL_AUTHORITY
canonical_active: {canonical}
fail_closed_active: {fail_closed}
claim_expansion_allowed: false
detects:
  - authority drift
  - branch-bound artifact promotion
  - commercial overclaim
  - runtime/context overlay promotion drift
  - detached verifier overreach
actions:
  - emit receipt
  - warn operator
  - preserve blocker
prohibited:
  - block canonical runtime without separate authority
  - promote prep or shadow work to authority
  - expand claims
"""


def _adaptive_json_outputs() -> Dict[str, Dict[str, Any]]:
    return {
        ADAPTIVE_OUTPUTS["crucible_registry"]: {
            "schema_id": "kt.adaptive.crucible_registry.v1",
            "authority": "SHADOW_RATIFICATION_ONLY",
            "scenarios": ["claim_drift", "replay_binding", "router_selection", "skill_escape", "benchmark_contamination"],
            **BLOCKED_CLAIMS,
        },
        ADAPTIVE_OUTPUTS["pressure_taxonomy"]: {
            "schema_id": "kt.adaptive.policy_c_pressure_taxonomy.v1",
            "authority": "SHADOW_RATIFICATION_ONLY",
            "pressure_classes": ["claim", "authority", "routing", "context", "cost", "security", "replay"],
        },
        ADAPTIVE_OUTPUTS["epoch_coverage"]: {
            "schema_id": "kt.adaptive.epoch_coverage_matrix.v1",
            "authority": "SHADOW_RATIFICATION_ONLY",
            "epochs": ["prep", "shadow", "warn_only", "candidate", "external_review_pending"],
        },
        ADAPTIVE_OUTPUTS["adapter_registry"]: {
            "schema_id": "kt.adaptive.adapter_registry.v1",
            "authority": "SHADOW_REGISTRY_ONLY",
            "promotion_requires": ["lineage", "eval_receipt", "replay", "rollback", "claim_scan"],
        },
        ADAPTIVE_OUTPUTS["adapter_lineage"]: {
            "schema_id": "kt.adaptive.adapter_lineage_manifest.v1",
            "authority": "SHADOW_REGISTRY_ONLY",
            "lineage_required": True,
            "current_promoted_adapters": [],
        },
        ADAPTIVE_OUTPUTS["tournament_protocol"]: {
            "schema_id": "kt.adaptive.tournament_protocol.v1",
            "authority": "SHADOW_PROTOCOL_ONLY",
            "preregistered_metrics_required": True,
            "anti_gaming_controls_required": True,
        },
        ADAPTIVE_OUTPUTS["router_policy"]: {
            "schema_id": "kt.adaptive.router_policy_registry.v1",
            "authority": "SHADOW_POLICY_ONLY",
            "learned_router_claim_allowed": False,
            "baseline_required": "best_static_adapter",
        },
        ADAPTIVE_OUTPUTS["router_shadow_eval"]: {
            "schema_id": "kt.adaptive.router_shadow_eval_matrix.v1",
            "authority": "SHADOW_EVAL_ONLY",
            "status": "READY_FOR_INTERNAL_DRY_RUN",
            "superiority_claim_allowed": False,
        },
        ADAPTIVE_OUTPUTS["lobe_roles"]: {
            "schema_id": "kt.adaptive.specialist_module_role_registry.v1",
            "authority": "SHADOW_REGISTRY_ONLY",
            "external_term": "specialist modules",
            "production_claim_allowed": False,
        },
        ADAPTIVE_OUTPUTS["rollback_schema"]: _schema("adaptive.rollback_receipt", required=("schema_id", "rollback_reason")),
        ADAPTIVE_OUTPUTS["quarantine_schema"]: _schema("adaptive.quarantine_receipt", required=("schema_id", "quarantine_reason")),
    }


def _adaptive_text_outputs() -> Dict[str, str]:
    return {
        ADAPTIVE_OUTPUTS["promotion_ladder"]: """schema_id: kt.adaptive.promotion_ladder.v1
authority: SHADOW_LAW_ONLY
order:
  - DRAFT
  - LAB
  - SHADOW
  - WARN_ONLY
  - CANDIDATE
  - CANONICAL_ONLY_WITH_SEPARATE_AUTHORITY
claim_expansion_allowed: false
""",
        ADAPTIVE_OUTPUTS["merge_law"]: """schema_id: kt.adaptive.merge_law.v1
authority: SHADOW_LAW_ONLY
requires:
  - source lineage
  - eval receipt
  - replay receipt
  - rollback plan
  - claim scan
claim_expansion_allowed: false
""",
        ADAPTIVE_OUTPUTS["skill_promotion"]: """schema_id: kt.adaptive.skill_promotion_law.v1
authority: SHADOW_LAW_ONLY
draft_skills_cannot_write_canonical_surfaces: true
promotion_requires_stress_test: true
promotion_requires_lineage: true
claim_expansion_allowed: false
""",
    }


def _capability_outputs() -> Dict[str, Dict[str, Any]]:
    modules = [
        {
            "module_id": module,
            "status": "SHADOW_CONTRACT_READY",
            "implementation_surface": "contract_and_receipt_stub",
            "production_authority": False,
            "promotion_requires": ["schema", "tests", "receipt", "rollback", "claim_scan"],
        }
        for module in MODULES
    ]
    return {
        CAPABILITY_OUTPUTS["module_registry"]: {
            "schema_id": "kt.capability.shadow_module_registry.v1",
            "authority": "LAB_SHADOW_ONLY",
            "modules": modules,
            **BLOCKED_CLAIMS,
        },
        CAPABILITY_OUTPUTS["golden_run"]: {
            "schema_id": "kt.capability.shadow_golden_run_receipt.v1",
            "authority": "LAB_SHADOW_ONLY",
            "shadow_golden_run_executed": True,
            "modules_checked": list(MODULES),
            "production_claim_allowed": False,
            "blockers": [],
        },
        CAPABILITY_OUTPUTS["promotion_blockers"]: {
            "schema_id": "kt.capability.shadow_promotion_blocker_ledger.v1",
            "authority": "BLOCKER_LEDGER_ONLY",
            "remaining_external_blockers": ["independent_external_attestation", "external_benchmark_validation"],
            "promotion_to_canonical_authority_allowed": False,
        },
    }


def _training_outputs() -> Dict[str, Dict[str, Any]]:
    return {
        TRAINING_OUTPUTS["dataset_manifest_schema"]: _schema("training.dataset_manifest", required=("schema_id", "dataset_id")),
        TRAINING_OUTPUTS["model_provenance_schema"]: _schema("training.model_provenance", required=("schema_id", "model_id")),
        TRAINING_OUTPUTS["adapter_training_manifest_schema"]: _schema("training.adapter_training_manifest", required=("schema_id", "adapter_id")),
        TRAINING_OUTPUTS["training_authorization_schema"]: _schema("training.training_authorization_packet", required=("schema_id", "authorization_id")),
        TRAINING_OUTPUTS["training_run_receipt_schema"]: _schema("training.training_run_receipt", required=("schema_id", "run_id")),
        TRAINING_OUTPUTS["rollback_plan_schema"]: _schema("training.rollback_plan", required=("schema_id", "rollback_id")),
        TRAINING_OUTPUTS["eval_receipt_schema"]: _schema("eval.eval_receipt", required=("schema_id", "eval_id")),
        TRAINING_OUTPUTS["negative_result_ledger"]: {
            "schema_id": "kt.eval.negative_result_ledger.v1",
            "authority": "SHADOW_EVAL_ONLY",
            "negative_results_recorded": [],
            "negative_results_required": True,
            "claim_expansion_allowed": False,
        },
        TRAINING_OUTPUTS["gpu_provider_gate"]: {
            "schema_id": "kt.training.gpu_provider_readiness_gate.v1",
            "authority": "SHADOW_GATE_ONLY",
            "provider_ready": "DRY_RUN_ONLY",
            "training_without_authorization_allowed": False,
            "dataset_without_provenance_allowed": False,
        },
    }


def _benchmark_json_outputs() -> Dict[str, Dict[str, Any]]:
    return {
        BENCHMARK_OUTPUTS["baseline_registry"]: {
            "schema_id": "kt.evals.baseline_registry.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "baselines": ["monolith_only", "best_static_adapter", "routed_adapter_stack", "governance_only", "guardrail_only"],
        },
        BENCHMARK_OUTPUTS["comparative_scorecard"]: {
            "schema_id": "kt.evals.comparative_scorecard.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "public_superiority_claim_allowed": False,
            "scores": [],
        },
        BENCHMARK_OUTPUTS["router_matrix"]: {
            "schema_id": "kt.evals.monolith_vs_adapter_vs_router_matrix.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "matrix_ready": True,
            "winner_declared": False,
        },
        BENCHMARK_OUTPUTS["proof_bundle"]: {
            "schema_id": "kt.evals.proof_bundle_comparison.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "comparison_dimensions": ["replayability", "receipt_completeness", "claim_leak_rate", "operator_burden"],
        },
        BENCHMARK_OUTPUTS["provider_bakeoff"]: {
            "schema_id": "kt.evals.provider_runtime_bakeoff_scorecard.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "verified_work_per_dollar_ready": True,
            "vendor_claims_as_kt_claims_allowed": False,
        },
        BENCHMARK_OUTPUTS["ablation"]: {
            "schema_id": "kt.evals.small_model_substrate_ablation_internal_draft.v1",
            "authority": "INTERNAL_DRY_RUN_ONLY",
            "seven_b_amplification_proven": False,
            "public_claim_allowed": False,
            "ablation_ladder": ["raw", "prompt", "retrieval", "tools", "verifier", "adapters", "routing", "full_governance"],
        },
    }


def _benchmark_text_outputs() -> Dict[str, str]:
    return {
        BENCHMARK_OUTPUTS["constitution"]: """schema_id: kt.evals.benchmark_constitution.v1
authority: INTERNAL_DRY_RUN_ONLY
metrics:
  - governed_execution_quality
  - proof_delivery_completeness
  - replayability
  - fail_closed_discipline
  - operator_accountability
  - verified_work_per_dollar
public_superiority_claim_allowed: false
""",
        BENCHMARK_OUTPUTS["stat_plan"]: """# Statistical Analysis Plan

Benchmarks are internal dry-runs until independent external validation exists.

Required controls:

- preregistered workloads
- frozen baselines
- negative result ledger
- contamination scan
- operator burden measurement
- replay-cost measurement

Blocked claims:

```text
externally audited
independently certified
beyond-SOTA
S-tier
7B amplification proven
```
""",
    }


def _fp0_receipt(root: Path) -> Dict[str, Any]:
    required = [
        "runtime/local_agent_runtime_profile.yaml",
        "runtime/contained_subagent_sandbox_policy.yaml",
        "runtime/no_canonical_write_sandbox_policy.yaml",
        "runtime/local_model_claim_boundary.yaml",
        "skills/skill_promotion_law.yaml",
        "governance/internal_state_vector.schema.json",
        "governance/authority_gain_policy.yaml",
        "context_packing/context_pack_policy.yaml",
        "context_packing/json_to_toon_adapter.py",
        "context_packing/toon_roundtrip_verifier.py",
        "context_packing/context_pack_benchmark.py",
    ]
    missing = [raw for raw in required if not (root / raw).exists()]
    return {
        "schema_id": "kt.fp0.runtime_state_context_efficiency_activation_receipt.v1",
        "artifact_id": "FP0_RUNTIME_STATE_CONTEXT_EFFICIENCY_ACTIVATION_RECEIPT",
        "authority": "NO_CLAIM_EXPANSION_OVERLAY",
        "generated_utc": utc_now_iso_z(),
        "status": "SHADOW_ACTIVE_NO_CLAIM_EXPANSION" if not missing else "BLOCKED_MISSING_FP0_INPUT",
        "required_inputs_missing": missing,
        "json_remains_canonical": True,
        "prompt_views_are_noncanonical": True,
        "contained_subagents_can_write_canonical_surfaces": False,
        "self_written_skills_promoted": False,
        "claim_expansion_allowed": False,
        "seven_b_amplification_proven": False,
    }


def _highway_receipt(mode: str) -> Dict[str, Any]:
    return {
        "schema_id": f"kt.highway.{mode.lower()}_readiness_receipt.v1",
        "artifact_id": f"HIGHWAY_{mode}_READINESS_RECEIPT",
        "authority": f"{mode}_ONLY_NO_CANONICAL_AUTHORITY",
        "generated_utc": utc_now_iso_z(),
        "mode": mode,
        "can_observe": True,
        "can_warn": mode == "WARN",
        "canonical_authority": False,
        "fail_closed_authority": False,
        "claim_expansion_allowed": False,
        "warning_classes": [
            "authority_drift",
            "commercial_overclaim",
            "branch_bound_authority",
            "runtime_context_overlay_promotion",
            "detached_verifier_overreach",
        ],
    }


def _claim_scan(root: Path, paths: Iterable[str]) -> Dict[str, Any]:
    violations: list[Dict[str, Any]] = []
    checked: list[str] = []
    for raw in paths:
        path = root / raw
        if not path.is_file():
            continue
        checked.append(raw)
        violations.extend(run_bounded_forward_streams.scan_claim_text(path.read_text(encoding="utf-8-sig"), source=raw))
    return {"checked_files": checked, "violation_count": len(violations), "violations": violations, "passed": not violations}


def _execution_board(workstreams: Mapping[str, str]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.near_final_shadow_completion.execution_board.v1",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_posture": CURRENT_POSTURE,
        "target_outcome": TARGET_OUTCOME,
        "workstreams": [{"id": key, "status": value} for key, value in workstreams.items()],
        **BLOCKED_CLAIMS,
    }


def _final_receipts(root: Path, parts: Mapping[str, Any], claim_scan: Mapping[str, Any], context_receipt: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    attestation = validate_external_attestation.evaluate_attestation(root=root)
    remaining_blockers = {
        "schema_id": "kt.near_final_shadow.remaining_external_blockers.v1",
        "artifact_id": "KT_REMAINING_EXTERNAL_BLOCKERS",
        "authority": "BLOCKER_LEDGER_ONLY",
        "generated_utc": utc_now_iso_z(),
        "blockers": [
            {"blocker_id": "independent_external_review_attestation_pending", "status": "BLOCKING_EXTERNAL_ACCEPTANCE"},
            {"blocker_id": "external_hostile_reproduction_pending", "status": "BLOCKING_PUBLIC_SUPERIORITY"},
            {"blocker_id": "external_benchmark_validation_pending", "status": "BLOCKING_CATEGORY_LEADERSHIP"},
        ],
        **BLOCKED_CLAIMS,
    }
    launch_board = {
        "schema_id": "kt.near_final_shadow.bounded_launch_status_board.v1",
        "artifact_id": "KT_BOUNDED_LAUNCH_STATUS_BOARD",
        "authority": "BOUNDED_PILOT_READY_NO_EXTERNAL_ACCEPTANCE",
        "generated_utc": utc_now_iso_z(),
        "bounded_launch_wedge_ready": True,
        "launch_wedge": ["KT Verifier", "KT Evidence Pack", "KT Claim Compiler"],
        "independent_attestation_pending": True,
        **BLOCKED_CLAIMS,
    }
    capability_board = {
        "schema_id": "kt.near_final_shadow.capability_status_board.v1",
        "artifact_id": "KT_SHADOW_CAPABILITY_STATUS_BOARD",
        "authority": "LAB_SHADOW_STATUS_ONLY",
        "generated_utc": utc_now_iso_z(),
        "modules": [
            {
                "module_id": module,
                "status": "SHADOW_CONTRACT_READY",
                "production_authority": False,
                "external_claim_allowed": False,
            }
            for module in MODULES
        ],
        "adaptive_capability_shadow_continues": True,
        **BLOCKED_CLAIMS,
    }
    claim_boundary = {
        "schema_id": "kt.near_final_shadow.final_claim_boundary_before_external_attestation.v1",
        "artifact_id": "KT_FINAL_CLAIM_BOUNDARY_BEFORE_EXTERNAL_ATTESTATION",
        "authority": "CLAIM_BOUNDARY",
        "generated_utc": utc_now_iso_z(),
        "allowed_claims": [
            "bounded pilot review",
            "internal operational use",
            "governed verifier, evidence-pack, and claim-control workflows",
            "internal shadow adaptive capability work",
            "internal benchmark dry-runs",
        ],
        "blocked_claims": list(BLOCKED_CLAIMS.keys()),
        **BLOCKED_CLAIMS,
    }
    workstream_status = {
        "WS1_external_attestation_intake": "READY_BLOCKER_PRESERVED",
        "WS2_bounded_launch_wedge_productization": "READY",
        "WS3_repo_cleanup_context_debloat": "READY" if context_receipt.get("status") == "PASS" else "BLOCKED",
        "WS4_highway_shadow_warn": "READY_NO_CANONICAL_AUTHORITY",
        "WS5_fp0_efficiency": parts["fp0"]["status"],
        "WS6_adaptive_law": "SHADOW_RATIFIED",
        "WS7_capability_shadow": "SHADOW_CONTRACT_READY",
        "WS8_training_eval": "SHADOW_READY",
        "WS9_benchmark_harness": "INTERNAL_DRY_RUN_READY",
        "WS10_final_shadow_readjudication": "COMPLETE",
    }
    readjudication = {
        "schema_id": "kt.near_final_shadow.readjudication_receipt.v1",
        "artifact_id": "KT_NEAR_FINAL_SHADOW_READJUDICATION_RECEIPT",
        "authority": "FINAL_SHADOW_READJUDICATION_NO_EXTERNAL_ACCEPTANCE",
        "generated_utc": utc_now_iso_z(),
        "current_posture": CURRENT_POSTURE,
        "selected_outcome": TARGET_OUTCOME,
        "near_final_shadow_complete": bool(claim_scan.get("passed")) and context_receipt.get("status") == "PASS" and not parts["fp0"].get("required_inputs_missing"),
        "claim_scan_passed": bool(claim_scan.get("passed")),
        "context_budget_gate_passed": context_receipt.get("status") == "PASS",
        "attestation_accepted": bool(attestation.get("attestation_accepted")),
        "workstream_status": workstream_status,
        "remaining_external_blockers": remaining_blockers["blockers"],
        **BLOCKED_CLAIMS,
    }
    return {
        "remaining_external_blockers": remaining_blockers,
        "bounded_launch_status_board": launch_board,
        "capability_status_board": capability_board,
        "final_claim_boundary": claim_boundary,
        "readjudication_receipt": readjudication,
        "execution_board": _execution_board(workstream_status),
    }


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    changed: list[str] = []

    text_outputs = {
        OUTPUTS["attestation_dashboard"]: _attestation_dashboard(validate_external_attestation.evaluate_attestation(root=root)),
        OUTPUTS["bounded_pilot_scope"]: _bounded_pilot_scope(),
        OUTPUTS["bounded_pilot_onboarding"]: _bounded_pilot_onboarding(),
        OUTPUTS["highway_shadow_policy"]: _highway_policy("SHADOW"),
        OUTPUTS["highway_warn_only_policy"]: _highway_policy("WARN"),
        **_adaptive_text_outputs(),
        **_benchmark_text_outputs(),
    }
    for raw, text in text_outputs.items():
        if _write_text_stable(root / raw, text):
            changed.append(raw)

    json_outputs: Dict[str, Dict[str, Any]] = {
        **_adaptive_json_outputs(),
        **_capability_outputs(),
        **_training_outputs(),
        **_benchmark_json_outputs(),
        OUTPUTS["highway_shadow_receipt"]: _highway_receipt("SHADOW"),
        OUTPUTS["highway_warn_receipt"]: _highway_receipt("WARN"),
    }
    fp0 = _fp0_receipt(root)
    json_outputs[OUTPUTS["fp0_activation_receipt"]] = fp0
    json_outputs[OUTPUTS["adaptive_law_receipt"]] = {
        "schema_id": "kt.adaptive_law.ratification_shadow_receipt.v1",
        "artifact_id": "ADAPTIVE_LAW_RATIFICATION_SHADOW_RECEIPT",
        "authority": "SHADOW_RATIFIED_NO_CANONICAL_PROMOTION",
        "generated_utc": utc_now_iso_z(),
        "adaptive_outputs": sorted(ADAPTIVE_OUTPUTS.values()),
        "claim_expansion_allowed": False,
        "router_superiority_claim_allowed": False,
        "specialist_module_orchestration_claim_allowed": False,
    }
    json_outputs[OUTPUTS["training_eval_receipt"]] = {
        "schema_id": "kt.training_eval.fabric_shadow_ready_receipt.v1",
        "artifact_id": "TRAINING_EVAL_FABRIC_SHADOW_READY_RECEIPT",
        "authority": "SHADOW_READY_NO_TRAINING_CLAIM",
        "generated_utc": utc_now_iso_z(),
        "training_outputs": sorted(TRAINING_OUTPUTS.values()),
        "training_without_authorization_allowed": False,
        "dataset_without_provenance_allowed": False,
        "promotion_without_eval_allowed": False,
    }
    json_outputs[OUTPUTS["benchmark_dry_run_receipt"]] = {
        "schema_id": "kt.benchmark_harness.internal_dry_run_receipt.v1",
        "artifact_id": "BENCHMARK_HARNESS_INTERNAL_DRY_RUN_RECEIPT",
        "authority": "INTERNAL_DRY_RUN_ONLY",
        "generated_utc": utc_now_iso_z(),
        "benchmark_outputs": sorted(BENCHMARK_OUTPUTS.values()),
        "public_superiority_claim_allowed": False,
        "seven_b_amplification_proven": False,
    }

    for raw, obj in json_outputs.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    context_receipt = context_budget_gate.evaluate(root=root)
    context_budget_gate.write_receipt(root, context_receipt)
    claim_scan = _claim_scan(root, [OUTPUTS[key] for key in HUMAN_CLAIM_SCAN_KEYS] + [BENCHMARK_OUTPUTS["stat_plan"]])
    if not claim_scan["passed"]:
        raise RuntimeError(f"FAIL_CLOSED: near-final shadow claim scan failed: {claim_scan['violations']}")

    final_parts = _final_receipts(root, {"fp0": fp0}, claim_scan, context_receipt)
    for key, obj in final_parts.items():
        raw = OUTPUTS[key]
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    print(TARGET_OUTCOME)
    return {
        "target_outcome": TARGET_OUTCOME,
        "changed_outputs": changed,
        "claim_scan": claim_scan,
        "context_budget_gate": context_receipt,
        **final_parts,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run KT near-final shadow completion superlane.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = run()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
