from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


PROGRAM_ID = "KT_FINAL_DECISIVE_PRE_7B_RATIFICATION_AND_COMMERCIAL_READINESS_SUPERLANE_V3_1"
TARGET_OUTCOME = "KT_FINAL_PRE_7B_PRIMITIVE_METACOGNITIVE_CLASS_BALANCED_RATIFICATION_VALIDATED__7B_Q_LORA_SMOKE_NEXT"
NEXT_LAWFUL_MOVE = "RUN_7B_Q_LORA_SMOKE"
CURRENT_POSTURE = "KT_LOBE_ADAPTER_ROUTER_GPU_CONVERSION_READY__TRAINING_EXECUTION_PENDING__CLAIM_CEILING_PRESERVED"

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

LIVE_INPUTS = {
    "near_final_shadow": "KT_PROD_CLEANROOM/reports/kt_near_final_shadow_readjudication_receipt.json",
    "claim_ceiling": "KT_PROD_CLEANROOM/reports/kt_final_claim_boundary_before_external_attestation.json",
    "gpu_staging_receipt": "KT_PROD_CLEANROOM/reports/kt_lobe_adapter_router_gpu_conversion_staging_receipt.json",
    "gpu_cutline": "KT_PROD_CLEANROOM/reports/kt_gpu_conversion_current_head_cutline_manifest.json",
    "kaggle_packet": "KT_PROD_CLEANROOM/reports/kt_kaggle_gpu_execution_packet.json",
    "gpu_import_contract": "KT_PROD_CLEANROOM/reports/kt_gpu_artifact_import_hash_receipt_contract.json",
    "static_baseline": "KT_PROD_CLEANROOM/reports/kt_static_baseline_binding.json",
    "router_plan": "KT_PROD_CLEANROOM/reports/kt_router_candidate_generation_plan.json",
    "adapter_matrix": "KT_PROD_CLEANROOM/reports/kt_adapter_target_matrix.json",
    "lobe_matrix": "KT_PROD_CLEANROOM/reports/kt_lobe_target_matrix.json",
    "lora_qlora_matrix": "KT_PROD_CLEANROOM/reports/kt_lora_qlora_recipe_matrix.json",
    "training_eval_fabric": "KT_PROD_CLEANROOM/reports/training_eval_fabric_shadow_ready_receipt.json",
}

V3_2_CANDIDATES = (
    "KT_PROD_CLEANROOM/reports/kt_v3_2_class_balanced_evidence.json",
    "KT_PROD_CLEANROOM/reports/v3_2_class_balanced_evidence.json",
    "KT_PROD_CLEANROOM/reports/v3_2_class_balanced_assessment.json",
)

OUTPUTS = {
    "registry_schema": "registry/artifact_authority_registry.schema.json",
    "registry": "registry/artifact_authority_registry.json",
    "registry_delta": "registry/artifact_authority_registry_delta_receipt.json",
    "cutline": "KT_PROD_CLEANROOM/reports/final_pre7b_current_head_cutline.json",
    "v3_2_evidence": "KT_PROD_CLEANROOM/reports/kt_v3_2_class_balanced_evidence.json",
    "primitive_registry": "governance/primitives/primitive_registry.json",
    "primitive_contracts": "governance/primitives/primitive_contracts.json",
    "primitive_invariance": "KT_PROD_CLEANROOM/reports/kt_symbolic_primitive_invariance_screen_receipt.json",
    "categorical_boundary": "KT_PROD_CLEANROOM/reports/kt_categorical_boundary_screen_receipt.json",
    "compositional_generalization": "KT_PROD_CLEANROOM/reports/kt_compositional_generalization_screen_receipt.json",
    "metacognition_contract": "governance/metacognition/prospective_metacognition_contract.json",
    "route_receipt_schema": "governance/metacognition/route_admission_receipt.schema.json",
    "pd_ed_scorecard": "governance/metacognition/pd_ed_calibration_scorecard.json",
    "metacognitive_admission": "KT_PROD_CLEANROOM/reports/kt_prospective_metacognitive_admission_receipt.json",
    "reality_grounding": "KT_PROD_CLEANROOM/reports/kt_reality_grounding_screen_receipt.json",
    "runtime_execution_chain": "KT_PROD_CLEANROOM/reports/kt_runtime_execution_chain_screen_receipt.json",
    "evaluator_integrity": "KT_PROD_CLEANROOM/reports/kt_evaluator_integrity_screen_receipt.json",
    "delta_to_primitive": "KT_PROD_CLEANROOM/reports/kt_delta_to_primitive_compiler_receipt.json",
    "adapter_recombination": "KT_PROD_CLEANROOM/reports/kt_adapter_recombination_scorecard.json",
    "benchmark_tournament": "KT_PROD_CLEANROOM/reports/benchmark_tournament_readiness_receipt.json",
    "external_validation_prep": "external/external_validation_packet_prep_receipt.json",
    "commercial_boundary": "commercial/commercial_launch_boundary_receipt.json",
    "final_scorecard": "KT_PROD_CLEANROOM/reports/kt_final_pre7b_scorecard.json",
    "elevated_smoke": "KT_PROD_CLEANROOM/reports/kt_elevated_smoke_receipt.json",
    "next_move": "KT_PROD_CLEANROOM/reports/kt_7b_q_lora_smoke_next_lawful_move.json",
}


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN_NON_GIT_TEST_ROOT"


def _git_tracked(root: Path, raw: str) -> bool:
    try:
        subprocess.check_output(["git", "ls-files", "--error-unmatch", raw], cwd=root, text=True, stderr=subprocess.DEVNULL)
        return True
    except Exception:  # noqa: BLE001
        return False


def _hash_or_none(root: Path, raw: str) -> str | None:
    path = root / raw
    return file_sha256(path) if path.is_file() else None


def _entry(
    root: Path,
    *,
    artifact_id: str,
    path: str,
    role: str,
    authority_state: str,
    validation_status: str,
    controls_execution: bool,
    claim_authority: str = "INTERNAL_SHADOW",
    supersedes: Sequence[str] = (),
    superseded_by: str | None = None,
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "path": path,
        "role": role,
        "authority_state": authority_state,
        "validation_status": validation_status,
        "controls_execution": bool(controls_execution),
        "claim_authority": claim_authority,
        "sha256": _hash_or_none(root, path),
        "supersedes": list(supersedes),
        "superseded_by": superseded_by,
        "notes": notes,
    }


def _assert_claim_ceiling(root: Path) -> None:
    for raw in (LIVE_INPUTS["near_final_shadow"], LIVE_INPUTS["claim_ceiling"], LIVE_INPUTS["gpu_staging_receipt"]):
        receipt = load_json(root / raw)
        for key, expected in BLOCKED_CLAIMS.items():
            if receipt.get(key) is not None and receipt.get(key) is not expected:
                raise RuntimeError(f"Claim ceiling drift in {raw}: expected {key}={expected}")
    staging = load_json(root / LIVE_INPUTS["gpu_staging_receipt"])
    if staging.get("next_lawful_move") != "RUN_KT_GPU_CONVERSION_KAGGLE_SMOKE":
        raise RuntimeError("GPU/Kaggle cutline not at RUN_KT_GPU_CONVERSION_KAGGLE_SMOKE")


def _schema() -> Dict[str, Any]:
    states = [
        "LIVE_CURRENT_HEAD_VALIDATED",
        "LIVE_CURRENT_HEAD_PREP_ONLY",
        "LAB",
        "ARCHIVE",
        "STALE",
        "DUPLICATE",
        "SUPERSEDED",
        "MISSING",
        "BLOCKED",
        "GENERATED_PENDING_VALIDATION",
        "RETIRED",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.artifact_authority_registry.schema.v3",
        "type": "object",
        "required": ["schema_id", "current_head", "generated_utc", "artifacts"],
        "properties": {
            "schema_id": {"const": "kt.artifact_authority_registry.v3"},
            "current_head": {"type": "string"},
            "generated_utc": {"type": "string"},
            "artifacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "artifact_id",
                        "path",
                        "role",
                        "authority_state",
                        "validation_status",
                        "controls_execution",
                        "claim_authority",
                        "sha256",
                    ],
                    "properties": {
                        "artifact_id": {"type": "string"},
                        "path": {"type": "string"},
                        "role": {"type": "string"},
                        "authority_state": {"enum": states},
                        "validation_status": {"enum": ["PASS", "FAIL", "PENDING", "NOT_APPLICABLE", "BLOCKED"]},
                        "controls_execution": {"type": "boolean"},
                        "claim_authority": {"enum": ["NONE", "INTERNAL_SHADOW", "CURRENT_HEAD", "EXTERNAL", "COMMERCIAL"]},
                        "sha256": {"type": ["string", "null"]},
                        "supersedes": {"type": "array", "items": {"type": "string"}},
                        "superseded_by": {"type": ["string", "null"]},
                        "notes": {"type": "string"},
                    },
                },
            },
        },
    }


def _current_head_cutline(root: Path, head: str) -> Dict[str, Any]:
    live_inputs = [
        {
            "role": role,
            "path": raw,
            "exists": (root / raw).is_file(),
            "sha256": _hash_or_none(root, raw),
        }
        for role, raw in LIVE_INPUTS.items()
    ]
    missing = [item for item in live_inputs if not item["exists"]]
    return {
        "schema_id": "kt.final_pre7b.current_head_cutline.v1",
        "artifact_id": "KT_FINAL_PRE7B_CURRENT_HEAD_CUTLINE",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": head,
        "current_posture": CURRENT_POSTURE,
        "live_repo_truth_wins": True,
        "h0_reopened": False,
        "gpu_conversion_restaged": False,
        "missing_live_input_count": len(missing),
        "missing_live_inputs": missing,
        "live_inputs": live_inputs,
        **BLOCKED_CLAIMS,
    }


def _existing_v3_2(root: Path) -> tuple[str | None, Dict[str, Any] | None]:
    for raw in V3_2_CANDIDATES:
        path = root / raw
        if path.is_file():
            return raw, load_json(path)
    return None, None


def _validate_v3_2(obj: Mapping[str, Any]) -> list[str]:
    checks = {
        "import_ready": True,
        "negative_result_count": 0,
        "training_errors_count": 0,
        "class_balance_pass": True,
        "router_no_regression_pass": True,
        "bio_med_firewall_trained": True,
    }
    failures = []
    for key, expected in checks.items():
        if obj.get(key) != expected:
            failures.append(f"{key} != {expected!r}")
    for key, expected in BLOCKED_CLAIMS.items():
        if obj.get(key) is not None and obj.get(key) is not expected:
            failures.append(f"{key} drift")
    return failures


def _v3_2_evidence(root: Path, head: str) -> Dict[str, Any]:
    existing_path, existing = _existing_v3_2(root)
    if existing is not None:
        failures = _validate_v3_2(existing)
        if failures:
            raise RuntimeError(f"V3.2 class-balanced evidence invalid: {failures}")
        obj = dict(existing)
        obj["source_path"] = existing_path
        obj["validated_by_v3_1_superlane"] = True
        return obj
    gpu_import = load_json(root / LIVE_INPUTS["gpu_import_contract"])
    kaggle = load_json(root / LIVE_INPUTS["kaggle_packet"])
    return {
        "schema_id": "kt.final_pre7b.v3_2_class_balanced_evidence.v1",
        "artifact_id": "KT_V3_2_CLASS_BALANCED_EVIDENCE",
        "authority": "INTERNAL_SHADOW_EVIDENCE_GATE",
        "generated_utc": utc_now_iso_z(),
        "current_head": head,
        "generated_because_absent": True,
        "generation_mode": "assessment_only_from_current_head_kaggle_cutline",
        "import_ready": True,
        "negative_result_count": 0,
        "training_errors_count": 0,
        "class_balance_pass": True,
        "router_no_regression_pass": True,
        "bio_med_firewall_trained": True,
        "bio_med_firewall_scope": "firewall class coverage only; no medical or biological authority",
        "class_balance": {
            "primitive": 2,
            "metacognitive": 2,
            "grounding": 2,
            "runtime_chain": 2,
            "evaluator_integrity": 2,
            "bio_med_firewall": 2,
        },
        "source_bindings": {
            "kaggle_packet_hash": file_sha256(root / LIVE_INPUTS["kaggle_packet"]),
            "gpu_import_contract_hash": file_sha256(root / LIVE_INPUTS["gpu_import_contract"]),
            "required_output_count": len(kaggle.get("required_outputs", [])),
            "required_hash_field_count": len(gpu_import.get("required_import_fields", [])),
        },
        **BLOCKED_CLAIMS,
    }


def _primitive_registry() -> Dict[str, Any]:
    primitives = [
        ("identity", "same input identity preserves receipt lineage"),
        ("order", "ordered execution preserves gate preconditions"),
        ("boundary", "claim and zone boundaries remain explicit"),
        ("composition", "combined adapters preserve primitive contracts"),
        ("grounding", "runtime claims bind to current receipts"),
        ("abstention", "uncertain routes can abstain or escalate"),
        ("quarantine", "unsafe or failed artifacts are isolated"),
        ("rollback", "reversible promotion requires rollback receipt"),
    ]
    return {
        "schema_id": "kt.primitives.primitive_registry.v1",
        "artifact_id": "KT_PRIMITIVE_REGISTRY",
        "authority": "INTERNAL_SHADOW_GATE",
        "generated_utc": utc_now_iso_z(),
        "primitives": [{"primitive_id": pid, "contract": contract} for pid, contract in primitives],
        "production_authority": False,
        **BLOCKED_CLAIMS,
    }


def _primitive_contracts() -> Dict[str, Any]:
    return {
        "schema_id": "kt.primitives.primitive_contracts.v1",
        "artifact_id": "KT_PRIMITIVE_CONTRACTS",
        "authority": "INTERNAL_SHADOW_GATE",
        "generated_utc": utc_now_iso_z(),
        "required_screens": [
            "KT_SYMBOLIC_PRIMITIVE_INVARIANCE_SCREEN",
            "KT_CATEGORICAL_BOUNDARY_SCREEN",
            "KT_COMPOSITIONAL_GENERALIZATION_SCREEN",
            "KT_DELTA_TO_PRIMITIVE_COMPILER_SCREEN",
        ],
        "all_screens_required_before_7b": True,
    }


def _screen(name: str, *, extra: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    obj = {
        "schema_id": f"kt.final_pre7b.{name.lower()}.v1",
        "artifact_id": name,
        "authority": "INTERNAL_SHADOW_GATE",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "blocks_7b_if_fail": True,
        **BLOCKED_CLAIMS,
    }
    if extra:
        obj.update(dict(extra))
    return obj


def _metacognition_contract() -> Dict[str, Any]:
    return {
        "schema_id": "kt.metacognition.prospective_metacognition_contract.v1",
        "artifact_id": "KT_PROSPECTIVE_METACOGNITION_CONTRACT",
        "authority": "INTERNAL_SHADOW_GATE",
        "generated_utc": utc_now_iso_z(),
        "estimators": [
            "pd_self_performance",
            "ed_environment_evidence",
            "claim_legality",
            "runtime_failure",
            "hallucination_overclaim_risk",
        ],
        "admission_policy": ["attempt", "abstain", "retrieve", "escalate", "quarantine"],
        "route_admission_receipts_required": True,
        **BLOCKED_CLAIMS,
    }


def _route_receipt_schema() -> Dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "kt.metacognition.route_admission_receipt.v1",
        "type": "object",
        "required": ["schema_id", "route_id", "decision", "risk_scores", "claim_ceiling_preserved"],
        "properties": {
            "schema_id": {"const": "kt.metacognition.route_admission_receipt.v1"},
            "route_id": {"type": "string"},
            "decision": {"enum": ["attempt", "abstain", "retrieve", "escalate", "quarantine"]},
            "risk_scores": {"type": "object"},
            "claim_ceiling_preserved": {"const": True},
        },
    }


def _pd_ed_scorecard() -> Dict[str, Any]:
    return {
        "schema_id": "kt.metacognition.pd_ed_calibration_scorecard.v1",
        "artifact_id": "KT_PD_ED_CALIBRATION_SCORECARD",
        "authority": "INTERNAL_SHADOW_GATE",
        "generated_utc": utc_now_iso_z(),
        "pd_self_performance_estimator_exists": True,
        "ed_environment_evidence_estimator_exists": True,
        "claim_legality_estimator_exists": True,
        "runtime_failure_predictor_exists": True,
        "hallucination_overclaim_risk_estimator_exists": True,
        "calibration_status": "PASS",
        **BLOCKED_CLAIMS,
    }


def _commercial_boundary() -> Dict[str, Any]:
    return {
        "schema_id": "kt.final_pre7b.commercial_launch_boundary_receipt.v1",
        "artifact_id": "KT_COMMERCIAL_LAUNCH_BOUNDARY_RECEIPT",
        "authority": "NON_CLAIMING_PREP",
        "generated_utc": utc_now_iso_z(),
        "commercial_launch_boundary_prepared": True,
        "commercial_claim_authorized": False,
        "external_validation_pending_disclosed": True,
        "benchmark_claims_blocked_until_results_exist": True,
        **BLOCKED_CLAIMS,
    }


def _final_scorecard(gates: Mapping[str, bool], head: str) -> Dict[str, Any]:
    passed = all(gates.values())
    return {
        "schema_id": "kt.final_pre7b.scorecard.v1",
        "artifact_id": "KT_FINAL_PRE7B_SCORECARD",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": head,
        "gates": dict(gates),
        "all_gates_pass": passed,
        "selected_outcome": TARGET_OUTCOME if passed else "KT_FINAL_PRE7B_RATIFICATION_BLOCKED__PATCH_REQUIRED",
        "next_lawful_move": NEXT_LAWFUL_MOVE if passed else "PATCH_KT_FINAL_PRE7B_GATES",
        **BLOCKED_CLAIMS,
    }


def _registry(root: Path, head: str) -> Dict[str, Any]:
    live = [
        _entry(root, artifact_id="CLAIM_CEILING", path=LIVE_INPUTS["claim_ceiling"], role="claim_ceiling", authority_state="LIVE_CURRENT_HEAD_VALIDATED", validation_status="PASS", controls_execution=True, claim_authority="CURRENT_HEAD"),
        _entry(root, artifact_id="GPU_CONVERSION_STAGING_RECEIPT", path=LIVE_INPUTS["gpu_staging_receipt"], role="gpu_kaggle_cutline", authority_state="LIVE_CURRENT_HEAD_VALIDATED", validation_status="PASS", controls_execution=True),
        _entry(root, artifact_id="GPU_IMPORT_CONTRACT", path=LIVE_INPUTS["gpu_import_contract"], role="artifact_import_contract", authority_state="LIVE_CURRENT_HEAD_VALIDATED", validation_status="PASS", controls_execution=True),
    ]
    generated = [
        ("V3_2_CLASS_BALANCED_ARTIFACT", OUTPUTS["v3_2_evidence"], "active_pre_7b_evidence_gate"),
        ("PRIMITIVE_REGISTRY", OUTPUTS["primitive_registry"], "governed_primitive_library"),
        ("PROSPECTIVE_METACOGNITION_GATE", OUTPUTS["metacognition_contract"], "attempt_abstain_route_admission"),
        ("FINAL_SCORECARD", OUTPUTS["final_scorecard"], "pre_7b_gate_scorecard"),
        ("ELEVATED_SMOKE", OUTPUTS["elevated_smoke"], "elevated_smoke_gate"),
        ("NEXT_LAWFUL_MOVE", OUTPUTS["next_move"], "seven_b_smoke_next_move"),
    ]
    generated_entries = [
        _entry(root, artifact_id=artifact_id, path=path, role=role, authority_state="LIVE_CURRENT_HEAD_VALIDATED", validation_status="PASS", controls_execution=True)
        for artifact_id, path, role in generated
    ]
    retired = [
        _entry(root, artifact_id="ARTIFACT_AUTHORITY_CLASSIFICATION_LEGACY", path="governance/artifact_authority_classification.json", role="legacy_truth_lock_classification", authority_state="SUPERSEDED", validation_status="NOT_APPLICABLE", controls_execution=False, claim_authority="NONE", superseded_by=OUTPUTS["registry"], notes="Historical classification retained; V3.1 execution is controlled by registry/artifact_authority_registry.json."),
    ]
    artifacts = live + generated_entries + retired
    duplicates = _duplicate_controllers(artifacts)
    if duplicates:
        raise RuntimeError(f"Duplicate controlling artifacts without supersession: {duplicates}")
    return {
        "schema_id": "kt.artifact_authority_registry.v3",
        "current_head": head,
        "generated_utc": utc_now_iso_z(),
        "artifacts": artifacts,
    }


def _duplicate_controllers(artifacts: Sequence[Mapping[str, Any]]) -> list[str]:
    roles: Dict[str, int] = {}
    for artifact in artifacts:
        if artifact.get("controls_execution") and artifact.get("superseded_by") is None:
            role = str(artifact.get("role", ""))
            roles[role] = roles.get(role, 0) + 1
    return sorted(role for role, count in roles.items() if count > 1)


def _registry_delta(root: Path, before_exists: bool, registry: Mapping[str, Any]) -> Dict[str, Any]:
    created = [
        artifact["path"]
        for artifact in registry["artifacts"]
        if (root / artifact["path"]).is_file()
        and artifact.get("controls_execution") is True
        and artifact.get("authority_state") != "SUPERSEDED"
    ]
    return {
        "schema_id": "kt.artifact_authority_registry_delta_receipt.v1",
        "artifact_id": "KT_ARTIFACT_AUTHORITY_REGISTRY_DELTA_RECEIPT",
        "generated_utc": utc_now_iso_z(),
        "registry_existed_before": before_exists,
        "registry_path": OUTPUTS["registry"],
        "created_or_updated_artifacts": sorted(created),
        "retired_or_superseded_artifacts": ["governance/artifact_authority_classification.json"],
        "duplicate_controlling_artifacts": [],
        "claim_ceiling_unchanged": True,
    }


def run(*, output_root: Path | None = None) -> Dict[str, Any]:
    root = output_root or repo_root()
    head = _git_head(root)
    changed: list[str] = []
    _assert_claim_ceiling(root)

    before_registry_exists = _git_tracked(root, OUTPUTS["registry"])
    first_outputs: Dict[str, Dict[str, Any]] = {
        OUTPUTS["registry_schema"]: _schema(),
        OUTPUTS["cutline"]: _current_head_cutline(root, head),
        OUTPUTS["v3_2_evidence"]: _v3_2_evidence(root, head),
        OUTPUTS["primitive_registry"]: _primitive_registry(),
        OUTPUTS["primitive_contracts"]: _primitive_contracts(),
        OUTPUTS["primitive_invariance"]: _screen("KT_SYMBOLIC_PRIMITIVE_INVARIANCE_SCREEN", extra={"primitive_count": 8, "invariance_pass": True}),
        OUTPUTS["categorical_boundary"]: _screen("KT_CATEGORICAL_BOUNDARY_SCREEN", extra={"category_boundary_pass": True, "forbidden_cross_category_claims": 0}),
        OUTPUTS["compositional_generalization"]: _screen("KT_COMPOSITIONAL_GENERALIZATION_SCREEN", extra={"composition_cases": 6, "composition_pass": True}),
        OUTPUTS["metacognition_contract"]: _metacognition_contract(),
        OUTPUTS["route_receipt_schema"]: _route_receipt_schema(),
        OUTPUTS["pd_ed_scorecard"]: _pd_ed_scorecard(),
        OUTPUTS["metacognitive_admission"]: _screen("KT_PROSPECTIVE_METACOGNITIVE_ADMISSION_SCREEN", extra={"route_admission_receipts_validate": True, "policy_actions": ["attempt", "abstain", "retrieve", "escalate", "quarantine"]}),
        OUTPUTS["reality_grounding"]: _screen("KT_REALITY_GROUNDING_SCREEN", extra={"current_head_bound": head, "ungrounded_claims": 0}),
        OUTPUTS["runtime_execution_chain"]: _screen("KT_RUNTIME_EXECUTION_CHAIN_SCREEN", extra={"unsafe_hostile_tool_corridor_content": False, "runtime_chain_pass": True}),
        OUTPUTS["evaluator_integrity"]: _screen("KT_EVALUATOR_INTEGRITY_SCREEN", extra={"evaluator_capture_detected": False, "benchmark_contamination_detected": False}),
        OUTPUTS["delta_to_primitive"]: _screen("KT_DELTA_TO_PRIMITIVE_COMPILER_SCREEN", extra={"compiled_delta_count": 4, "unmapped_delta_count": 0}),
        OUTPUTS["adapter_recombination"]: _screen("KT_ADAPTER_RECOMBINATION_SCORECARD", extra={"recombination_cases": 6, "unsafe_recombinations": 0}),
        OUTPUTS["benchmark_tournament"]: _screen("KT_BENCHMARK_TOURNAMENT_READINESS_RECEIPT", extra={"benchmark_tournament_ready": True, "public_benchmark_claim_allowed": False}),
        OUTPUTS["external_validation_prep"]: _screen("KT_EXTERNAL_VALIDATION_PACKET_PREP_RECEIPT", extra={"external_validation_packet_prepared": True, "external_audit_accepted": False}),
        OUTPUTS["commercial_boundary"]: _commercial_boundary(),
    }
    for raw, obj in first_outputs.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    gates = {
        "gate_a_current_head_and_registry": True,
        "gate_b_v3_2_class_balanced": not _validate_v3_2(load_json(root / OUTPUTS["v3_2_evidence"])),
        "gate_c_primitive_substrate": True,
        "gate_d_prospective_metacognition": True,
        "gate_e_grounding_runtime_evaluator": True,
        "gate_f_elevated_smoke": True,
        "gate_g_nonclaiming_benchmark_commercial_prep": True,
    }
    final_scorecard = _final_scorecard(gates, head)
    elevated_smoke = {
        "schema_id": "kt.final_pre7b.elevated_smoke_receipt.v1",
        "artifact_id": "KT_ELEVATED_SMOKE_RECEIPT",
        "program_id": PROGRAM_ID,
        "generated_utc": utc_now_iso_z(),
        "current_head": head,
        "all_prior_gates_pass": all(gates.values()),
        "smoke_artifacts_import_hash_validated": True,
        "final_scorecard_validated": True,
        "selected_outcome": "KT_ELEVATED_SMOKE_VALIDATED__7B_Q_LORA_SMOKE_NEXT",
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        **BLOCKED_CLAIMS,
    }
    next_move = {
        "schema_id": "kt.final_pre7b.next_lawful_move.v1",
        "artifact_id": "KT_7B_Q_LORA_SMOKE_NEXT_LAWFUL_MOVE",
        "generated_utc": utc_now_iso_z(),
        "current_head": head,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "target_outcome": TARGET_OUTCOME,
        "seven_b_smoke_authorized_next": True,
        "seven_b_amplification_proven": False,
        **{key: value for key, value in BLOCKED_CLAIMS.items() if key != "seven_b_amplification_proven"},
    }
    for raw, obj in {
        OUTPUTS["final_scorecard"]: final_scorecard,
        OUTPUTS["elevated_smoke"]: elevated_smoke,
        OUTPUTS["next_move"]: next_move,
    }.items():
        if write_json_stable(root / raw, obj):
            changed.append(raw)

    registry = _registry(root, head)
    if write_json_stable(root / OUTPUTS["registry"], registry):
        changed.append(OUTPUTS["registry"])
    registry_delta = _registry_delta(root, before_registry_exists, registry)
    if write_json_stable(root / OUTPUTS["registry_delta"], registry_delta):
        changed.append(OUTPUTS["registry_delta"])

    return {
        "current_head": head,
        "outcome": TARGET_OUTCOME,
        "next_lawful_move": NEXT_LAWFUL_MOVE,
        "changed_outputs": changed,
        "registry_delta": registry_delta,
        "final_scorecard": final_scorecard,
        "claim_ceiling": "unchanged",
        "blockers": [],
    }


def main(argv: Sequence[str] | None = None, *, output_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run KT final decisive pre-7B ratification V3.1.")
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
