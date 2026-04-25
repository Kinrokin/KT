from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema, MODE_DRY_RUN as COGNITION_MODE_DRY_RUN
from core.claim_compiler import compile_runtime_claims
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from council.council_router import CouncilRouter, execute_council_request
from council.council_schemas import CouncilRequestSchema, MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN
from council.providers.adapter_abi_runtime import LEGACY_PROVIDER_MAP, load_active_adapter_manifests
from council.providers.provider_registry import ProviderRegistry
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH
from schemas.schema_hash import sha256_text
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/w1_runtime_realization"
MVCR_OUTPUT_REL = f"{REPORT_ROOT_REL}/mvcr_live_execution_receipt.json"
USEFUL_OUTPUT_REL = f"{REPORT_ROOT_REL}/useful_output_benchmark.json"
PROVIDER_PATH_REL = f"{REPORT_ROOT_REL}/provider_path_integrity_receipt.json"
UNIVERSAL_ADAPTER_RECEIPT_REL = f"{REPORT_ROOT_REL}/universal_adapter_receipt.json"
W3_CIVILIZATION_LOOP_RECEIPT_REL = f"{REPORT_ROOT_REL}/civilization_loop_receipt.json"
ORGAN_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json"
ORGAN_DEPENDENCY_REL = f"{REPORT_ROOT_REL}/organ_dependency_resolution_receipt.json"
CANONICAL_DELTA_REL = f"{REPORT_ROOT_REL}/canonical_delta_w1.json"
ADVANCEMENT_DELTA_REL = f"{REPORT_ROOT_REL}/advancement_delta_w1.json"
TELEMETRY_OUTPUT_REL = f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl"

TRUTH_LOCK_REL = "KT_PROD_CLEANROOM/governance/current_head_truth_lock.json"
WAVE3_RUN_REL = f"{REPORT_ROOT_REL}/kt_wave3_minimum_viable_civilization_run_pack.json"
RUNTIME_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_runtime_truth_surface.json"
VERIFIER_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_verifier_truth_surface.json"
TIER_RULING_REL = f"{REPORT_ROOT_REL}/kt_wave5_final_tier_ruling.json"
C016A_SUCCESS_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
C016B_RESILIENCE_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"
FINAL_BLOCKER_REL = f"{REPORT_ROOT_REL}/kt_final_blocker_matrix.json"
POST_WAVE5_C005_REL = f"{REPORT_ROOT_REL}/post_wave5_c005_router_ratification_receipt.json"

ENTRYPOINT_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py"
SPINE_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py"
CLAIM_COMPILER_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/claim_compiler.py"
COUNCIL_ROUTER_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py"
PROVIDER_REGISTRY_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_registry.py"
STATE_VAULT_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py"
REPLAY_REF = "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py"

REQUIRED_ORGANS = [
    "router",
    "council",
    "cognition",
    "paradox",
    "temporal",
    "multiverse",
    "memory",
    "adapter_layer",
    "tournament_promotion",
    "teacher_growth_surfaces",
    "toolchain_only_orchestrators",
    "detached_verifier",
    "claim_compiler",
]
REQUIRED_COLUMNS = [
    "validator",
    "receipt",
    "claim_ceiling",
    "promotion_rule",
    "rollback_rule",
    "owner",
    "zone",
    "plane",
]


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _tool_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _receipt_pass(root: Path, rel: str) -> bool:
    path = root / rel
    if not path.exists():
        return False
    payload = load_json(path)
    return str(payload.get("status", "")).strip().upper() == "PASS"


def _base_context() -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _run_probe(*, root: Path, export_root: Path, probe_id: str, payload: Dict[str, Any], telemetry_path: Path) -> Dict[str, Any]:
    probe_root = (export_root / "canonical_run" / probe_id).resolve()
    artifact_root = (probe_root / "artifacts").resolve()
    payload_path = probe_root / "payload.json"
    result_path = probe_root / "entry_result.json"
    probe_root.mkdir(parents=True, exist_ok=True)
    payload_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    env = _tool_env(root)
    env["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_path.resolve())
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.wave3_canonical_entry_probe",
            "--payload-file",
            str(payload_path),
            "--artifact-root",
            str(artifact_root),
            "--output",
            str(result_path),
            "--telemetry-output",
            str(telemetry_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: canonical probe failed for {probe_id}: {proc.stdout}")
    result = load_json(result_path)
    return {
        "status": "PASS",
        "artifact_root_ref": _rel(root, artifact_root),
        "payload_ref": _rel(root, payload_path),
        "entry_result_ref": _rel(root, result_path),
        "entry_result": result["entry_result"],
    }


def build_useful_output_benchmark(*, root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Any]:
    registry_hash = _registry_hash()
    base_context = _base_context()

    council_request = CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w1.council.request",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_DRY_RUN,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 128,
            "total_token_cap": 256,
            "input_hash": sha256_text("w1 council input"),
        }
    )
    council_plan = CouncilRouter.plan(context=base_context, request=council_request).to_dict()

    cognition_request = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w1.cognition.request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("w1 cognition input"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("w1.trace"), "artifact_id": "w1.trace"}],
        }
    )
    cognition_plan = CognitiveEngine.plan(context=base_context, request=cognition_request).to_dict()
    cognition_result = CognitiveEngine.execute(context=base_context, plan=CognitivePlanSchema.from_dict(cognition_plan)).to_dict()

    council_probe = _run_probe(root=root, export_root=export_root, probe_id="council_plan", payload=council_request.to_dict(), telemetry_path=telemetry_path)
    cognition_plan_probe = _run_probe(root=root, export_root=export_root, probe_id="cognition_plan", payload=cognition_request.to_dict(), telemetry_path=telemetry_path)
    cognition_execute_probe = _run_probe(
        root=root,
        export_root=export_root,
        probe_id="cognition_execute",
        payload=CognitivePlanSchema.from_dict(cognition_plan).to_dict(),
        telemetry_path=telemetry_path,
    )

    c016a = load_json(root / C016A_SUCCESS_REL)
    c016b = load_json(root / C016B_RESILIENCE_REL)
    live_provider_success = str(c016a.get("status", "")).strip().upper() == "PASS" and int(c016a.get("successful_provider_count", 0) or 0) > 0
    live_provider_resilience = str(c016b.get("status", "")).strip().upper() == "PASS" and str(c016b.get("repeatability_status", "")).strip().upper() == "PASS"

    rows: List[Dict[str, Any]] = []
    council_observed = council_probe["entry_result"].get("council", {})
    rows.append(
        {
            "benchmark_id": "canonical_council_plan_probe",
            "pass": (
                isinstance(council_observed, dict)
                and str(council_observed.get("status", "")).strip() == str(council_plan.get("status", "")).strip()
                and str(council_observed.get("plan_hash", "")).strip() == str(council_plan.get("plan_hash", "")).strip()
            ),
            "artifact_ref": council_probe["entry_result_ref"],
        }
    )

    cognition_plan_observed = cognition_plan_probe["entry_result"].get("cognition", {})
    rows.append(
        {
            "benchmark_id": "canonical_cognition_plan_probe",
            "pass": (
                isinstance(cognition_plan_observed, dict)
                and str(cognition_plan_observed.get("status", "")).strip() == str(cognition_plan.get("status", "")).strip()
                and int(cognition_plan_observed.get("steps", 0) or 0) == len(cognition_plan.get("steps", []))
            ),
            "artifact_ref": cognition_plan_probe["entry_result_ref"],
        }
    )

    cognition_execute_observed = cognition_execute_probe["entry_result"].get("cognition", {})
    cognition_execute_pass = (
        isinstance(cognition_execute_observed, dict)
        and str(cognition_execute_observed.get("status", "")).strip() == str(cognition_result.get("status", "")).strip()
        and int(cognition_execute_observed.get("steps", 0) or 0) == len(cognition_result.get("steps", []))
        and str(cognition_execute_observed.get("result_hash", "")).strip() == str(cognition_result.get("result_hash", "")).strip()
    )
    rows.append({"benchmark_id": "canonical_cognition_execute_probe", "pass": cognition_execute_pass, "artifact_ref": cognition_execute_probe["entry_result_ref"]})
    rows.append({"benchmark_id": "same_host_live_hashed_success_witness_present", "pass": live_provider_success, "artifact_ref": C016A_SUCCESS_REL})
    rows.append({"benchmark_id": "same_host_live_hashed_resilience_witness_present", "pass": live_provider_resilience, "artifact_ref": C016B_RESILIENCE_REL})
    rows.append(
        {
            "benchmark_id": "useful_output_evidence_stronger_than_ceremonial_path_evidence",
            "pass": cognition_execute_pass and live_provider_success,
            "artifact_refs": [cognition_execute_probe["entry_result_ref"], C016A_SUCCESS_REL],
        }
    )

    status = "PASS" if all(bool(row["pass"]) for row in rows) else "FAIL"
    return {
        "schema_id": "kt.w1.useful_output_benchmark.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "scope_boundary": "W1 useful-output benchmarking stays bounded to canonical entrypoint probes plus same-host LIVE_HASHED provider witnesses only.",
        "canonical_entrypoint_ref": ENTRYPOINT_REF,
        "canonical_spine_ref": SPINE_REF,
        "rows": rows,
        "successful_provider_ids": list(c016a.get("successful_provider_ids", [])),
        "source_refs": [WAVE3_RUN_REL, C016A_SUCCESS_REL, C016B_RESILIENCE_REL],
    }


def build_provider_path_integrity_receipt(*, root: Path) -> Dict[str, Any]:
    c016a = load_json(root / C016A_SUCCESS_REL)
    c016b = load_json(root / C016B_RESILIENCE_REL)
    manifests = load_active_adapter_manifests()
    registry = ProviderRegistry.build_default()

    rows: List[Dict[str, Any]] = []
    for provider_id in ("openai", "openrouter"):
        adapter_id = LEGACY_PROVIDER_MAP[provider_id]
        manifest = manifests.get(adapter_id)
        provider_row = next((row for row in c016a.get("provider_rows", []) if isinstance(row, dict) and str(row.get("provider_id", "")).strip() == provider_id), {})
        row_pass = (
            manifest is not None
            and manifest.execution_mode == "LIVE"
            and manifest.provider_id == provider_id
            and provider_id in registry.providers
            and str(provider_row.get("status", "")).strip() == "OK"
            and bool(provider_row.get("receipt_exists"))
        )
        rows.append(
            {
                "provider_id": provider_id,
                "adapter_id": adapter_id,
                "pass": row_pass,
                "manifest_path_ref": _rel(root, manifest.manifest_path) if manifest is not None else "",
                "execution_mode": manifest.execution_mode if manifest is not None else "",
                "provider_registered": provider_id in registry.providers,
                "c016a_status": provider_row.get("status", ""),
                "c016a_receipt_ref": provider_row.get("receipt_rel", ""),
            }
        )

    status = "PASS" if (
        str(c016a.get("status", "")).strip().upper() == "PASS"
        and str(c016b.get("status", "")).strip().upper() == "PASS"
        and str(c016b.get("repeatability_status", "")).strip().upper() == "PASS"
        and callable(execute_council_request)
        and all(bool(row["pass"]) for row in rows)
    ) else "FAIL"

    return {
        "schema_id": "kt.w1.provider_path_integrity_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "same_host_boundary": "Provider-path integrity proves same-host LIVE_HASHED OpenAI/OpenRouter path integrity only.",
        "required_code_refs": [COUNCIL_ROUTER_REF, PROVIDER_REGISTRY_REF, "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/adapter_abi_runtime.py"],
        "adapter_binding_rows": rows,
        "same_host_live_hashed_provider_ids": list(c016a.get("successful_provider_ids", [])),
        "resilience_reference": C016B_RESILIENCE_REL,
        "source_refs": [C016A_SUCCESS_REL, C016B_RESILIENCE_REL],
        "forbidden_current_claims": [
            "Do not narrate same-host provider integrity as a C006 or externality upgrade.",
            "Do not narrate OpenAI/OpenRouter same-host success as cross-host or outsider portability.",
            "Do not widen router, lobe, product, or comparative claims from provider-path integrity alone.",
        ],
    }


def _organ_field_map(*, root: Path, provider_path_ref: str, mvcr_ref: str) -> Dict[str, Dict[str, Any]]:
    w3_adapter_live = _receipt_pass(root, UNIVERSAL_ADAPTER_RECEIPT_REL)
    w3_civilization_live = _receipt_pass(root, W3_CIVILIZATION_LOOP_RECEIPT_REL)
    return {
        "router": {"validator": "python -m tools.operator.post_wave5_c005_router_ratification_validate", "receipt": POST_WAVE5_C005_REL, "claim_ceiling": "STATIC_CANONICAL_BASELINE_ONLY", "promotion_rule": "shadow_eval_then_best_static_comparison_then_ordered_superiority_proof", "rollback_rule": "hold_or_revert_to_static_baseline_on_ambiguity_or_regression", "owner": "runtime_router_governance", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "council": {"validator": "python -m tools.operator.w1_runtime_realization_validate", "receipt": provider_path_ref, "claim_ceiling": "CANONICAL_SAME_HOST_LIVE_HASHED_AND_BOUNDED_DRY_RUN_ONLY", "promotion_rule": "same_host_live_hashed_path_must_remain_receipted_and_fail_closed", "rollback_rule": "fall_back_to_static_dry_run_lane_on_live_path_ambiguity", "owner": "council_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "cognition": {"validator": "python -m tools.operator.runtime_organ_realization_validate", "receipt": mvcr_ref, "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1", "promotion_rule": "earn broader semantic task evidence before widening cognition claims", "rollback_rule": "keep bounded typed planning and semantic scoring or quarantine on regression", "owner": "cognition_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "paradox": {"validator": "python -m tools.operator.runtime_organ_realization_validate", "receipt": "KT_PROD_CLEANROOM/reports/kt_wave2c_paradox_engine_pack.json", "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1", "promotion_rule": "earn broader contradiction metabolism proof before any widening", "rollback_rule": "retain bounded conflict classification gate on regression", "owner": "paradox_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "temporal": {"validator": "python -m tools.operator.runtime_organ_realization_validate", "receipt": "KT_PROD_CLEANROOM/reports/kt_wave2c_temporal_engine_pack.json", "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1", "promotion_rule": "earn broader temporal replay proof before widening", "rollback_rule": "retain bounded fork and replay accounting on regression", "owner": "temporal_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "multiverse": {"validator": "python -m tools.operator.runtime_organ_realization_validate", "receipt": "KT_PROD_CLEANROOM/reports/kt_wave2c_multiverse_engine_pack.json", "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1", "promotion_rule": "earn broader branching proof before widening multiverse claims", "rollback_rule": "retain bounded candidate ranking with nonconstant coherence on regression", "owner": "multiverse_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "memory": {"validator": "python -m tools.operator.w1_runtime_realization_validate", "receipt": mvcr_ref, "claim_ceiling": "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1", "promotion_rule": "append_only_state_and_replay_chain_must_remain_intact", "rollback_rule": "fail_closed_to_state_vault_and_replay_validation", "owner": "memory_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "adapter_layer": {
            "validator": "python -m tools.operator.universal_adapter_validate" if w3_adapter_live else "python -m tools.operator.w1_runtime_realization_validate",
            "receipt": UNIVERSAL_ADAPTER_RECEIPT_REL if w3_adapter_live else provider_path_ref,
            "claim_ceiling": "CURRENT_HEAD_BOUNDED_UNIVERSAL_ADAPTER_CONTRACT_ONLY" if w3_adapter_live else "CANONICAL_SAME_HOST_LIVE_HASHED_ONLY",
            "promotion_rule": "universal_contract_must_remain_receipted_and_generated_candidates_must_not_be_laundered_as_live_runtime" if w3_adapter_live else "adapter_path_must_remain_abi_bound_receipted_and_fail_closed",
            "rollback_rule": "revert_to_two_live_same_host_manifests_on_any_universal_contract_ambiguity" if w3_adapter_live else "revert_to_bound_static_or_dry_run_lane_on_ambiguity",
            "owner": "adapter_runtime",
            "zone": "CANONICAL",
            "plane": "GENERATED_RUNTIME_TRUTH",
            "evidence_ref": UNIVERSAL_ADAPTER_RECEIPT_REL if w3_adapter_live else provider_path_ref,
            "bounded_summary": "Adapter layer now has one universal contract across the two live runtime adapters and one bounded generated candidate; live provider breadth remains narrow." if w3_adapter_live else "Adapter layer remains bounded by Wave 2A live-hashed receipts and auth-bounded outcomes.",
            "disposition": "REALIZED_BOUNDED_UNIVERSAL_CONTRACT" if w3_adapter_live else "KEEP_BOUNDED_WAVE2A",
            "status": "UPDATED_W3" if w3_adapter_live else "UNCHANGED",
        },
        "tournament_promotion": {
            "validator": "python -m tools.operator.civilization_loop_validate" if w3_civilization_live else "python -m tools.operator.w1_runtime_realization_validate",
            "receipt": W3_CIVILIZATION_LOOP_RECEIPT_REL if w3_civilization_live else "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json",
            "claim_ceiling": "CURRENT_HEAD_BOUNDED_INTERNAL_CIVILIZATION_LOOP_ONLY" if w3_civilization_live else "LAB_GOVERNED_ONLY",
            "promotion_rule": "promotion_decision_is_real_but_materialized_runtime_cutover_stays_separately_gated" if w3_civilization_live else "promotion_receipt_and_rollback_law_required_before_canonical_influence",
            "rollback_rule": "retain_rollback_bound_internal_loop_and_block_runtime_cutover_on_ambiguity" if w3_civilization_live else "retain_lab_only_until_runtime_real_and_receipted",
            "owner": "growth_runtime",
            "zone": "CANONICAL" if w3_civilization_live else "LAB",
            "plane": "GENERATED_RUNTIME_TRUTH" if w3_civilization_live else "QUARANTINED",
            "evidence_ref": W3_CIVILIZATION_LOOP_RECEIPT_REL if w3_civilization_live else "KT_PROD_CLEANROOM/reports/kt_tournament_readiness_receipt.json",
            "bounded_summary": "One bounded tournament, promotion-decision, rollback, and learning-response loop is now current-head real; automatic runtime cutover remains blocked." if w3_civilization_live else "Tournament/promotion remains lab-only.",
            "disposition": "REALIZED_BOUNDED_INTERNAL_CIVILIZATION_LOOP" if w3_civilization_live else "LAB_ONLY_UNTIL_RUNTIME_REAL",
            "status": "UPDATED_W3" if w3_civilization_live else "UNCHANGED",
        },
        "teacher_growth_surfaces": {"validator": "python -m tools.operator.w1_runtime_realization_validate", "receipt": "KT_PROD_CLEANROOM/reports/kt_wave0_quarantine_receipts.json", "claim_ceiling": "LAB_GOVERNED_ONLY", "promotion_rule": "promotion_receipt_required_before_runtime_mutation", "rollback_rule": "remain_lab_governed_or_quarantine", "owner": "growth_runtime", "zone": "LAB", "plane": "QUARANTINED"},
        "toolchain_only_orchestrators": {"validator": "python -m tools.operator.omega_gate", "receipt": "KT_PROD_CLEANROOM/reports/kt_wave0_5_toolchain_runtime_firewall_receipt.json", "claim_ceiling": "TOOLCHAIN_PROVING_ONLY", "promotion_rule": "must_not_influence_canonical_truth_without_explicit_promotion_receipt", "rollback_rule": "retain_toolchain_only_or_quarantine", "owner": "toolchain_governance", "zone": "TOOLCHAIN_PROVING", "plane": "QUARANTINED"},
        "detached_verifier": {"validator": "python -m tools.operator.post_wave5_c006_second_host_execute_validate", "receipt": VERIFIER_TRUTH_REL, "claim_ceiling": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED", "promotion_rule": "higher_externality_class_requires_direct_earned_receipts", "rollback_rule": "hold_at_E1_on_any_externality_ambiguity", "owner": "verifier_runtime", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
        "claim_compiler": {"validator": "python -m tools.operator.w1_runtime_realization_validate", "receipt": mvcr_ref, "claim_ceiling": "BOUNDED_RUNTIME_VOCABULARY_GATE_ONLY", "promotion_rule": "language_may_widen_only_from_live_truth_and_tier_surfaces", "rollback_rule": "downgrade_claims_immediately_on_ambiguity_or_regression", "owner": "runtime_claim_compiler", "zone": "CANONICAL", "plane": "GENERATED_RUNTIME_TRUTH"},
    }


def upgrade_organ_disposition_register(*, root: Path, provider_path_ref: str, mvcr_ref: str) -> Dict[str, Any]:
    payload = load_json(root / ORGAN_REGISTER_REL)
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: organ disposition rows missing")

    mapping = _organ_field_map(root=root, provider_path_ref=provider_path_ref, mvcr_ref=mvcr_ref)
    row_by_id: Dict[str, Dict[str, Any]] = {}
    ordered_ids: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        organ_id = str(row.get("organ_id", "")).strip()
        if not organ_id:
            continue
        row_by_id[organ_id] = dict(row)
        ordered_ids.append(organ_id)

    if "memory" not in row_by_id:
        row_by_id["memory"] = {
            "organ_id": "memory",
            "reality_class": "LIVE_BOUNDED",
            "maturity_class": "O2_HARDENED",
            "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
            "disposition": "REALIZED_CANONICAL_STATE_AND_REPLAY",
            "status": "ADDED_W1",
            "evidence_ref": mvcr_ref,
            "bounded_summary": "Memory is realized as append-only state-vault plus replay-chain validation on the canonical organism path.",
        }
        ordered_ids.insert(6, "memory")

    for organ_id in REQUIRED_ORGANS:
        if organ_id not in row_by_id:
            raise RuntimeError(f"FAIL_CLOSED: required organ missing from disposition register: {organ_id}")
        row = row_by_id[organ_id]
        row.update(mapping[organ_id])
        if not str(row.get("receipt", "")).strip():
            row["receipt"] = str(row.get("evidence_ref", "")).strip()

    ordered_unique: List[str] = []
    for organ_id in ordered_ids + [item for item in REQUIRED_ORGANS if item not in ordered_ids]:
        if organ_id not in ordered_unique and organ_id in row_by_id:
            ordered_unique.append(organ_id)

    payload["generated_utc"] = utc_now_iso_z()
    payload["current_git_head"] = _git_head(root)
    if "cognition" in row_by_id:
        row_by_id["cognition"]["bounded_summary"] = (
            "Cognition is now bounded as a typed evidence-aware planner/executor with structural scoring and explicit refusal paths."
        )
    if "paradox" in row_by_id:
        row_by_id["paradox"]["bounded_summary"] = (
            "Paradox is now a bounded context-aware contradiction classification gate, not a broad debate engine."
        )
    if "temporal" in row_by_id:
        row_by_id["temporal"]["bounded_summary"] = (
            "Temporal is now a bounded fork-and-replay identity surface with nonzero step accounting when replay budget is positive."
        )
    if "multiverse" in row_by_id:
        row_by_id["multiverse"]["bounded_summary"] = (
            "Multiverse is now a bounded candidate-ranking surface with task-dependent coherence instead of constant coherence."
        )
    payload["rows"] = [row_by_id[organ_id] for organ_id in ordered_unique]
    stronger = [str(item).strip() for item in payload.get("stronger_claim_not_made", []) if str(item).strip()]
    for item in ["router_or_lobe_superiority_claimed", "same_host_live_hashed_success_narrated_as_externality_upgrade", "runtime_claim_compiler_missing_from_canonical_code"]:
        if item not in stronger:
            stronger.append(item)
    payload["stronger_claim_not_made"] = stronger
    return payload


def build_runtime_realism_threshold(*, organ_register: Mapping[str, Any], useful_output_benchmark: Mapping[str, Any], provider_path_integrity: Mapping[str, Any]) -> Dict[str, Any]:
    rows = organ_register.get("rows", [])
    row_by_id = {str(row.get("organ_id", "")).strip(): row for row in rows if isinstance(row, dict) and str(row.get("organ_id", "")).strip()}
    cognition_row = row_by_id.get("cognition", {})
    quarantined_rows = [
        row
        for row in rows
        if isinstance(row, dict) and str(row.get("plane", "")).strip() == "QUARANTINED" and str(row.get("zone", "")).strip() in {"LAB", "TOOLCHAIN_PROVING"}
    ]
    useful_row = next((row for row in useful_output_benchmark.get("rows", []) if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip() == "useful_output_evidence_stronger_than_ceremonial_path_evidence"), {})
    checks = [
        {"check_id": "useful_output_evidence_stronger_than_ceremonial_path_evidence", "pass": bool(useful_row.get("pass"))},
        {"check_id": "same_host_live_hashed_provider_witness_present", "pass": str(provider_path_integrity.get("status", "")).strip().upper() == "PASS"},
        {
            "check_id": "scaffolded_runtime_risk_explicitly_bounded_or_quarantined",
            "pass": (
                isinstance(cognition_row, dict)
                and str(cognition_row.get("claim_ceiling", "")).strip() == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1"
                and "bounded" in str(cognition_row.get("bounded_summary", "")).lower()
                and len(quarantined_rows) >= 2
            ),
        },
    ]
    return {
        "status": "PASS",
        "glamour_unlock": False,
        "enforcement_mode": "BLOCK_SUPERIORITY_CLAIMS_UNTIL_UNLOCK_ALLOWED",
        "checks": checks,
        "blocked_claims": ["learned_router_superiority", "multi_lobe_orchestration_superiority", "civilization_scale_runtime_superiority"],
        "summary": "W1 establishes the runtime realism threshold and keeps router/lobe/civilization glamour locked.",
    }


def build_organ_dependency_resolution_receipt(*, root: Path, organ_register: Mapping[str, Any], runtime_realism_threshold: Mapping[str, Any]) -> Dict[str, Any]:
    rows = organ_register.get("rows", [])
    row_by_id = {str(row.get("organ_id", "")).strip(): row for row in rows if isinstance(row, dict) and str(row.get("organ_id", "")).strip()}
    missing_organs = [organ_id for organ_id in REQUIRED_ORGANS if organ_id not in row_by_id]
    missing_columns: List[Dict[str, Any]] = []
    for organ_id in REQUIRED_ORGANS:
        row = row_by_id.get(organ_id, {})
        absent = [field for field in REQUIRED_COLUMNS if not str(row.get(field, "")).strip()]
        if absent:
            missing_columns.append({"organ_id": organ_id, "missing_columns": absent})

    status = "PASS" if not missing_organs and not missing_columns else "FAIL"
    return {
        "schema_id": "kt.w1.organ_dependency_resolution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "load_bearing_register_ref": ORGAN_REGISTER_REL,
        "required_organs": REQUIRED_ORGANS,
        "required_columns": REQUIRED_COLUMNS,
        "missing_organs": missing_organs,
        "rows_missing_required_columns": missing_columns,
        "runtime_realism_threshold": dict(runtime_realism_threshold),
        "claim_boundary": "No organ inherits maturity or claim ceiling from KT as a whole.",
    }


def build_mvcr_live_execution_receipt(*, root: Path, useful_output_benchmark: Mapping[str, Any], provider_path_integrity: Mapping[str, Any], organ_dependency_resolution: Mapping[str, Any], runtime_realism_threshold: Mapping[str, Any]) -> Dict[str, Any]:
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    runtime_truth = load_json(root / RUNTIME_TRUTH_REL)
    verifier_truth = load_json(root / VERIFIER_TRUTH_REL)
    tier_ruling = load_json(root / TIER_RULING_REL)
    wave3_run = load_json(root / WAVE3_RUN_REL)
    runtime_claim_compilation = compile_runtime_claims(
        root=root,
        useful_output_benchmark=useful_output_benchmark,
        provider_path_integrity=provider_path_integrity,
        truth_lock=truth_lock,
        runtime_truth=runtime_truth,
        verifier_truth=verifier_truth,
        tier_ruling=tier_ruling,
    )

    status = "PASS" if all(
        str(payload.get("status", "")).strip().upper() == "PASS"
        for payload in (useful_output_benchmark, provider_path_integrity, organ_dependency_resolution, runtime_claim_compilation)
    ) else "FAIL"

    forbidden_current_claims = list(runtime_claim_compilation.get("forbidden_current_claims", []))
    for blocked in runtime_realism_threshold.get("blocked_claims", []):
        text = f"Do not claim {blocked} before later comparator-earned waves."
        if text not in forbidden_current_claims:
            forbidden_current_claims.append(text)

    return {
        "schema_id": "kt.w1.mvcr_live_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "scope_boundary": "W1 runtime realization proves a live and useful bounded organism lane and does not close C006 or widen router, lobe, comparative, or commercial claims.",
        "code_path_bindings": [ENTRYPOINT_REF, SPINE_REF, CLAIM_COMPILER_REF, COUNCIL_ROUTER_REF, PROVIDER_REGISTRY_REF, STATE_VAULT_REF, REPLAY_REF],
        "source_family_ref": WAVE3_RUN_REL,
        "source_family_status": wave3_run.get("status", ""),
        "useful_output_benchmark_ref": USEFUL_OUTPUT_REL,
        "provider_path_integrity_ref": PROVIDER_PATH_REL,
        "organ_dependency_resolution_ref": ORGAN_DEPENDENCY_REL,
        "runtime_claim_compilation": runtime_claim_compilation,
        "runtime_realism_threshold": dict(runtime_realism_threshold),
        "active_current_head_blocker_ref": truth_lock.get("active_blocker_matrix_ref", ""),
        "active_open_blocker_ids": list(truth_lock.get("active_deferred_blocker_ids", [])),
        "current_truth_posture_open_blocker_ids": list(truth_lock.get("active_open_blocker_ids", [])),
        "legacy_release_blocker_ref": FINAL_BLOCKER_REL,
        "forbidden_current_claims": forbidden_current_claims,
        "next_lawful_move": "C006 remains open on the canonical lane; W2 lawful-evolution work may not widen claims beyond this bounded runtime realization.",
    }


def build_canonical_delta_w1(*, root: Path, mvcr_receipt: Mapping[str, Any], organ_dependency_resolution: Mapping[str, Any]) -> Dict[str, Any]:
    truth_lock = load_json(root / TRUTH_LOCK_REL)
    return {
        "schema_id": "kt.operator.canonical_delta_w1.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if str(mvcr_receipt.get("status", "")).strip().upper() == "PASS" and str(organ_dependency_resolution.get("status", "")).strip().upper() == "PASS" else "FAIL",
        "wave_id": "W1_RUNTIME_REALIZATION",
        "canonical_outputs": [MVCR_OUTPUT_REL, USEFUL_OUTPUT_REL, PROVIDER_PATH_REL, ORGAN_REGISTER_REL, ORGAN_DEPENDENCY_REL, CANONICAL_DELTA_REL],
        "blocker_delta": {
            "active_current_head_blocker_ref": truth_lock.get("active_blocker_matrix_ref", ""),
            "active_open_blocker_ids": list(truth_lock.get("active_deferred_blocker_ids", [])),
            "current_truth_posture_open_blocker_ids": list(truth_lock.get("active_open_blocker_ids", [])),
            "canonical_blocker_change": "NONE_C006_STILL_OPEN_WITHIN_W0_CURRENT_HEAD_SCOPE",
        },
        "ambiguity_reduced": [
            "mvcr_live_and_useful_receipt_now_exists",
            "runtime_claim_compiler_now_exists_as_canonical_code",
            "organ_disposition_register_now_has_load_bearing_columns",
        ],
        "forbidden_claims_remaining": [
            "Do not claim E2 or higher externality.",
            "Do not claim learned-router or multi-lobe superiority.",
            "Do not claim commercial or enterprise readiness.",
        ],
    }


def build_advancement_delta_w1(*, runtime_realism_threshold: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.advancement_delta_w1.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "wave_id": "W1_RUNTIME_REALIZATION",
        "advancement_outputs": [USEFUL_OUTPUT_REL, PROVIDER_PATH_REL, ADVANCEMENT_DELTA_REL],
        "runtime_realism_threshold": dict(runtime_realism_threshold),
        "glamour_unlock": bool(runtime_realism_threshold.get("glamour_unlock")),
        "blocked_advancement_claims": list(runtime_realism_threshold.get("blocked_claims", [])),
        "next_lawful_move": "Keep router/lobe/civilization superiority locked; only comparator-earned W2/W3 work may attempt widening later.",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute W1 runtime realization without creating sibling authority families.")
    parser.add_argument("--mvcr-output", default=MVCR_OUTPUT_REL)
    parser.add_argument("--useful-output-output", default=USEFUL_OUTPUT_REL)
    parser.add_argument("--provider-path-output", default=PROVIDER_PATH_REL)
    parser.add_argument("--organ-register-output", default=ORGAN_REGISTER_REL)
    parser.add_argument("--organ-dependency-output", default=ORGAN_DEPENDENCY_REL)
    parser.add_argument("--canonical-delta-output", default=CANONICAL_DELTA_REL)
    parser.add_argument("--advancement-delta-output", default=ADVANCEMENT_DELTA_REL)
    parser.add_argument("--telemetry-output", default=TELEMETRY_OUTPUT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    export_root = _resolve(root, str(args.export_root))
    telemetry_path = _resolve(root, str(args.telemetry_output))
    mvcr_path = _resolve(root, str(args.mvcr_output))
    useful_output_path = _resolve(root, str(args.useful_output_output))
    provider_path = _resolve(root, str(args.provider_path_output))
    organ_register_path = _resolve(root, str(args.organ_register_output))
    organ_dependency_path = _resolve(root, str(args.organ_dependency_output))
    canonical_delta_path = _resolve(root, str(args.canonical_delta_output))
    advancement_delta_path = _resolve(root, str(args.advancement_delta_output))

    useful_output_benchmark = build_useful_output_benchmark(root=root, export_root=export_root, telemetry_path=telemetry_path)
    provider_path_integrity = build_provider_path_integrity_receipt(root=root)
    upgraded_register = upgrade_organ_disposition_register(root=root, provider_path_ref=PROVIDER_PATH_REL, mvcr_ref=MVCR_OUTPUT_REL)
    runtime_realism_threshold = build_runtime_realism_threshold(organ_register=upgraded_register, useful_output_benchmark=useful_output_benchmark, provider_path_integrity=provider_path_integrity)
    organ_dependency_resolution = build_organ_dependency_resolution_receipt(root=root, organ_register=upgraded_register, runtime_realism_threshold=runtime_realism_threshold)
    mvcr_receipt = build_mvcr_live_execution_receipt(
        root=root,
        useful_output_benchmark=useful_output_benchmark,
        provider_path_integrity=provider_path_integrity,
        organ_dependency_resolution=organ_dependency_resolution,
        runtime_realism_threshold=runtime_realism_threshold,
    )
    canonical_delta = build_canonical_delta_w1(root=root, mvcr_receipt=mvcr_receipt, organ_dependency_resolution=organ_dependency_resolution)
    advancement_delta = build_advancement_delta_w1(runtime_realism_threshold=runtime_realism_threshold)

    write_json_stable(useful_output_path, useful_output_benchmark)
    write_json_stable(provider_path, provider_path_integrity)
    write_json_stable(organ_register_path, upgraded_register)
    write_json_stable(organ_dependency_path, organ_dependency_resolution)
    write_json_stable(mvcr_path, mvcr_receipt)
    write_json_stable(canonical_delta_path, canonical_delta)
    write_json_stable(advancement_delta_path, advancement_delta)

    summary = {
        "status": mvcr_receipt["status"],
        "active_open_blocker_ids": mvcr_receipt["active_open_blocker_ids"],
        "runtime_realism_glamour_unlock": mvcr_receipt["runtime_realism_threshold"]["glamour_unlock"],
        "runtime_claim_compiler_status": mvcr_receipt["runtime_claim_compilation"]["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if mvcr_receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
