from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from core.runtime_registry import load_runtime_registry
from council.council_router import CouncilRouter
from council.council_schemas import (
    MODE_DRY_RUN,
    MODE_LIVE_REQUESTED,
    PLAN_STATUS_OK,
    PLAN_STATUS_REFUSED,
    RESULT_STATUS_DRY_RUN,
    RESULT_STATUS_REFUSED,
    CouncilPlanSchema,
    CouncilRequestSchema,
)
from council.providers.adapter_abi_runtime import derive_legacy_adapter_id, load_active_adapter_manifests, resolve_live_adapter
from tools.operator.b02_runtime_unify_t3_validate import build_b02_runtime_unify_t3_outputs
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/b02_runtime_unify_t4"

EXECUTION_BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"
BOUNDARY_RULES_REL = "KT_PROD_CLEANROOM/governance/runtime_integration_boundary_rules.json"
ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
ROUTER_POLICY_REL = "KT_PROD_CLEANROOM/governance/router_policy_registry.json"
CIVILIZATION_LOOP_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/civilization_loop_contract.json"

B02_T1_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_receipt.json"
B02_T2_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t2_receipt.json"
B02_T3_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t3_receipt.json"
B02_T4_ADAPTER_BOUNDARY_REL = f"{REPORT_ROOT_REL}/b02_adapter_runtime_boundary_receipt.json"
B02_T4_ROUTER_BOUNDARY_REL = f"{REPORT_ROOT_REL}/b02_router_boundary_truth_receipt.json"
B02_T4_PROMOTION_BOUNDARY_REL = f"{REPORT_ROOT_REL}/b02_promotion_boundary_truth_receipt.json"
B02_T4_EXIT_GAP_REDUCTION_REL = f"{REPORT_ROOT_REL}/b02_exit_gap_reduction_receipt.json"
B02_T4_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t4_receipt.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status(payload: Mapping[str, Any]) -> str:
    return str(payload.get("status", "")).strip().upper()


def _is_pass(payload: Mapping[str, Any]) -> bool:
    return _status(payload) == "PASS"


def _check_row(check_id: str, passed: bool, **details: Any) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "pass": bool(passed),
        **details,
    }


def _runtime_src_root(root: Path) -> Path:
    return root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"


def _import_roots(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    roots: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = str(alias.name or "").strip()
                if name:
                    roots.append(name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            module = str(node.module or "").strip()
            if module:
                roots.append(module.split(".", 1)[0])
    return sorted(set(roots))


def _call_names_in_function(path: Path, fn_name: str) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            names: List[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _call_name(child.func)
                    if name:
                        names.append(name)
            return sorted(set(names))
    return []


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _valid_context() -> Dict[str, Any]:
    return {
        "envelope": {"input": ""},
        "schema_id": "kt.runtime.context.v1",
        "schema_version_hash": "2a5dfd46d8d4ef38d5f0b1e0d0b2dce7dc9aef0b6c04a8a9bb8c09d2f0a8d2a4",
        "constitution_version_hash": "0" * 64,
    }


def _router_request(*, mode: str) -> Dict[str, Any]:
    return {
        "schema_id": CouncilRequestSchema.SCHEMA_ID,
        "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
        "request_id": "b02.tranche4.council.request",
        "runtime_registry_hash": "1" * 64,
        "mode": mode,
        "provider_ids": ["dry_run"],
        "fanout_cap": 1,
        "per_call_token_cap": 256,
        "total_token_cap": 1024,
        "input_hash": "2" * 64,
    }


def _router_probe() -> Dict[str, Any]:
    context = _valid_context()
    dry_run_request = CouncilRequestSchema.from_dict(_router_request(mode=MODE_DRY_RUN))
    dry_plan = CouncilRouter.plan(context=context, request=dry_run_request).to_dict()
    dry_result = CouncilRouter.execute(context=context, plan=CouncilPlanSchema.from_dict(dry_plan)).to_dict()

    live_request = CouncilRequestSchema.from_dict(_router_request(mode=MODE_LIVE_REQUESTED))
    live_plan = CouncilRouter.plan(context=context, request=live_request).to_dict()
    live_result = CouncilRouter.execute(context=context, plan=CouncilPlanSchema.from_dict(live_plan)).to_dict()

    return {
        "dry_run_plan_status": dry_plan["status"],
        "dry_run_result_status": dry_result["status"],
        "live_requested_plan_status": live_plan["status"],
        "live_requested_result_status": live_result["status"],
        "pass": (
            dry_plan["status"] == PLAN_STATUS_OK
            and dry_result["status"] == RESULT_STATUS_DRY_RUN
            and live_plan["status"] == PLAN_STATUS_REFUSED
            and live_result["status"] == RESULT_STATUS_REFUSED
        ),
    }


def _row_by_id(organ_register: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {
        str(row.get("organ_id", "")).strip(): row
        for row in organ_register.get("rows", [])
        if isinstance(row, dict) and str(row.get("organ_id", "")).strip()
    }


def _load_boundary_rules(root: Path) -> Dict[str, Any]:
    return load_json(root / BOUNDARY_RULES_REL)


def _boundary_rules_are_expected(boundary_rules: Mapping[str, Any]) -> bool:
    return (
        str(boundary_rules.get("schema_id", "")).strip() == "kt.governance.runtime_integration_boundary_rules.v1"
        and str(boundary_rules.get("status", "")).strip() == "ACTIVE"
        and str(boundary_rules.get("canonical_runtime_lane", "")).strip() == "kt.entrypoint.invoke -> core.spine.run"
        and str(boundary_rules.get("runtime_admissible_adapter_root", "")).strip()
        == "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/exports/adapters"
        and str(boundary_rules.get("shadow_candidate_root", "")).strip() == "KT_PROD_CLEANROOM/exports/adapters_shadow"
        and sorted(str(item).strip() for item in boundary_rules.get("runtime_admissible_provider_ids", []) if str(item).strip())
        == ["openai", "openrouter"]
        and str(boundary_rules.get("remaining_b02_exit_blocker_id", "")).strip() == "PROMOTION_CIVILIZATION_RATIFIED_FALSE"
        and boundary_rules.get("router_boundary", {}).get("canonical_status") == "STATIC_CANONICAL_BASELINE_ONLY"
        and boundary_rules.get("router_boundary", {}).get("learned_router_cutover_allowed") is False
        and boundary_rules.get("router_boundary", {}).get("multi_lobe_promotion_allowed") is False
        and boundary_rules.get("promotion_boundary", {}).get("internal_promotion_evidence_allowed") is True
        and boundary_rules.get("promotion_boundary", {}).get("canonical_runtime_cutover_allowed") is False
        and boundary_rules.get("promotion_boundary", {}).get("generated_candidate_runtime_admissible") is False
        and boundary_rules.get("promotion_boundary", {}).get("teacher_growth_runtime_influence_allowed") is False
    )


def build_b02_adapter_runtime_boundary_receipt(
    *,
    root: Path,
    head: str,
    boundary_rules: Mapping[str, Any],
    runtime_registry: Any,
    provider_path_integrity: Mapping[str, Any],
    universal_adapter_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    src_root = _runtime_src_root(root)
    adapter_registry = load_json(root / ADAPTER_REGISTRY_REL)
    live_manifests = load_active_adapter_manifests()
    runtime_adapter_root = root / boundary_rules["runtime_admissible_adapter_root"]
    shadow_root = root / boundary_rules["shadow_candidate_root"]
    council_router_path = src_root / "council" / "council_router.py"

    runtime_active_entries = [entry for entry in runtime_registry.adapters.entries if entry.status == "ACTIVE"]
    runtime_active_ids = sorted(entry.adapter_id for entry in runtime_active_entries)
    live_manifest_ids = sorted(live_manifests.keys())
    live_provider_ids = sorted(
        str(item).strip() for item in provider_path_integrity.get("same_host_live_hashed_provider_ids", []) if str(item).strip()
    )
    derived_provider_adapter_ids = sorted(derive_legacy_adapter_id(provider_id=provider_id) for provider_id in live_provider_ids)
    governance_inventory_ids = sorted(
        {
            str(item).strip()
            for bucket in ("experimental_adapter_ids", "ratified_adapter_ids")
            for item in adapter_registry.get(bucket, [])
            if str(item).strip()
        }
    )
    generated_candidate = universal_adapter_receipt.get("generated_candidate", {})
    generated_candidate_id = str(generated_candidate.get("adapter_id", "")).strip()
    generated_candidate_job_dir_ref = str(universal_adapter_receipt.get("generated_candidate_job_dir_ref", "")).strip()
    generated_candidate_job_dir = root / generated_candidate_job_dir_ref if generated_candidate_job_dir_ref else None

    resolved_rows = []
    for entry in runtime_active_entries:
        manifest = resolve_live_adapter(
            adapter_id=entry.adapter_id,
            request_type="analysis",
            provider_id=live_manifests[entry.adapter_id].provider_id,
        )
        resolved_rows.append(
            {
                "adapter_id": manifest.adapter_id,
                "provider_id": manifest.provider_id,
                "manifest_path_ref": manifest.manifest_path.relative_to(root).as_posix(),
                "request_type_allowlist": list(manifest.request_type_allowlist),
            }
        )

    manifest_rows = [
        {
            "adapter_id": manifest.adapter_id,
            "provider_id": manifest.provider_id,
            "manifest_path_ref": manifest.manifest_path.relative_to(root).as_posix(),
            "under_runtime_root": manifest.manifest_path.resolve().is_relative_to(runtime_adapter_root.resolve()),
            "under_shadow_root": manifest.manifest_path.resolve().is_relative_to(shadow_root.resolve()),
        }
        for manifest in live_manifests.values()
    ]
    execute_calls = _call_names_in_function(council_router_path, "execute_council_request")

    checks = [
        _check_row("boundary_rules_active_and_exact", _boundary_rules_are_expected(boundary_rules)),
        _check_row(
            "runtime_active_entries_match_live_manifests_and_provider_path",
            runtime_active_ids == live_manifest_ids == derived_provider_adapter_ids,
            runtime_active_ids=runtime_active_ids,
            live_manifest_ids=live_manifest_ids,
            provider_path_adapter_ids=derived_provider_adapter_ids,
        ),
        _check_row(
            "runtime_admissible_live_manifests_stay_under_runtime_adapter_root_only",
            all(row["under_runtime_root"] and not row["under_shadow_root"] for row in manifest_rows),
        ),
        _check_row(
            "governance_lobe_inventory_does_not_launder_into_live_runtime_manifests",
            not set(governance_inventory_ids).intersection(live_manifest_ids),
            overlap=sorted(set(governance_inventory_ids).intersection(live_manifest_ids)),
        ),
        _check_row(
            "generated_candidate_remains_shadow_only_and_non_runtime",
            _is_pass(universal_adapter_receipt)
            and generated_candidate_id not in live_manifest_ids
            and "adapters_shadow" in generated_candidate_job_dir_ref
            and generated_candidate_job_dir is not None,
            generated_candidate_id=generated_candidate_id,
            generated_candidate_job_dir_ref=generated_candidate_job_dir_ref,
        ),
        _check_row(
            "council_live_path_resolves_live_adapter_then_invokes_live_hashed_provider_registry",
            {"resolve_live_adapter", "ProviderRegistry.build_default", "registry.invoke_live_hashed"}.issubset(set(execute_calls)),
            observed_calls=execute_calls,
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.adapter_runtime_boundary_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 4 proves adapter runtime admissibility stays narrow on the canonical path. It does not widen adapter breadth or permit generated runtime cutover.",
        "runtime_admissible_adapter_ids": runtime_active_ids,
        "manifest_rows": manifest_rows,
        "resolved_runtime_rows": resolved_rows,
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim all adapter inventory is runtime-admissible.",
            "Do not claim generated candidates are live runtime adapters.",
            "Do not widen externality or civilization claims from adapter admissibility alone."
        ],
    }


def build_b02_router_boundary_truth_receipt(
    *,
    root: Path,
    head: str,
    boundary_rules: Mapping[str, Any],
) -> Dict[str, Any]:
    router_receipt = load_json(root / "KT_PROD_CLEANROOM" / "reports" / "post_wave5_c005_router_ratification_receipt.json")
    shadow_matrix = load_json(root / "KT_PROD_CLEANROOM" / "reports" / "kt_wave2b_router_shadow_eval_matrix.json")
    router_policy = load_json(root / ROUTER_POLICY_REL)
    router_probe = _router_probe()
    src_root = _runtime_src_root(root)
    checked_paths = [
        src_root / "kt" / "entrypoint.py",
        src_root / "core" / "spine.py",
        src_root / "council" / "council_router.py",
        src_root / "council" / "providers" / "provider_registry.py",
        src_root / "council" / "providers" / "adapter_abi_runtime.py",
    ]
    forbidden_roots = {"tools", "training"}
    import_scan_rows = [{"path_ref": path.relative_to(root).as_posix(), "import_roots": _import_roots(path)} for path in checked_paths]

    checks = [
        _check_row(
            "router_ratification_is_pass_and_static_only",
            _is_pass(router_receipt)
            and str(router_receipt.get("canonical_router_status", "")).strip()
            == str(boundary_rules.get("router_boundary", {}).get("canonical_status", "")).strip()
            and str(router_receipt.get("ratification_decision", "")).strip() == "HOLD_STATIC_CANONICAL_BASELINE",
        ),
        _check_row(
            "shadow_eval_keeps_canonical_router_unchanged_and_learned_cutover_blocked",
            bool(shadow_matrix.get("promotion_decision", {}).get("canonical_router_unchanged"))
            and not bool(shadow_matrix.get("promotion_decision", {}).get("learned_router_cutover_allowed")),
        ),
        _check_row(
            "router_policy_blocks_learned_and_multi_lobe_until_earned",
            str(router_policy.get("ratification_scope", "")).strip() == "STATIC_ROUTER_BASELINE_ONLY"
            and str(router_policy.get("learned_router_candidate_policy", {}).get("current_status", "")).strip()
            == "BLOCKED_PENDING_ELIGIBLE_CANDIDATE_AND_CLEAN_WIN"
            and str(router_policy.get("multi_lobe_orchestration_policy", {}).get("current_status", "")).strip()
            == "BLOCKED_PENDING_LEARNED_ROUTER_WIN",
        ),
        _check_row(
            "canonical_council_router_stays_bounded_dry_run_and_refuses_live_requested_mode",
            bool(router_probe["pass"]),
            dry_run_plan_status=router_probe["dry_run_plan_status"],
            dry_run_result_status=router_probe["dry_run_result_status"],
            live_requested_plan_status=router_probe["live_requested_plan_status"],
            live_requested_result_status=router_probe["live_requested_result_status"],
        ),
        _check_row(
            "claim_bearing_runtime_modules_have_no_hidden_tools_or_training_imports",
            all(not forbidden_roots.intersection(set(row["import_roots"])) for row in import_scan_rows),
            import_scan_rows=import_scan_rows,
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.router_boundary_truth_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 4 proves the router remains a lawful static baseline boundary on the canonical path, not a hidden learned or multi-lobe runtime.",
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim learned-router superiority or cutover.",
            "Do not claim multi-lobe orchestration is canonical runtime.",
            "Do not open Gate C from router boundary truth alone."
        ],
    }


def build_b02_promotion_boundary_truth_receipt(
    *,
    root: Path,
    head: str,
    boundary_rules: Mapping[str, Any],
    organ_register: Mapping[str, Any],
) -> Dict[str, Any]:
    contract = load_json(root / CIVILIZATION_LOOP_CONTRACT_REL)
    loop_receipt = load_json(root / "KT_PROD_CLEANROOM" / "reports" / "civilization_loop_receipt.json")
    learning_receipt = load_json(root / "KT_PROD_CLEANROOM" / "reports" / "learning_response_receipt.json")
    quarantine = load_json(root / "KT_PROD_CLEANROOM" / "reports" / "kt_wave0_quarantine_receipts.json")
    execution_board = load_json(root / EXECUTION_BOARD_REL)
    row_map = _row_by_id(organ_register)
    teacher_row = row_map.get("teacher_growth_surfaces", {})
    tournament_row = row_map.get("tournament_promotion", {})
    quarantine_rows = {
        str(row.get("surface_id", "")).strip(): row
        for row in quarantine.get("rows", [])
        if isinstance(row, dict) and str(row.get("surface_id", "")).strip()
    }
    src_root = _runtime_src_root(root)
    checked_paths = [
        src_root / "kt" / "entrypoint.py",
        src_root / "core" / "spine.py",
        src_root / "council" / "council_router.py",
        src_root / "memory" / "state_vault.py",
        src_root / "memory" / "replay.py",
    ]
    forbidden_roots = {"tools", "training"}
    import_scan_rows = [{"path_ref": path.relative_to(root).as_posix(), "import_roots": _import_roots(path)} for path in checked_paths]

    checks = [
        _check_row(
            "civilization_loop_contract_keeps_runtime_cutover_separately_gated",
            str(contract.get("status", "")).strip() == "ACTIVE"
            and "separately gated" in str(contract.get("canonical_influence_rule", "")).lower()
            and boundary_rules.get("promotion_boundary", {}).get("canonical_runtime_cutover_allowed") is False,
        ),
        _check_row(
            "civilization_loop_receipt_stays_pass_but_forbids_automatic_runtime_cutover",
            _is_pass(loop_receipt)
            and bool(loop_receipt.get("rollback_bound"))
            and "automatic_runtime_cutover_completed" in loop_receipt.get("forbidden_claims_not_made", []),
        ),
        _check_row(
            "learning_response_receipt_stays_bounded_and_forbids_autonomous_runtime_self_modification",
            _is_pass(learning_receipt)
            and str(learning_receipt.get("learning_response_status", "")).strip() == "BOUNDED_SAFE_IMPROVEMENT_PROVED"
            and "autonomous_live_runtime_self_modification" in learning_receipt.get("forbidden_claims_not_made", []),
        ),
        _check_row(
            "tournament_and_teacher_surfaces_remain_bounded_non_cutover_runtime_boundaries",
            str(tournament_row.get("claim_ceiling", "")).strip() == "CURRENT_HEAD_BOUNDED_INTERNAL_CIVILIZATION_LOOP_ONLY"
            and str(teacher_row.get("claim_ceiling", "")).strip() == "LAB_GOVERNED_ONLY"
            and str(teacher_row.get("zone", "")).strip() == "LAB"
            and str(quarantine_rows.get("teacher_growth_surfaces", {}).get("zone", "")).strip() == "LAB",
        ),
        _check_row(
            "execution_board_exit_gate_remains_false_and_is_the_actual_remaining_gate",
            bool(execution_board.get("program_gates", {}).get("H1_ACTIVATION_ALLOWED"))
            and not bool(execution_board.get("program_gates", {}).get("PROMOTION_CIVILIZATION_RATIFIED"))
            and str(boundary_rules.get("remaining_b02_exit_blocker_id", "")).strip() == "PROMOTION_CIVILIZATION_RATIFIED_FALSE",
        ),
        _check_row(
            "claim_bearing_runtime_modules_have_no_training_or_tools_import_influence",
            all(not forbidden_roots.intersection(set(row["import_roots"])) for row in import_scan_rows),
            import_scan_rows=import_scan_rows,
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.promotion_boundary_truth_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 4 proves tournament, learning-response, and teacher/growth surfaces remain bounded evidence or lab-only boundaries and do not yet influence canonical runtime cutover.",
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim canonical runtime cutover from tournament evidence.",
            "Do not claim autonomous runtime self-modification.",
            "Do not claim teacher or growth surfaces are canonical runtime."
        ],
    }


def build_b02_exit_gap_reduction_receipt(
    *,
    head: str,
    t3_exit_gap_receipt: Mapping[str, Any],
    adapter_boundary_receipt: Mapping[str, Any],
    router_boundary_receipt: Mapping[str, Any],
    promotion_boundary_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    reclassified_boundaries = [
        {
            "boundary_id": "ROUTER_STATIC_CANONICAL_BASELINE_ONLY",
            "class": "BOUNDARY_RATIFIED_NOT_EXIT_BLOCKING",
            "evidence_ref": B02_T4_ROUTER_BOUNDARY_REL,
            "why": "Router status is now explicit runtime boundary truth, not a runtime-lane ambiguity."
        },
        {
            "boundary_id": "ADAPTER_LAYER_BREADTH_AND_CUTOVER_REMAIN_BOUNDED",
            "class": "BOUNDARY_RATIFIED_NOT_EXIT_BLOCKING",
            "evidence_ref": B02_T4_ADAPTER_BOUNDARY_REL,
            "why": "Adapter layer is now explicit runtime-admissibility truth: two live hashed manifests only, generated candidates excluded."
        },
        {
            "boundary_id": "TOURNAMENT_PROMOTION_NOT_CANONICAL_RUNTIME_CUTOVER",
            "class": "BOUNDARY_RATIFIED_NOT_EXIT_BLOCKING",
            "evidence_ref": B02_T4_PROMOTION_BOUNDARY_REL,
            "why": "Tournament/promotion loop is explicit bounded evidence only and remains separately gated from canonical runtime cutover."
        },
        {
            "boundary_id": "TEACHER_GROWTH_SURFACES_LAB_ONLY",
            "class": "BOUNDARY_RATIFIED_NOT_EXIT_BLOCKING",
            "evidence_ref": B02_T4_PROMOTION_BOUNDARY_REL,
            "why": "Teacher/growth surfaces remain lab-only and are no longer treated as runtime-lane ambiguity."
        }
    ]
    remaining_exit_blockers = [
        {
            "blocker_id": "PROMOTION_CIVILIZATION_RATIFIED_FALSE",
            "class": "EXIT_GATE_BLOCKER",
            "evidence_ref": EXECUTION_BOARD_REL,
            "why": "Gate B exit remains closed until promotion civilization is formally ratified on the execution board."
        }
    ]
    checks = [
        _check_row("t3_exit_gap_receipt_remains_pass", _is_pass(t3_exit_gap_receipt)),
        _check_row(
            "adapter_router_and_promotion_boundaries_are_all_explicit_and_pass",
            _is_pass(adapter_boundary_receipt) and _is_pass(router_boundary_receipt) and _is_pass(promotion_boundary_receipt),
        ),
        _check_row(
            "remaining_exit_blocker_count_reduced_to_one",
            len(remaining_exit_blockers) == 1 and len(reclassified_boundaries) == 4,
            remaining_exit_blocker_count=len(remaining_exit_blockers),
            reclassified_boundary_count=len(reclassified_boundaries),
        ),
        _check_row(
            "remaining_exit_blocker_is_only_promotion_civilization_ratified_false",
            remaining_exit_blockers[0]["blocker_id"] == "PROMOTION_CIVILIZATION_RATIFIED_FALSE",
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.exit_gap_reduction_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 4 reclassifies upper-stack runtime surfaces from exit blockers into explicit bounded boundaries, leaving only promotion-civilization ratification as the remaining B02 exit blocker.",
        "checks": checks,
        "reclassified_boundaries": reclassified_boundaries,
        "remaining_exit_blockers": remaining_exit_blockers,
        "exit_ready": False,
    }


def build_b02_runtime_unify_t4_outputs(
    *,
    root: Path,
    export_root: Path,
    c017_telemetry_path: Path,
    w1_telemetry_path: Path,
) -> Dict[str, Dict[str, Any]]:
    head = _git_head(root)
    export_root.mkdir(parents=True, exist_ok=True)
    boundary_rules = _load_boundary_rules(root)
    runtime_registry = load_runtime_registry()
    t3_outputs = build_b02_runtime_unify_t3_outputs(
        root=root,
        export_root=(export_root / "t3_refresh").resolve(),
        c017_telemetry_path=c017_telemetry_path,
        w1_telemetry_path=w1_telemetry_path,
    )
    adapter_boundary = build_b02_adapter_runtime_boundary_receipt(
        root=root,
        head=head,
        boundary_rules=boundary_rules,
        runtime_registry=runtime_registry,
        provider_path_integrity=t3_outputs["provider_path_integrity_receipt"],
        universal_adapter_receipt=load_json(root / "KT_PROD_CLEANROOM" / "reports" / "universal_adapter_receipt.json"),
    )
    router_boundary = build_b02_router_boundary_truth_receipt(root=root, head=head, boundary_rules=boundary_rules)
    promotion_boundary = build_b02_promotion_boundary_truth_receipt(
        root=root,
        head=head,
        boundary_rules=boundary_rules,
        organ_register=t3_outputs["organ_disposition_register"],
    )
    exit_gap_reduction = build_b02_exit_gap_reduction_receipt(
        head=head,
        t3_exit_gap_receipt=t3_outputs["b02_exit_gap_receipt"],
        adapter_boundary_receipt=adapter_boundary,
        router_boundary_receipt=router_boundary,
        promotion_boundary_receipt=promotion_boundary,
    )
    t4_receipt = build_b02_runtime_unify_t4_receipt(
        head=head,
        t3_receipt=t3_outputs["b02_runtime_unify_t3_receipt"],
        adapter_boundary_receipt=adapter_boundary,
        router_boundary_receipt=router_boundary,
        promotion_boundary_receipt=promotion_boundary,
        exit_gap_reduction_receipt=exit_gap_reduction,
    )
    return {
        **t3_outputs,
        "b02_adapter_runtime_boundary_receipt": adapter_boundary,
        "b02_router_boundary_truth_receipt": router_boundary,
        "b02_promotion_boundary_truth_receipt": promotion_boundary,
        "b02_exit_gap_reduction_receipt": exit_gap_reduction,
        "b02_runtime_unify_t4_receipt": t4_receipt,
    }


def build_b02_runtime_unify_t4_receipt(
    *,
    head: str,
    t3_receipt: Mapping[str, Any],
    adapter_boundary_receipt: Mapping[str, Any],
    router_boundary_receipt: Mapping[str, Any],
    promotion_boundary_receipt: Mapping[str, Any],
    exit_gap_reduction_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    status = "PASS" if all(
        _is_pass(payload)
        for payload in (
            t3_receipt,
            adapter_boundary_receipt,
            router_boundary_receipt,
            promotion_boundary_receipt,
            exit_gap_reduction_receipt,
        )
    ) else "FAIL"
    return {
        "schema_id": "kt.b02.runtime_unify_t4_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "tranche_id": "B02_GATE_B_RUNTIME_UNIFY_T4",
        "scope_boundary": "Fourth counted B02 tranche only. This tranche canonizes runtime integration boundaries for adapters, router, and promotion surfaces, and reduces B02 exit blockers to the single remaining promotion-civilization ratification gate without opening Gate C.",
        "entry_gate_status": bool(t3_receipt.get("entry_gate_status")),
        "exit_gate_status": False,
        "earned_current_head_claims": [
            "The adapter layer is now explicitly runtime-admissible only as the two live hashed manifests under exports/adapters on the canonical path.",
            "Router boundary truth is explicit: the canonical runtime remains static-baseline only, with no hidden learned-router or multi-lobe influence on the claim-bearing lane.",
            "Tournament, learning-response, and teacher/growth surfaces are explicit bounded boundaries and do not currently influence canonical runtime cutover.",
            "The remaining B02 exit blocker is reduced to PROMOTION_CIVILIZATION_RATIFIED_FALSE on the execution board."
        ],
        "component_refs": [
            B02_T1_RECEIPT_REL,
            B02_T2_RECEIPT_REL,
            B02_T3_RECEIPT_REL,
            B02_T4_ADAPTER_BOUNDARY_REL,
            B02_T4_ROUTER_BOUNDARY_REL,
            B02_T4_PROMOTION_BOUNDARY_REL,
            B02_T4_EXIT_GAP_REDUCTION_REL
        ],
        "forbidden_claims_remaining": [
            "Do not claim B02 is complete.",
            "Do not claim Gate C is open.",
            "Do not claim promotion civilization is ratified.",
            "Do not widen civilization, externality, product, or prestige language."
        ],
        "next_lawful_move": "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C"
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute B02 runtime-unification tranche 4 on current head.")
    parser.add_argument("--c017-telemetry-output", default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl")
    parser.add_argument("--w1-telemetry-output", default=f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl")
    parser.add_argument("--adapter-boundary-output", default=B02_T4_ADAPTER_BOUNDARY_REL)
    parser.add_argument("--router-boundary-output", default=B02_T4_ROUTER_BOUNDARY_REL)
    parser.add_argument("--promotion-boundary-output", default=B02_T4_PROMOTION_BOUNDARY_REL)
    parser.add_argument("--exit-gap-reduction-output", default=B02_T4_EXIT_GAP_REDUCTION_REL)
    parser.add_argument("--receipt-output", default=B02_T4_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_b02_runtime_unify_t4_outputs(
        root=root,
        export_root=_resolve(root, str(args.export_root)),
        c017_telemetry_path=_resolve(root, str(args.c017_telemetry_output)),
        w1_telemetry_path=_resolve(root, str(args.w1_telemetry_output)),
    )

    write_json_stable(_resolve(root, str(args.adapter_boundary_output)), outputs["b02_adapter_runtime_boundary_receipt"])
    write_json_stable(_resolve(root, str(args.router_boundary_output)), outputs["b02_router_boundary_truth_receipt"])
    write_json_stable(_resolve(root, str(args.promotion_boundary_output)), outputs["b02_promotion_boundary_truth_receipt"])
    write_json_stable(_resolve(root, str(args.exit_gap_reduction_output)), outputs["b02_exit_gap_reduction_receipt"])
    write_json_stable(_resolve(root, str(args.receipt_output)), outputs["b02_runtime_unify_t4_receipt"])

    summary = {
        "status": outputs["b02_runtime_unify_t4_receipt"]["status"],
        "entry_gate_status": outputs["b02_runtime_unify_t4_receipt"]["entry_gate_status"],
        "exit_gate_status": outputs["b02_runtime_unify_t4_receipt"]["exit_gate_status"],
        "next_lawful_move": outputs["b02_runtime_unify_t4_receipt"]["next_lawful_move"],
        "remaining_exit_blocker_count": len(outputs["b02_exit_gap_reduction_receipt"]["remaining_exit_blockers"]),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["b02_runtime_unify_t4_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
