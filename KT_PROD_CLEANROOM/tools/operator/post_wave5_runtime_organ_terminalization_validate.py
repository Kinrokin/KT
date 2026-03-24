from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WAVE_ID = "POST_WAVE5_RUNTIME_ORGAN_TERMINALIZATION"

FREEZE_RECEIPT_REL = f"{REPORT_ROOT_REL}/post_wave5_runtime_terminalization_receipt.json"
ORGAN_REGISTER_REL = f"{REPORT_ROOT_REL}/post_wave5_runtime_organ_terminal_state_register.json"
TOOLS_REGISTER_REL = f"{REPORT_ROOT_REL}/post_wave5_runtime_tools_state_register.json"
GROWTH_REGISTER_REL = f"{REPORT_ROOT_REL}/post_wave5_growth_surface_state_register.json"
TRUTH_MATRIX_REL = f"{REPORT_ROOT_REL}/post_wave5_runtime_truth_matrix.json"
TELEMETRY_REL = f"{REPORT_ROOT_REL}/post_wave5_runtime_terminalization_telemetry.jsonl"

C007_REL = f"{REPORT_ROOT_REL}/kt_wave0_5_package_import_canon_receipt.json"
C016A_REL = f"{REPORT_ROOT_REL}/post_wave5_c016a_success_matrix.json"
C016B_REL = f"{REPORT_ROOT_REL}/post_wave5_c016b_resilience_pack.json"
WAVE5_STATE_CORE_REL = f"{REPORT_ROOT_REL}/kt_wave5_state_core.json"
WAVE5_BLOCKER_REL = f"{REPORT_ROOT_REL}/kt_wave5_blocker_matrix.json"
WAVE5_RUNTIME_TRUTH_REL = f"{REPORT_ROOT_REL}/kt_wave5_runtime_truth_surface.json"
WAVE5_DISPOSITION_REL = f"{REPORT_ROOT_REL}/kt_wave5_updated_surface_disposition_register.json"


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _is_pass(payload: Dict[str, Any]) -> bool:
    return str(payload.get("status", "")).strip().upper() == "PASS"


def _build_freeze_receipt(*, head: str, c007: Dict[str, Any], c016a: Dict[str, Any], c016b: Dict[str, Any]) -> Dict[str, Any]:
    if not (_is_pass(c007) and _is_pass(c016a) and _is_pass(c016b)):
        raise RuntimeError("FAIL_CLOSED: C007/C016A/C016B prerequisites must already be PASS before L4 terminalization.")
    return {
        "schema_id": "kt.post_wave5.runtime_terminalization_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "wave_id": WAVE_ID,
        "closed_blockers": [
            {
                "blocker_id": "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
                "closure_state": "CLOSED_FOR_CANONICAL_RUNTIME_IMPORT_INSTALL_LANE",
                "evidence_ref": C007_REL,
            },
            {
                "blocker_id": "C016A_AUTHENTICATED_LIVE_PROVIDER_SUCCESS_NOT_YET_PROVEN",
                "closure_state": "CLOSED_FOR_CANONICAL_SAME_HOST_LIVE_HASHED_SUCCESS_LANE",
                "evidence_ref": C016A_REL,
            },
            {
                "blocker_id": "C016B_AUTHENTICATED_LIVE_PROVIDER_RESILIENCE_NOT_YET_PROVEN",
                "closure_state": "CLOSED_FOR_CANONICAL_SAME_HOST_LIVE_HASHED_RESILIENCE_LANE",
                "evidence_ref": C016B_REL,
            },
        ],
        "remaining_open_blockers": [
            "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
            "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
        ],
        "execution_order": [
            "thermodynamics.budget_meters",
            "temporal",
            "multiverse",
            "paradox",
            "cognition",
            "council",
            "runtime_terminal_state_rollup",
        ],
        "forbidden_claims_preserved": [
            "Do not narrate same-host LIVE_HASHED provider success as a C006 externality upgrade.",
            "Do not narrate router superiority, learned cutover, or multi-lobe routing from this lane.",
            "Do not narrate product, comparative, or standards expansion from this lane.",
        ],
        "source_refs": [
            C007_REL,
            C016A_REL,
            C016B_REL,
            WAVE5_STATE_CORE_REL,
            WAVE5_BLOCKER_REL,
            WAVE5_RUNTIME_TRUTH_REL,
            WAVE5_DISPOSITION_REL,
        ],
    }


def _build_organ_register(*, head: str) -> Dict[str, Any]:
    rows = [
        {
            "organ_id": "core.fail_closed_dispatch_stack",
            "terminal_state": "CORE_LIVE",
            "execution_tranche": "FOUNDATIONAL_ALREADY_PROVEN",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/import_truth_guard.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/invariants_gate.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/runtime_registry.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/routing_receipts.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_runtime_registry_boundary.py",
            ],
            "bounded_summary": "Canonical dispatch, import truth, invariant gating, registry enforcement, and routing receipts are runtime-live and protected.",
        },
        {
            "organ_id": "memory.state_vault_and_replay",
            "terminal_state": "CORE_LIVE",
            "execution_tranche": "FOUNDATIONAL_ALREADY_PROVEN",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py",
                "KT_PROD_CLEANROOM/reports/kt_wave3_minimum_viable_civilization_run_pack.json",
            ],
            "bounded_summary": "Append-only persistence and replay validation remain core-live protected runtime surfaces.",
        },
        {
            "organ_id": "thermodynamics.budget_engine",
            "terminal_state": "CORE_LIVE",
            "execution_tranche": "LOW_COUPLING_FIRST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/budget_engine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/tests/test_budget_engine.py",
            ],
            "bounded_summary": "Budget allocation and refusal logic are real, deterministic, and runtime-enforced on the canonical path.",
        },
        {
            "organ_id": "thermodynamics.budget_meters",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "LOW_COUPLING_FIRST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/token_meter.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/step_meter.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/memory_meter.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/meters/duration_fuse.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/thermodynamics/tests/test_budget_meters.py",
            ],
            "bounded_summary": "Meters are deterministic subtraction/fuse helpers that are runtime-used and bounded, not semantic controllers.",
        },
        {
            "organ_id": "temporal",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "LOW_COUPLING_FIRST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/tests/test_temporal_engine.py",
                "KT_PROD_CLEANROOM/reports/kt_wave2c_temporal_engine_pack.json",
            ],
            "bounded_summary": "Temporal is a real deterministic fork-and-replay identity surface with bounded replay semantics, not a broad execution-history simulator.",
        },
        {
            "organ_id": "multiverse",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "LOW_COUPLING_FIRST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/tests/test_multiverse_engine.py",
                "KT_PROD_CLEANROOM/reports/kt_wave2c_multiverse_engine_pack.json",
            ],
            "bounded_summary": "Multiverse is a deterministic candidate-ranking surface with explicit caps and a bounded coherence placeholder.",
        },
        {
            "organ_id": "paradox",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "LOW_COUPLING_FIRST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/tests/test_paradox_engine.py",
                "KT_PROD_CLEANROOM/reports/kt_wave2c_paradox_engine_pack.json",
            ],
            "bounded_summary": "Paradox is a real deterministic contradiction-trigger gate with injection/noop behavior, not a broad paradox reasoner.",
        },
        {
            "organ_id": "cognition",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "HIGH_COUPLING_LAST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/planners/step_planner.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py",
                "KT_PROD_CLEANROOM/reports/kt_wave2c_cognitive_provenance_pack.json",
            ],
            "bounded_summary": "Cognition is a deterministic hash-only planner/executor with explicit refusal paths, not a semantic reasoning organ.",
        },
        {
            "organ_id": "council",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "HIGH_COUPLING_LAST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/council_router.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/providers/provider_registry.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests/test_council_router.py",
                C016A_REL,
                C016B_REL,
            ],
            "bounded_summary": "Council now has a proven same-host LIVE_HASHED OpenAI/OpenRouter execution and resilience lane, while static routing remains the canonical baseline and broader router claims stay forbidden.",
        },
        {
            "organ_id": "router_static_baseline",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "HIGH_COUPLING_LAST",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/governance/router_policy_registry.json",
                "KT_PROD_CLEANROOM/reports/kt_wave2b_router_selection_receipt.json",
            ],
            "bounded_summary": "The router is truthfully terminalized as a static canonical baseline only; learned cutover remains unearned under C005.",
        },
        {
            "organ_id": "curriculum_ingest_boundary",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "ROLLED_UP",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/curriculum/curriculum_ingest.py",
            ],
            "bounded_summary": "Curriculum remains a live bounded training-boundary guard, not a production training engine.",
        },
        {
            "organ_id": "runtime_governance_enforcement",
            "terminal_state": "LIVE_BOUNDED",
            "execution_tranche": "ROLLED_UP",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/governance/event_logger.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/governance/events.py",
            ],
            "bounded_summary": "Runtime governance Python surfaces are real and bounded, but they do not on their own upgrade broader governance claims.",
        },
    ]
    return {
        "schema_id": "kt.post_wave5.runtime_organ_terminal_state_register.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "rows": rows,
        "terminal_state_counts": {
            "CORE_LIVE": sum(1 for row in rows if row["terminal_state"] == "CORE_LIVE"),
            "LIVE_BOUNDED": sum(1 for row in rows if row["terminal_state"] == "LIVE_BOUNDED"),
            "LAB_GOVERNED": 0,
            "ARCHIVE_QUARANTINED": 0,
            "RETIRED": 0,
        },
        "stronger_claims_not_made": [
            "semantic_cognition_or_general_reasoning_claimed",
            "learned_router_cutover_claimed",
            "cross_host_or_outsider_live_provider_verification_claimed",
        ],
    }


def _build_tools_register(*, head: str) -> Dict[str, Any]:
    rows = [
        {
            "tool_id": "tools.operator.package_import_canon",
            "tool_state": "TOOL_VERIFIED",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/tools/operator/package_import_canon.py",
                "KT_PROD_CLEANROOM/tests/operator/test_package_import_canon.py",
                C007_REL,
            ],
        },
        {
            "tool_id": "tools.operator.c016a_live_provider_success_validate",
            "tool_state": "TOOL_VERIFIED",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/tools/operator/c016a_live_provider_success_validate.py",
                "KT_PROD_CLEANROOM/tests/operator/test_c016a_live_provider_success_validate.py",
                C016A_REL,
            ],
        },
        {
            "tool_id": "tools.operator.c016b_live_provider_resilience_validate",
            "tool_state": "TOOL_VERIFIED",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/tools/operator/c016b_live_provider_resilience_validate.py",
                "KT_PROD_CLEANROOM/tests/operator/test_c016b_live_provider_resilience_validate.py",
                C016B_REL,
            ],
        },
        {
            "tool_id": "tools.operator.wave5_final_readjudication_and_tier_ruling_validate",
            "tool_state": "TOOL_VERIFIED",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/tools/operator/wave5_final_readjudication_and_tier_ruling_validate.py",
                "KT_PROD_CLEANROOM/tests/operator/test_wave5_final_readjudication_and_tier_ruling.py",
                WAVE5_STATE_CORE_REL,
            ],
        },
    ]
    return {
        "schema_id": "kt.post_wave5.runtime_tools_state_register.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "rows": rows,
    }


def _build_growth_register(*, head: str) -> Dict[str, Any]:
    rows = [
        {"surface_id": "tools/growth/crucibles", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/growth/distillation", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/growth/dream_loop", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/growth/eval_harness", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/growth/teacher_factory", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/growth/training_warehouse", "terminal_state": "LAB_GOVERNED"},
        {"surface_id": "tools/training/fl3_factory", "terminal_state": "LAB_GOVERNED"},
    ]
    return {
        "schema_id": "kt.post_wave5.growth_surface_state_register.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "rows": rows,
        "stronger_claims_not_made": [
            "growth_surfaces_promoted_to_canonical_runtime_without_promotion_receipts",
            "teacher_or_training_surfaces_narrated_as_runtime_organs",
        ],
    }


def _build_truth_matrix(
    *,
    head: str,
    freeze_receipt: Dict[str, Any],
    organ_register: Dict[str, Any],
    tools_register: Dict[str, Any],
    growth_register: Dict[str, Any],
) -> Dict[str, Any]:
    organ_rows = organ_register["rows"]
    return {
        "schema_id": "kt.post_wave5.runtime_truth_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": "PASS",
        "runtime_truth_summary": "Provider execution and resilience are now proven for the canonical same-host LIVE_HASHED OpenAI/OpenRouter lane. The remaining lawful runtime work is organ terminalization, not externality or router widening.",
        "remaining_open_blockers": freeze_receipt["remaining_open_blockers"],
        "closed_blockers": [row["blocker_id"] for row in freeze_receipt["closed_blockers"]],
        "runtime_organ_terminal_state_ref": ORGAN_REGISTER_REL,
        "runtime_tools_state_ref": TOOLS_REGISTER_REL,
        "growth_surface_state_ref": GROWTH_REGISTER_REL,
        "rows": [
            {
                "surface_id": row["organ_id"],
                "terminal_state": row["terminal_state"],
                "execution_tranche": row["execution_tranche"],
            }
            for row in organ_rows
        ],
        "forbidden_claims_remaining": [
            "C006 externality upgrade remains forbidden.",
            "Router widening or learned cutover remains forbidden.",
            "Product, comparative proof, and standards widening remain forbidden.",
        ],
        "source_refs": [
            FREEZE_RECEIPT_REL,
            ORGAN_REGISTER_REL,
            TOOLS_REGISTER_REL,
            GROWTH_REGISTER_REL,
            WAVE5_STATE_CORE_REL,
            WAVE5_BLOCKER_REL,
            WAVE5_RUNTIME_TRUTH_REL,
        ],
        "tool_rows_count": len(tools_register["rows"]),
        "growth_rows_count": len(growth_register["rows"]),
    }


def build_post_wave5_terminalization_outputs(*, root: Path, telemetry_path: Path) -> Dict[str, Dict[str, Any]]:
    started = telemetry_now_ms()
    head = _git_head(root)
    c007 = load_json((root / C007_REL).resolve())
    c016a = load_json((root / C016A_REL).resolve())
    c016b = load_json((root / C016B_REL).resolve())

    freeze_receipt = _build_freeze_receipt(head=head, c007=c007, c016a=c016a, c016b=c016b)
    organ_register = _build_organ_register(head=head)
    tools_register = _build_tools_register(head=head)
    growth_register = _build_growth_register(head=head)
    truth_matrix = _build_truth_matrix(
        head=head,
        freeze_receipt=freeze_receipt,
        organ_register=organ_register,
        tools_register=tools_register,
        growth_register=growth_register,
    )
    completed = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id="tools.operator.post_wave5_runtime_organ_terminalization_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="post_wave5.runtime_terminalization",
        start_ts=started,
        end_ts=completed,
        result_status="PASS",
        policy_applied="post_wave5.runtime_organ_terminalization",
        receipt_ref=FREEZE_RECEIPT_REL,
        trace_id="post-wave5-runtime-terminalization",
        request_id="post_wave5_runtime_organ_terminalization_validate",
        path=telemetry_path,
    )
    return {
        "freeze_receipt": freeze_receipt,
        "organ_register": organ_register,
        "tools_register": tools_register,
        "growth_register": growth_register,
        "truth_matrix": truth_matrix,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Freeze Post-Wave5 provider wins and emit runtime organ terminal-state registers.")
    parser.add_argument("--freeze-output", default=FREEZE_RECEIPT_REL)
    parser.add_argument("--organ-output", default=ORGAN_REGISTER_REL)
    parser.add_argument("--tools-output", default=TOOLS_REGISTER_REL)
    parser.add_argument("--growth-output", default=GROWTH_REGISTER_REL)
    parser.add_argument("--truth-matrix-output", default=TRUTH_MATRIX_REL)
    parser.add_argument("--telemetry-output", default=TELEMETRY_REL)
    return parser.parse_args(argv)


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    telemetry_path = _resolve(root, str(args.telemetry_output))
    outputs = build_post_wave5_terminalization_outputs(root=root, telemetry_path=telemetry_path)

    write_json_stable(_resolve(root, str(args.freeze_output)), outputs["freeze_receipt"])
    write_json_stable(_resolve(root, str(args.organ_output)), outputs["organ_register"])
    write_json_stable(_resolve(root, str(args.tools_output)), outputs["tools_register"])
    write_json_stable(_resolve(root, str(args.growth_output)), outputs["growth_register"])
    write_json_stable(_resolve(root, str(args.truth_matrix_output)), outputs["truth_matrix"])

    print(
        json.dumps(
            {
                "remaining_open_blockers": outputs["freeze_receipt"]["remaining_open_blockers"],
                "status": outputs["freeze_receipt"]["status"],
                "terminal_state_counts": outputs["organ_register"]["terminal_state_counts"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
