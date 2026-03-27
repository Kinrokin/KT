from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from tools.operator.c017_spine_carriage_validate import build_c017_receipt
from tools.operator.single_spine_path_validate import build_single_spine_receipts
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.toolchain_runtime_firewall_validate import build_toolchain_runtime_firewall_receipt
from tools.operator.w1_runtime_realization_validate import (
    build_mvcr_live_execution_receipt,
    build_organ_dependency_resolution_receipt,
    build_provider_path_integrity_receipt,
    build_runtime_realism_threshold,
    build_useful_output_benchmark,
    upgrade_organ_disposition_register,
)


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/b02_runtime_unify"

CANONICAL_SCOPE_RECEIPT_REL = f"{REPORT_ROOT_REL}/canonical_scope_manifest_receipt.json"
RUNTIME_BOUNDARY_RECEIPT_REL = f"{REPORT_ROOT_REL}/runtime_boundary_receipt.json"
SINGLE_SPINE_RECEIPT_REL = f"{REPORT_ROOT_REL}/single_spine_path_receipt.json"
TOOLCHAIN_FIREWALL_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave0_5_toolchain_runtime_firewall_receipt.json"
C017_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_remediation_receipt.json"
C017_TELEMETRY_REL = f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl"
USEFUL_OUTPUT_RECEIPT_REL = f"{REPORT_ROOT_REL}/useful_output_benchmark.json"
PROVIDER_PATH_RECEIPT_REL = f"{REPORT_ROOT_REL}/provider_path_integrity_receipt.json"
ORGAN_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_wave2c_organ_disposition_register.json"
ORGAN_DEPENDENCY_REL = f"{REPORT_ROOT_REL}/organ_dependency_resolution_receipt.json"
MVCR_RECEIPT_REL = f"{REPORT_ROOT_REL}/mvcr_live_execution_receipt.json"
W1_TELEMETRY_REL = f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl"

B02_PATH_AGREEMENT_REL = f"{REPORT_ROOT_REL}/b02_runtime_path_agreement_receipt.json"
B02_ORGAN_HONESTY_REL = f"{REPORT_ROOT_REL}/b02_organ_honesty_receipt.json"
B02_UNIFY_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_receipt.json"

EXECUTION_BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"


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


def _head_value(payload: Mapping[str, Any]) -> str:
    for key in ("current_git_head", "validated_head_sha", "runtime_boundary_subject_commit"):
        value = str(payload.get(key, "")).strip()
        if value:
            return value
    return ""


def _find_useful_output_row(payload: Mapping[str, Any], benchmark_id: str) -> Mapping[str, Any]:
    for row in payload.get("rows", []):
        if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip() == benchmark_id:
            return row
    return {}


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def build_b02_runtime_unify_outputs(
    *,
    root: Path,
    export_root: Path,
    report_root_rel: str = REPORT_ROOT_REL,
    c017_telemetry_path: Path,
    w1_telemetry_path: Path,
) -> Dict[str, Dict[str, Any]]:
    head = _git_head(root)
    export_root.mkdir(parents=True, exist_ok=True)

    single_spine = build_single_spine_receipts(
        root=root,
        report_root_rel=report_root_rel,
        export_root=(export_root / "single_spine").resolve(),
    )
    toolchain_firewall = build_toolchain_runtime_firewall_receipt(root=root)
    c017_receipt = build_c017_receipt(
        root=root,
        telemetry_path=c017_telemetry_path,
        export_root=(export_root / "c017").resolve(),
    )

    useful_output = build_useful_output_benchmark(
        root=root,
        export_root=(export_root / "w1_runtime_realization").resolve(),
        telemetry_path=w1_telemetry_path,
    )
    provider_path_integrity = build_provider_path_integrity_receipt(root=root)
    organ_register = upgrade_organ_disposition_register(
        root=root,
        provider_path_ref=PROVIDER_PATH_RECEIPT_REL,
        mvcr_ref=MVCR_RECEIPT_REL,
    )
    runtime_realism_threshold = build_runtime_realism_threshold(
        organ_register=organ_register,
        useful_output_benchmark=useful_output,
        provider_path_integrity=provider_path_integrity,
    )
    organ_dependency_resolution = build_organ_dependency_resolution_receipt(
        root=root,
        organ_register=organ_register,
        runtime_realism_threshold=runtime_realism_threshold,
    )
    mvcr_receipt = build_mvcr_live_execution_receipt(
        root=root,
        useful_output_benchmark=useful_output,
        provider_path_integrity=provider_path_integrity,
        organ_dependency_resolution=organ_dependency_resolution,
        runtime_realism_threshold=runtime_realism_threshold,
    )
    execution_board = load_json(root / EXECUTION_BOARD_REL)

    path_agreement_receipt = build_b02_runtime_path_agreement_receipt(
        root=root,
        head=head,
        single_spine=single_spine,
        toolchain_firewall=toolchain_firewall,
        c017_receipt=c017_receipt,
        useful_output=useful_output,
        provider_path_integrity=provider_path_integrity,
        organ_dependency_resolution=organ_dependency_resolution,
        mvcr_receipt=mvcr_receipt,
    )
    organ_honesty_receipt = build_b02_organ_honesty_receipt(
        root=root,
        head=head,
        organ_register=organ_register,
        runtime_realism_threshold=runtime_realism_threshold,
    )
    b02_unify_receipt = build_b02_runtime_unify_receipt(
        head=head,
        single_spine=single_spine,
        toolchain_firewall=toolchain_firewall,
        c017_receipt=c017_receipt,
        useful_output=useful_output,
        provider_path_integrity=provider_path_integrity,
        organ_dependency_resolution=organ_dependency_resolution,
        mvcr_receipt=mvcr_receipt,
        path_agreement_receipt=path_agreement_receipt,
        organ_honesty_receipt=organ_honesty_receipt,
        execution_board=execution_board,
    )

    return {
        "canonical_scope_manifest_receipt": single_spine["canonical_scope_manifest_receipt"],
        "runtime_boundary_receipt": single_spine["runtime_boundary_receipt"],
        "single_spine_path_receipt": single_spine["single_spine_path_receipt"],
        "toolchain_runtime_firewall_receipt": toolchain_firewall,
        "c017_spine_carriage_receipt": c017_receipt,
        "useful_output_benchmark": useful_output,
        "provider_path_integrity_receipt": provider_path_integrity,
        "organ_disposition_register": organ_register,
        "organ_dependency_resolution_receipt": organ_dependency_resolution,
        "mvcr_live_execution_receipt": mvcr_receipt,
        "b02_runtime_path_agreement_receipt": path_agreement_receipt,
        "b02_organ_honesty_receipt": organ_honesty_receipt,
        "b02_runtime_unify_receipt": b02_unify_receipt,
    }


def build_b02_runtime_path_agreement_receipt(
    *,
    root: Path,
    head: str,
    single_spine: Mapping[str, Mapping[str, Any]],
    toolchain_firewall: Mapping[str, Any],
    c017_receipt: Mapping[str, Any],
    useful_output: Mapping[str, Any],
    provider_path_integrity: Mapping[str, Any],
    organ_dependency_resolution: Mapping[str, Any],
    mvcr_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    single_spine_receipt = single_spine["single_spine_path_receipt"]
    runtime_boundary_receipt = single_spine["runtime_boundary_receipt"]
    canonical_scope_receipt = single_spine["canonical_scope_manifest_receipt"]

    component_rows: List[Dict[str, Any]] = []
    for component_id, payload in (
        ("canonical_scope_manifest", canonical_scope_receipt),
        ("runtime_boundary", runtime_boundary_receipt),
        ("single_spine_path", single_spine_receipt),
        ("toolchain_runtime_firewall", toolchain_firewall),
        ("useful_output_benchmark", useful_output),
        ("provider_path_integrity", provider_path_integrity),
        ("organ_dependency_resolution", organ_dependency_resolution),
        ("mvcr_live_execution", mvcr_receipt),
    ):
        observed_head = _head_value(payload)
        component_rows.append(
            {
                "component_id": component_id,
                "status": _status(payload),
                "observed_head": observed_head,
                "head_match_required": bool(observed_head),
                "head_matches_current": observed_head == head if observed_head else True,
            }
        )

    component_rows.append(
        {
            "component_id": "c017_spine_carriage",
            "status": _status(c017_receipt),
            "observed_head": "",
            "head_match_required": False,
            "head_matches_current": True,
        }
    )

    useful_output_row = _find_useful_output_row(useful_output, "useful_output_evidence_stronger_than_ceremonial_path_evidence")
    provider_ids = sorted(str(item).strip() for item in provider_path_integrity.get("same_host_live_hashed_provider_ids", []) if str(item).strip())
    c017_carriage_ok = all(
        isinstance(row, dict) and str(row.get("status", "")).strip().upper() == "PASS"
        for row in c017_receipt.get("carriage_matrix", [])
    )
    mvcr_code_bindings = [str(item).strip() for item in mvcr_receipt.get("code_path_bindings", []) if str(item).strip()]
    mvcr_allowed_claims = [str(item).strip() for item in mvcr_receipt.get("runtime_claim_compilation", {}).get("allowed_current_claims", []) if str(item).strip()]
    checks = [
        {
            "check_id": "all_component_receipts_pass",
            "pass": all(row["status"] == "PASS" for row in component_rows),
        },
        {
            "check_id": "head_bound_receipts_match_current_head",
            "pass": all(row["head_matches_current"] for row in component_rows if row["head_match_required"]),
        },
        {
            "check_id": "single_claim_bearing_runtime_lane_is_fixed",
            "pass": (
                str(single_spine_receipt.get("canonical_entry_callable", "")).strip() == "kt.entrypoint.invoke"
                and str(single_spine_receipt.get("canonical_spine_callable", "")).strip() == "core.spine.run"
            ),
        },
        {
            "check_id": "c017_carriage_and_oversize_guard_pass",
            "pass": c017_carriage_ok
            and str(c017_receipt.get("oversize_guard", {}).get("status", "")).strip().upper() == "PASS"
            and bool(c017_receipt.get("oversize_guard", {}).get("message_match")),
        },
        {
            "check_id": "useful_output_is_bound_to_the_runtime_path",
            "pass": bool(useful_output_row.get("pass")),
        },
        {
            "check_id": "provider_path_is_current_head_same_host_live_hashed_only",
            "pass": provider_ids == ["openai", "openrouter"],
        },
        {
            "check_id": "mvcr_replay_and_lineage_agree_on_the_runtime_path",
            "pass": (
                _is_pass(mvcr_receipt)
                and str(mvcr_receipt.get("runtime_claim_compilation", {}).get("status", "")).strip().upper() == "PASS"
                and "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py" in mvcr_code_bindings
                and "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py" in mvcr_code_bindings
                and "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/state_vault.py" in mvcr_code_bindings
                and "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/memory/replay.py" in mvcr_code_bindings
                and any("kt.entrypoint.invoke -> core.spine.run" in claim for claim in mvcr_allowed_claims)
            ),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.runtime_path_agreement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 first tranche aligns claim-bearing path, off-spine enforcement, useful output, provider path, replay, and claim compilation on current head only.",
        "component_rows": component_rows,
        "checks": checks,
        "runtime_lane": "kt.entrypoint.invoke -> core.spine.run",
        "mvcr_code_path_bindings": mvcr_code_bindings,
        "same_host_live_hashed_provider_ids": provider_ids,
        "forbidden_claims_remaining": [
            "Do not claim promotion civilization is ratified.",
            "Do not claim router or lobe superiority.",
            "Do not widen externality, comparative, or product language.",
        ],
    }


def build_b02_organ_honesty_receipt(
    *,
    root: Path,
    head: str,
    organ_register: Mapping[str, Any],
    runtime_realism_threshold: Mapping[str, Any],
) -> Dict[str, Any]:
    rows = organ_register.get("rows", [])
    row_by_id = {
        str(row.get("organ_id", "")).strip(): row
        for row in rows
        if isinstance(row, dict) and str(row.get("organ_id", "")).strip()
    }

    def row(organ_id: str) -> Mapping[str, Any]:
        return row_by_id.get(organ_id, {})

    checks = [
        {
            "check_id": "router_is_static_canonical_only",
            "pass": str(row("router").get("claim_ceiling", "")).strip() == "STATIC_CANONICAL_BASELINE_ONLY",
        },
        {
            "check_id": "toolchain_orchestrators_remain_quarantined",
            "pass": (
                str(row("toolchain_only_orchestrators").get("zone", "")).strip() == "TOOLCHAIN_PROVING"
                and str(row("toolchain_only_orchestrators").get("plane", "")).strip() == "QUARANTINED"
            ),
        },
        {
            "check_id": "teacher_growth_surfaces_remain_lab_only",
            "pass": (
                str(row("teacher_growth_surfaces").get("zone", "")).strip() == "LAB"
                and str(row("teacher_growth_surfaces").get("plane", "")).strip() == "QUARANTINED"
            ),
        },
        {
            "check_id": "memory_is_explicitly_claim_bearing",
            "pass": (
                str(row("memory").get("zone", "")).strip() == "CANONICAL"
                and str(row("memory").get("plane", "")).strip() == "GENERATED_RUNTIME_TRUTH"
            ),
        },
        {
            "check_id": "claim_compiler_is_explicitly_claim_bearing",
            "pass": (
                str(row("claim_compiler").get("zone", "")).strip() == "CANONICAL"
                and str(row("claim_compiler").get("plane", "")).strip() == "GENERATED_RUNTIME_TRUTH"
            ),
        },
        {
            "check_id": "cognition_summary_stays_bounded",
            "pass": "bounded" in str(row("cognition").get("bounded_summary", "")).lower(),
        },
        {
            "check_id": "council_summary_stays_same_host_bounded",
            "pass": "same_host" in str(row("council").get("claim_ceiling", "")).lower(),
        },
        {
            "check_id": "adapter_layer_does_not_launder_breadth",
            "pass": str(row("adapter_layer").get("claim_ceiling", "")).strip()
            in {"CANONICAL_SAME_HOST_LIVE_HASHED_ONLY", "CURRENT_HEAD_BOUNDED_UNIVERSAL_ADAPTER_CONTRACT_ONLY"},
        },
        {
            "check_id": "tournament_promotion_is_not_claimed_as_canonical_cutover",
            "pass": str(row("tournament_promotion").get("claim_ceiling", "")).strip()
            in {"LAB_GOVERNED_ONLY", "CURRENT_HEAD_BOUNDED_INTERNAL_CIVILIZATION_LOOP_ONLY"},
        },
        {
            "check_id": "runtime_realism_threshold_keeps_glamour_locked",
            "pass": (
                str(runtime_realism_threshold.get("status", "")).strip().upper() == "PASS"
                and not bool(runtime_realism_threshold.get("glamour_unlock"))
            ),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.organ_honesty_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 first tranche refreshes organ honesty against current code reality without promoting later adaptive surfaces.",
        "checks": checks,
        "organ_rows": [
            row_by_id[organ_id]
            for organ_id in (
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
                "claim_compiler",
            )
            if organ_id in row_by_id
        ],
        "stronger_claims_not_made": [
            "promotion civilization ratified",
            "learned router cutover earned",
            "multi-lobe execution earned",
            "training or growth surfaces promoted into canonical runtime",
        ],
    }


def build_b02_runtime_unify_receipt(
    *,
    head: str,
    single_spine: Mapping[str, Mapping[str, Any]],
    toolchain_firewall: Mapping[str, Any],
    c017_receipt: Mapping[str, Any],
    useful_output: Mapping[str, Any],
    provider_path_integrity: Mapping[str, Any],
    organ_dependency_resolution: Mapping[str, Any],
    mvcr_receipt: Mapping[str, Any],
    path_agreement_receipt: Mapping[str, Any],
    organ_honesty_receipt: Mapping[str, Any],
    execution_board: Mapping[str, Any],
) -> Dict[str, Any]:
    domain = execution_board.get("current_constitutional_domain", {})
    program_gates = execution_board.get("program_gates", {})
    status = "PASS" if all(
        _is_pass(payload)
        for payload in (
            single_spine["single_spine_path_receipt"],
            toolchain_firewall,
            c017_receipt,
            useful_output,
            provider_path_integrity,
            organ_dependency_resolution,
            mvcr_receipt,
            path_agreement_receipt,
            organ_honesty_receipt,
        )
    ) else "FAIL"

    return {
        "schema_id": "kt.b02.runtime_unify_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "tranche_id": "B02_GATE_B_RUNTIME_UNIFY_T1",
        "scope_boundary": "First counted B02 runtime-unification tranche only. This tranche proves one governed claim-bearing live path, bans off-spine live execution, refreshes organ honesty, and aligns replay/useful-output/lineage on current head. It does not ratify promotion civilization or open Gate C.",
        "current_domain": {
            "domain_id": str(domain.get("domain_id", "")).strip(),
            "title": str(domain.get("title", "")).strip(),
        },
        "entry_gate_status": bool(program_gates.get("H1_ACTIVATION_ALLOWED")),
        "exit_gate_status": bool(program_gates.get("PROMOTION_CIVILIZATION_RATIFIED")),
        "earned_current_head_claims": [
            "One governed claim-bearing runtime path remains fixed at kt.entrypoint.invoke -> core.spine.run on current head.",
            "Off-spine live execution remains blocked by the toolchain/runtime firewall and runtime-boundary law.",
            "Replay, useful-output, provider-path, and bounded claim compilation now agree on the current-head runtime path.",
            "Organ honesty is refreshed against current code reality, and glamour surfaces remain locked.",
        ],
        "component_refs": [
            CANONICAL_SCOPE_RECEIPT_REL,
            RUNTIME_BOUNDARY_RECEIPT_REL,
            SINGLE_SPINE_RECEIPT_REL,
            TOOLCHAIN_FIREWALL_RECEIPT_REL,
            C017_RECEIPT_REL,
            USEFUL_OUTPUT_RECEIPT_REL,
            PROVIDER_PATH_RECEIPT_REL,
            ORGAN_REGISTER_REL,
            ORGAN_DEPENDENCY_REL,
            MVCR_RECEIPT_REL,
            B02_PATH_AGREEMENT_REL,
            B02_ORGAN_HONESTY_REL,
        ],
        "attacks_weakened": [
            "split runtime scaffolding can still carry claim-bearing truth outside the canonical spine",
            "toolchain or lab surfaces can silently act as live runtime",
            "replay/useful-output/lineage are disconnected and can be laundered independently",
            "organ labels still outrun current code reality",
        ],
        "forbidden_claims_remaining": [
            "Do not claim B02 is complete.",
            "Do not claim promotion civilization is ratified.",
            "Do not claim router or lobe superiority.",
            "Do not widen externality, comparative, product, or prestige language.",
        ],
        "next_lawful_move": "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute the first counted B02 runtime-unification tranche on current head.")
    parser.add_argument("--canonical-scope-output", default=CANONICAL_SCOPE_RECEIPT_REL)
    parser.add_argument("--runtime-boundary-output", default=RUNTIME_BOUNDARY_RECEIPT_REL)
    parser.add_argument("--single-spine-output", default=SINGLE_SPINE_RECEIPT_REL)
    parser.add_argument("--toolchain-firewall-output", default=TOOLCHAIN_FIREWALL_RECEIPT_REL)
    parser.add_argument("--c017-output", default=C017_RECEIPT_REL)
    parser.add_argument("--c017-telemetry-output", default=C017_TELEMETRY_REL)
    parser.add_argument("--useful-output-output", default=USEFUL_OUTPUT_RECEIPT_REL)
    parser.add_argument("--provider-path-output", default=PROVIDER_PATH_RECEIPT_REL)
    parser.add_argument("--organ-register-output", default=ORGAN_REGISTER_REL)
    parser.add_argument("--organ-dependency-output", default=ORGAN_DEPENDENCY_REL)
    parser.add_argument("--mvcr-output", default=MVCR_RECEIPT_REL)
    parser.add_argument("--w1-telemetry-output", default=W1_TELEMETRY_REL)
    parser.add_argument("--path-agreement-output", default=B02_PATH_AGREEMENT_REL)
    parser.add_argument("--organ-honesty-output", default=B02_ORGAN_HONESTY_REL)
    parser.add_argument("--receipt-output", default=B02_UNIFY_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    export_root = _resolve(root, str(args.export_root))
    outputs = {
        "canonical_scope_manifest_receipt": _resolve(root, str(args.canonical_scope_output)),
        "runtime_boundary_receipt": _resolve(root, str(args.runtime_boundary_output)),
        "single_spine_path_receipt": _resolve(root, str(args.single_spine_output)),
        "toolchain_runtime_firewall_receipt": _resolve(root, str(args.toolchain_firewall_output)),
        "c017_spine_carriage_receipt": _resolve(root, str(args.c017_output)),
        "useful_output_benchmark": _resolve(root, str(args.useful_output_output)),
        "provider_path_integrity_receipt": _resolve(root, str(args.provider_path_output)),
        "organ_disposition_register": _resolve(root, str(args.organ_register_output)),
        "organ_dependency_resolution_receipt": _resolve(root, str(args.organ_dependency_output)),
        "mvcr_live_execution_receipt": _resolve(root, str(args.mvcr_output)),
        "b02_runtime_path_agreement_receipt": _resolve(root, str(args.path_agreement_output)),
        "b02_organ_honesty_receipt": _resolve(root, str(args.organ_honesty_output)),
        "b02_runtime_unify_receipt": _resolve(root, str(args.receipt_output)),
    }

    built = build_b02_runtime_unify_outputs(
        root=root,
        export_root=export_root,
        c017_telemetry_path=_resolve(root, str(args.c017_telemetry_output)),
        w1_telemetry_path=_resolve(root, str(args.w1_telemetry_output)),
    )

    for key, path in outputs.items():
        write_json_stable(path, built[key])

    summary = {
        "status": built["b02_runtime_unify_receipt"]["status"],
        "entry_gate_status": built["b02_runtime_unify_receipt"]["entry_gate_status"],
        "exit_gate_status": built["b02_runtime_unify_receipt"]["exit_gate_status"],
        "next_lawful_move": built["b02_runtime_unify_receipt"]["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if built["b02_runtime_unify_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
