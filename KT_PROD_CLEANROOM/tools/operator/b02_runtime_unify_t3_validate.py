from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from core.runtime_registry import load_runtime_registry
from memory.replay import validate_state_vault_chain
import memory.state_vault as state_vault_module
from memory.state_vault import StateVault, StateVaultCorruptionError, StateVaultWriteError, resolve_state_vault_path
from tools.operator.b02_runtime_unify_t2_validate import build_b02_runtime_unify_t2_outputs
from tools.operator.runtime_organ_realization_validate import (
    _build_multiverse_pack,
    _build_paradox_pack,
    _build_temporal_pack,
    _registry_hash,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/b02_runtime_unify_t3"

EXECUTION_BOARD_REL = "KT_PROD_CLEANROOM/governance/execution_board.json"
STATE_VAULT_DISCIPLINE_REL = "KT_PROD_CLEANROOM/governance/state_vault_mutation_discipline.json"

B02_T1_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_receipt.json"
B02_T2_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t2_receipt.json"
B02_T3_STATE_VAULT_REL = f"{REPORT_ROOT_REL}/b02_state_vault_lawfulness_receipt.json"
B02_T3_ORGAN_TRUTH_REL = f"{REPORT_ROOT_REL}/b02_residual_organ_truth_receipt.json"
B02_T3_EXIT_GAP_REL = f"{REPORT_ROOT_REL}/b02_exit_gap_receipt.json"
B02_T3_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t3_receipt.json"


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


def _row_by_id(organ_register: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {
        str(row.get("organ_id", "")).strip(): row
        for row in organ_register.get("rows", [])
        if isinstance(row, dict) and str(row.get("organ_id", "")).strip()
    }


def _check_row(check_id: str, passed: bool, **details: Any) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "pass": bool(passed),
        **details,
    }


def _contract_requires_expected_values(contract: Mapping[str, Any]) -> bool:
    return (
        str(contract.get("status", "")).strip() == "ACTIVE"
        and str(contract.get("mutation_discipline", "")).strip() == "SEQUENTIAL_ONLY_SHARED_APPEND_LOG"
        and str(contract.get("parallel_validation_policy", "")).strip() == "FORBIDDEN_ON_SHARED_CANONICAL_VAULT"
        and list(contract.get("required_fail_closed_modes", [])) == ["APPEND_LOCK_BUSY", "STALE_WRITER_HEAD_MISMATCH"]
        and str(contract.get("permitted_parallel_alternative", "")).strip() == "ISOLATED_SNAPSHOT_OR_TEMPORARY_VAULT_ONLY"
    )


def _state_vault_busy_lock_fails_closed() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "state_vault.jsonl"
        vault = StateVault(path=path)
        lock_path = path.with_name(path.name + ".lock")
        lock_path.write_text("busy", encoding="utf-8")

        original_timeout = state_vault_module._AppendLock._TIMEOUT_SECONDS
        original_poll = state_vault_module._AppendLock._POLL_SECONDS
        state_vault_module._AppendLock._TIMEOUT_SECONDS = 0.01
        state_vault_module._AppendLock._POLL_SECONDS = 0.001
        try:
            try:
                vault.append(event_type="E1", organ_id="Spine")
            except StateVaultWriteError as exc:
                return {
                    "pass": "append lock busy" in str(exc).lower(),
                    "message": str(exc),
                }
            return {
                "pass": False,
                "message": "append unexpectedly succeeded with busy lock",
            }
        finally:
            state_vault_module._AppendLock._TIMEOUT_SECONDS = original_timeout
            state_vault_module._AppendLock._POLL_SECONDS = original_poll
            if lock_path.exists():
                lock_path.unlink()


def _state_vault_stale_writer_fails_closed() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "state_vault.jsonl"
        first = StateVault(path=path)
        second = StateVault(path=path)
        first.append(event_type="E1", organ_id="Spine")
        try:
            second.append(event_type="E2", organ_id="Spine")
        except StateVaultCorruptionError as exc:
            return {
                "pass": "head mismatch" in str(exc).lower(),
                "message": str(exc),
            }
        return {
            "pass": False,
            "message": "stale writer append unexpectedly succeeded",
        }


def _state_vault_sequential_append_passes() -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "state_vault.jsonl"
        vault = StateVault(path=path)
        first = vault.append(event_type="E1", organ_id="Spine")
        second = vault.append(event_type="E2", organ_id="Spine")
        replay = validate_state_vault_chain(path)
        return {
            "pass": replay.record_count == 2 and replay.head_hash == second.head_hash and first.head_hash != second.head_hash,
            "record_count": replay.record_count,
            "head_hash": replay.head_hash,
        }


def build_b02_state_vault_lawfulness_receipt(*, root: Path, head: str) -> Dict[str, Any]:
    contract = load_json(root / STATE_VAULT_DISCIPLINE_REL)
    registry = load_runtime_registry()
    default_vault_path = resolve_state_vault_path()
    registry_vault_path = registry.resolve_state_vault_jsonl_path()
    sequential = _state_vault_sequential_append_passes()
    stale_writer = _state_vault_stale_writer_fails_closed()
    busy_lock = _state_vault_busy_lock_fails_closed()

    checks = [
        _check_row(
            "state_vault_contract_declares_sequential_only_shared_append_log",
            _contract_requires_expected_values(contract),
        ),
        _check_row(
            "state_vault_default_path_matches_runtime_registry",
            default_vault_path == registry_vault_path,
            default_path=default_vault_path.as_posix(),
            registry_path=registry_vault_path.as_posix(),
        ),
        _check_row(
            "shared_state_vault_sequential_append_and_replay_pass",
            bool(sequential["pass"]),
            record_count=sequential["record_count"],
        ),
        _check_row(
            "stale_writer_fails_closed_on_head_mismatch",
            bool(stale_writer["pass"]),
            message=stale_writer["message"],
        ),
        _check_row(
            "busy_append_lock_fails_closed",
            bool(busy_lock["pass"]),
            message=busy_lock["message"],
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.state_vault_lawfulness_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 3 codifies sequential-only shared canonical state-vault discipline and verifies fail-closed lock and stale-writer behavior. It does not widen runtime capability claims.",
        "contract_ref": STATE_VAULT_DISCIPLINE_REL,
        "canonical_state_vault_ref": f"KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/{registry.state_vault.jsonl_path}",
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim parallel shared-vault execution is admissible.",
            "Do not claim isolated snapshot replay has been promoted into canonical runtime.",
        ],
    }


def _bounded_summary_has(row: Mapping[str, Any], *keywords: str) -> bool:
    summary = str(row.get("bounded_summary", "")).lower()
    return all(keyword.lower() in summary for keyword in keywords)


def build_b02_residual_organ_truth_receipt(
    *,
    head: str,
    organ_register: Mapping[str, Any],
    state_vault_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    row_map = _row_by_id(organ_register)
    registry_hash = _registry_hash()
    temporal_pack = _build_temporal_pack(registry_hash=registry_hash)
    paradox_pack = _build_paradox_pack()
    multiverse_pack = _build_multiverse_pack(registry_hash=registry_hash)

    checks = [
        _check_row(
            "temporal_pack_passes_and_register_stays_bounded",
            _is_pass(temporal_pack)
            and _bounded_summary_has(row_map.get("temporal", {}), "bounded", "replay")
            and str(row_map.get("temporal", {}).get("claim_ceiling", "")).strip() == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
        ),
        _check_row(
            "paradox_pack_passes_and_register_stays_bounded_gate_only",
            _is_pass(paradox_pack)
            and _bounded_summary_has(row_map.get("paradox", {}), "bounded", "contradiction")
            and str(row_map.get("paradox", {}).get("claim_ceiling", "")).strip() == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
        ),
        _check_row(
            "multiverse_pack_passes_and_register_stays_bounded_ranker_only",
            _is_pass(multiverse_pack)
            and _bounded_summary_has(row_map.get("multiverse", {}), "bounded", "candidate")
            and str(row_map.get("multiverse", {}).get("claim_ceiling", "")).strip() == "SCOPED_TIER_BOUNDED_CURRENT_HEAD_ORGANISM_E1",
        ),
        _check_row(
            "memory_register_matches_append_only_replay_truth",
            _is_pass(state_vault_receipt)
            and _bounded_summary_has(row_map.get("memory", {}), "append-only", "replay")
            and str(row_map.get("memory", {}).get("zone", "")).strip() == "CANONICAL"
            and str(row_map.get("memory", {}).get("plane", "")).strip() == "GENERATED_RUNTIME_TRUTH",
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.residual_organ_truth_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 3 tightens residual temporal/paradox/multiverse/memory truth against live bounded code behavior without promoting those organs above their current ceilings.",
        "checks": checks,
        "observed_organ_truth": [
            {
                "organ_id": "temporal",
                "register_summary": row_map.get("temporal", {}).get("bounded_summary", ""),
                "observed_summary": temporal_pack.get("bounded_summary", ""),
                "status": temporal_pack.get("status", ""),
            },
            {
                "organ_id": "paradox",
                "register_summary": row_map.get("paradox", {}).get("bounded_summary", ""),
                "observed_summary": paradox_pack.get("bounded_summary", ""),
                "status": paradox_pack.get("status", ""),
            },
            {
                "organ_id": "multiverse",
                "register_summary": row_map.get("multiverse", {}).get("bounded_summary", ""),
                "observed_summary": multiverse_pack.get("bounded_summary", ""),
                "status": multiverse_pack.get("status", ""),
            },
            {
                "organ_id": "memory",
                "register_summary": row_map.get("memory", {}).get("bounded_summary", ""),
                "observed_summary": "Memory remains append-only state-vault plus replay-chain validation under explicit sequential shared-vault discipline.",
                "status": state_vault_receipt.get("status", ""),
            },
        ],
        "forbidden_claims_remaining": [
            "Do not claim full temporal execution history.",
            "Do not claim broad paradox metabolism.",
            "Do not claim broad multiverse search or superiority.",
            "Do not claim memory supports parallel shared canonical mutation.",
        ],
    }


def build_b02_exit_gap_receipt(
    *,
    head: str,
    execution_board: Mapping[str, Any],
    organ_register: Mapping[str, Any],
    t2_receipt: Mapping[str, Any],
    state_vault_receipt: Mapping[str, Any],
    residual_organ_truth_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    row_map = _row_by_id(organ_register)
    remaining_exit_blockers = [
        {
            "blocker_id": "PROMOTION_CIVILIZATION_RATIFIED_FALSE",
            "evidence_ref": EXECUTION_BOARD_REL,
            "why": "Domain 2 exit gate remains false on the execution board.",
        },
        {
            "blocker_id": "ROUTER_STATIC_CANONICAL_BASELINE_ONLY",
            "organ_id": "router",
            "claim_ceiling": row_map.get("router", {}).get("claim_ceiling", ""),
            "evidence_ref": row_map.get("router", {}).get("receipt", ""),
            "why": "Router remains static canonical baseline only; learned superiority is not earned.",
        },
        {
            "blocker_id": "ADAPTER_LAYER_BREADTH_AND_CUTOVER_REMAIN_BOUNDED",
            "organ_id": "adapter_layer",
            "claim_ceiling": row_map.get("adapter_layer", {}).get("claim_ceiling", ""),
            "evidence_ref": row_map.get("adapter_layer", {}).get("receipt", ""),
            "why": "Adapter layer is still bounded to the universal contract over narrow live breadth.",
        },
        {
            "blocker_id": "TOURNAMENT_PROMOTION_NOT_CANONICAL_RUNTIME_CUTOVER",
            "organ_id": "tournament_promotion",
            "claim_ceiling": row_map.get("tournament_promotion", {}).get("claim_ceiling", ""),
            "evidence_ref": row_map.get("tournament_promotion", {}).get("receipt", ""),
            "why": "Promotion loop is real but runtime cutover remains separately gated and unearned.",
        },
        {
            "blocker_id": "TEACHER_GROWTH_SURFACES_LAB_ONLY",
            "organ_id": "teacher_growth_surfaces",
            "claim_ceiling": row_map.get("teacher_growth_surfaces", {}).get("claim_ceiling", ""),
            "evidence_ref": row_map.get("teacher_growth_surfaces", {}).get("receipt", ""),
            "why": "Teacher/growth surfaces remain lab-only and cannot count as canonical runtime.",
        },
    ]

    checks = [
        _check_row(
            "t2_runtime_unification_receipt_remains_pass",
            _is_pass(t2_receipt),
        ),
        _check_row(
            "state_vault_lawfulness_is_now_explicit_and_pass",
            _is_pass(state_vault_receipt),
        ),
        _check_row(
            "residual_organ_truth_is_explicit_and_pass",
            _is_pass(residual_organ_truth_receipt),
        ),
        _check_row(
            "entry_gate_open_but_exit_gate_not_yet_earned",
            bool(execution_board.get("program_gates", {}).get("H1_ACTIVATION_ALLOWED"))
            and not bool(execution_board.get("program_gates", {}).get("PROMOTION_CIVILIZATION_RATIFIED")),
        ),
        _check_row(
            "remaining_exit_blockers_are_machine_enumerated",
            bool(remaining_exit_blockers),
            blocker_count=len(remaining_exit_blockers),
        ),
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.exit_gap_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 3 enumerates remaining runtime-unification exit blockers on current head. It does not open Gate C.",
        "exit_ready": False,
        "checks": checks,
        "closed_ambiguities": [
            "Shared canonical state-vault mutation discipline is explicit and fail-closed.",
            "Temporal/paradox/multiverse/memory bounded summaries now align with observed current-head behavior.",
            "Ingress, dependency truth, and multi-organ path agreement are already receipted on the canonical runtime lane.",
        ],
        "remaining_exit_blockers": remaining_exit_blockers,
    }


def build_b02_runtime_unify_t3_outputs(
    *,
    root: Path,
    export_root: Path,
    c017_telemetry_path: Path,
    w1_telemetry_path: Path,
) -> Dict[str, Dict[str, Any]]:
    head = _git_head(root)
    export_root.mkdir(parents=True, exist_ok=True)
    t2_outputs = build_b02_runtime_unify_t2_outputs(
        root=root,
        export_root=(export_root / "t2_refresh").resolve(),
        c017_telemetry_path=c017_telemetry_path,
        w1_telemetry_path=w1_telemetry_path,
    )
    execution_board = load_json(root / EXECUTION_BOARD_REL)
    state_vault_receipt = build_b02_state_vault_lawfulness_receipt(root=root, head=head)
    residual_organ_truth_receipt = build_b02_residual_organ_truth_receipt(
        head=head,
        organ_register=t2_outputs["organ_disposition_register"],
        state_vault_receipt=state_vault_receipt,
    )
    exit_gap_receipt = build_b02_exit_gap_receipt(
        head=head,
        execution_board=execution_board,
        organ_register=t2_outputs["organ_disposition_register"],
        t2_receipt=t2_outputs["b02_runtime_unify_t2_receipt"],
        state_vault_receipt=state_vault_receipt,
        residual_organ_truth_receipt=residual_organ_truth_receipt,
    )
    t3_receipt = build_b02_runtime_unify_t3_receipt(
        head=head,
        t2_receipt=t2_outputs["b02_runtime_unify_t2_receipt"],
        state_vault_receipt=state_vault_receipt,
        residual_organ_truth_receipt=residual_organ_truth_receipt,
        exit_gap_receipt=exit_gap_receipt,
    )
    return {
        **t2_outputs,
        "b02_state_vault_lawfulness_receipt": state_vault_receipt,
        "b02_residual_organ_truth_receipt": residual_organ_truth_receipt,
        "b02_exit_gap_receipt": exit_gap_receipt,
        "b02_runtime_unify_t3_receipt": t3_receipt,
    }


def build_b02_runtime_unify_t3_receipt(
    *,
    head: str,
    t2_receipt: Mapping[str, Any],
    state_vault_receipt: Mapping[str, Any],
    residual_organ_truth_receipt: Mapping[str, Any],
    exit_gap_receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    status = "PASS" if all(
        _is_pass(payload)
        for payload in (t2_receipt, state_vault_receipt, residual_organ_truth_receipt, exit_gap_receipt)
    ) else "FAIL"
    return {
        "schema_id": "kt.b02.runtime_unify_t3_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "tranche_id": "B02_GATE_B_RUNTIME_UNIFY_T3",
        "scope_boundary": "Third counted B02 tranche only. This tranche codifies sequential state-vault lawfulness, tightens residual organ truth, and machine-enumerates remaining B02 exit gaps without opening Gate C.",
        "entry_gate_status": bool(t2_receipt.get("entry_gate_status")),
        "exit_gate_status": bool(exit_gap_receipt.get("exit_ready")),
        "earned_current_head_claims": [
            "Shared canonical state-vault mutation and validator execution are now explicitly sequential-only and fail-closed on lock or stale-writer conflict.",
            "Temporal, paradox, multiverse, and memory surfaces now have explicit bounded runtime truth aligned to live current-head behavior.",
            "Remaining B02 exit blockers are now mechanically enumerated instead of narrative, and Gate C stays closed until they clear.",
        ],
        "component_refs": [
            B02_T1_RECEIPT_REL,
            B02_T2_RECEIPT_REL,
            B02_T3_STATE_VAULT_REL,
            B02_T3_ORGAN_TRUTH_REL,
            B02_T3_EXIT_GAP_REL,
        ],
        "forbidden_claims_remaining": [
            "Do not claim B02 is complete.",
            "Do not claim Gate C is open.",
            "Do not widen civilization, externality, product, or prestige language.",
        ],
        "next_lawful_move": "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute B02 runtime-unification tranche 3 on current head.")
    parser.add_argument("--c017-telemetry-output", default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl")
    parser.add_argument("--w1-telemetry-output", default=f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl")
    parser.add_argument("--state-vault-lawfulness-output", default=B02_T3_STATE_VAULT_REL)
    parser.add_argument("--residual-organ-truth-output", default=B02_T3_ORGAN_TRUTH_REL)
    parser.add_argument("--exit-gap-output", default=B02_T3_EXIT_GAP_REL)
    parser.add_argument("--receipt-output", default=B02_T3_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_b02_runtime_unify_t3_outputs(
        root=root,
        export_root=_resolve(root, str(args.export_root)),
        c017_telemetry_path=_resolve(root, str(args.c017_telemetry_output)),
        w1_telemetry_path=_resolve(root, str(args.w1_telemetry_output)),
    )

    write_json_stable(_resolve(root, str(args.state_vault_lawfulness_output)), outputs["b02_state_vault_lawfulness_receipt"])
    write_json_stable(_resolve(root, str(args.residual_organ_truth_output)), outputs["b02_residual_organ_truth_receipt"])
    write_json_stable(_resolve(root, str(args.exit_gap_output)), outputs["b02_exit_gap_receipt"])
    write_json_stable(_resolve(root, str(args.receipt_output)), outputs["b02_runtime_unify_t3_receipt"])

    summary = {
        "status": outputs["b02_runtime_unify_t3_receipt"]["status"],
        "entry_gate_status": outputs["b02_runtime_unify_t3_receipt"]["entry_gate_status"],
        "exit_gate_status": outputs["b02_runtime_unify_t3_receipt"]["exit_gate_status"],
        "next_lawful_move": outputs["b02_runtime_unify_t3_receipt"]["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["b02_runtime_unify_t3_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
