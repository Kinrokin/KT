from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from tools.operator.titanium_common import repo_root, write_json_stable
from tools.operator.w3_civilization_common import (
    CIVILIZATION_LOOP_CONTRACT_REL,
    UNIVERSAL_ADAPTER_ABI_V2_REL,
    build_civilization_loop_contract,
    run_w3_cycle,
)


DEFAULT_CIVILIZATION_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/civilization_loop_receipt.json"
DEFAULT_ROLLBACK_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/rollback_drill_receipt.json"
DEFAULT_LEARNING_RESPONSE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/learning_response_receipt.json"


def _write(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / rel).resolve(), payload)


def build_rollback_drill_receipt(*, contract: Dict[str, Any], cycle: Dict[str, Any]) -> Dict[str, Any]:
    rollback = cycle["rollback_report"]
    checks = [
        {
            "check_id": "rollback_restores_original_registry_bytes",
            "pass": bool(rollback.get("restored_matches_original")),
        },
        {
            "check_id": "rollback_mutation_was_nontrivial",
            "pass": rollback.get("original_sha256") != rollback.get("mutated_sha256"),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w3.rollback_drill_receipt.v1",
        "generated_utc": contract["generated_utc"],
        "current_git_head": cycle["current_git_head"],
        "status": status,
        "runtime_registry_path_ref": cycle["runtime_registry_path_ref"],
        "rollback_work_dir_ref": cycle["rollback_work_dir_ref"],
        "original_sha256": rollback["original_sha256"],
        "mutated_sha256": rollback["mutated_sha256"],
        "restored_sha256": rollback["restored_sha256"],
        "checks": checks,
        "claim_boundary": "W3 proves rollback discipline on the runtime-registry surface only. It does not claim cross-host replay or automatic runtime cutover rollback.",
        "forbidden_claims_not_made": [
            "rollback_drill_proves_externality",
            "rollback_drill_proves_full_runtime_cutover",
        ],
    }


def build_learning_response_receipt(*, contract: Dict[str, Any], cycle: Dict[str, Any], rollback_receipt: Dict[str, Any]) -> Dict[str, Any]:
    checks = [
        {
            "check_id": "eval_report_passes",
            "pass": cycle["eval_report"]["final_verdict"] == "PASS",
        },
        {
            "check_id": "fitness_region_a_required_for_improvement",
            "pass": cycle["fitness_region"]["fitness_region"] == "A",
        },
        {
            "check_id": "signal_quality_candidate_or_better",
            "pass": cycle["signal_quality"]["status"] in {"CANDIDATE", "PROMOTED"},
        },
        {
            "check_id": "promotion_decision_promote",
            "pass": cycle["promotion"]["decision"] == "PROMOTE",
        },
        {
            "check_id": "phase_trace_has_no_stub_execution",
            "pass": bool(cycle["phase_trace"].get("no_stub_executed")),
        },
        {
            "check_id": "rollback_receipt_passes",
            "pass": rollback_receipt["status"] == "PASS",
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w3.learning_response_receipt.v1",
        "generated_utc": contract["generated_utc"],
        "current_git_head": cycle["current_git_head"],
        "status": status,
        "learning_response_status": "BOUNDED_SAFE_IMPROVEMENT_PROVED" if status == "PASS" else "FAIL_CLOSED",
        "job_dir_ref": cycle["job_dir_ref"],
        "promotion_decision": cycle["promotion"]["decision"],
        "eval_verdict": cycle["eval_report"]["final_verdict"],
        "fitness_region": cycle["fitness_region"]["fitness_region"],
        "checks": checks,
        "claim_boundary": (
            "W3 proves one bounded improvement proposal can be evaluated, promotion-decided, and rollback-bound on current head. "
            "It does not claim live runtime cutover, autonomous self-improvement, or benchmark superiority."
        ),
        "forbidden_claims_not_made": [
            "autonomous_live_runtime_self_modification",
            "benchmark_superiority_earned",
            "externality_class_widened_above_E1",
        ],
    }


def build_civilization_loop_receipt(*, contract: Dict[str, Any], cycle: Dict[str, Any], rollback_receipt: Dict[str, Any], learning_response_receipt: Dict[str, Any]) -> Dict[str, Any]:
    checks = [
        {
            "check_id": "blind_pack_emitted",
            "pass": cycle["blind_pack"]["schema_id"] == "kt.blind_judgement_pack.v1",
        },
        {
            "check_id": "reveal_mapping_sealed_then_unsealed",
            "pass": cycle["reveal_mapping_sealed"]["sealed"] is True and cycle["reveal_mapping"]["sealed"] is False,
        },
        {
            "check_id": "tournament_manifest_present",
            "pass": cycle["tournament_manifest"]["schema_id"] == "kt.tournament_manifest.v1",
        },
        {
            "check_id": "promotion_decision_promote",
            "pass": cycle["promotion"]["decision"] == "PROMOTE",
        },
        {
            "check_id": "promotion_rationale_present",
            "pass": cycle["promotion_rationale"]["decision"] == "PROMOTE",
        },
        {
            "check_id": "rollback_receipt_passes",
            "pass": rollback_receipt["status"] == "PASS",
        },
        {
            "check_id": "learning_response_receipt_passes",
            "pass": learning_response_receipt["status"] == "PASS",
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.w3.civilization_loop_receipt.v1",
        "generated_utc": contract["generated_utc"],
        "current_git_head": cycle["current_git_head"],
        "status": status,
        "civilization_loop_status": "PASS" if status == "PASS" else "FAIL_CLOSED",
        "job_dir_ref": cycle["job_dir_ref"],
        "exact_loop": contract["exact_loop"],
        "promotion_decision": cycle["promotion"]["decision"],
        "rollback_bound": rollback_receipt["status"] == "PASS",
        "checks": checks,
        "claim_boundary": contract["claim_boundary"],
        "source_refs": [
            CIVILIZATION_LOOP_CONTRACT_REL,
            UNIVERSAL_ADAPTER_ABI_V2_REL,
            cycle["job_dir_ref"],
        ],
        "forbidden_claims_not_made": [
            "automatic_runtime_cutover_completed",
            "externality_widened_above_E1",
            "public_tournament_readiness_unblocked",
            "router_or_lobe_superiority_earned",
        ],
    }


def build_civilization_loop_outputs(*, root: Path) -> Dict[str, Any]:
    contract = build_civilization_loop_contract(root=root)
    cycle = run_w3_cycle(root=root)
    rollback_receipt = build_rollback_drill_receipt(contract=contract, cycle=cycle)
    learning_response_receipt = build_learning_response_receipt(contract=contract, cycle=cycle, rollback_receipt=rollback_receipt)
    civilization_loop_receipt = build_civilization_loop_receipt(
        contract=contract,
        cycle=cycle,
        rollback_receipt=rollback_receipt,
        learning_response_receipt=learning_response_receipt,
    )
    return {
        "contract": contract,
        "rollback_receipt": rollback_receipt,
        "learning_response_receipt": learning_response_receipt,
        "civilization_loop_receipt": civilization_loop_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the bounded W3 civilization loop.")
    parser.add_argument("--contract-output", default=CIVILIZATION_LOOP_CONTRACT_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_CIVILIZATION_RECEIPT_REL)
    parser.add_argument("--rollback-output", default=DEFAULT_ROLLBACK_RECEIPT_REL)
    parser.add_argument("--learning-output", default=DEFAULT_LEARNING_RESPONSE_RECEIPT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_civilization_loop_outputs(root=root)
    _write(root, str(args.contract_output), outputs["contract"])
    _write(root, str(args.rollback_output), outputs["rollback_receipt"])
    _write(root, str(args.learning_output), outputs["learning_response_receipt"])
    _write(root, str(args.receipt_output), outputs["civilization_loop_receipt"])
    summary = {
        "promotion_decision": outputs["civilization_loop_receipt"]["promotion_decision"],
        "status": outputs["civilization_loop_receipt"]["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["civilization_loop_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
