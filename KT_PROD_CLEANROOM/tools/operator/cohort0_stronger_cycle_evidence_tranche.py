from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_PREP_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_stronger_cycle_prep_packet.json"
DEFAULT_FORGE_REGISTRY_REL = "KT_PROD_CLEANROOM/tools/operator/config/forge_cohort0_registry.json"
DEFAULT_ADAPTER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/adapter_registry.json"
DEFAULT_EVIDENCE_PACKET_REL = "KT_PROD_CLEANROOM/reports/cohort0_stronger_cycle_evidence_packet.json"

CHAOS_A_SEED_OFFSET = 1000
HYPERTRAINING_SEED_OFFSET = 2000
CHAOS_B_SEED_OFFSET = 3000


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"FAIL_CLOSED: unable to resolve git HEAD rc={exc.returncode}") from exc


def _parse_adapter_rows(adapter_registry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows = adapter_registry.get("adapter_rows")
    if not isinstance(rows, list):
        raise RuntimeError("FAIL_CLOSED: adapter registry adapter_rows missing/invalid")
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: adapter registry row must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        if not adapter_id:
            raise RuntimeError("FAIL_CLOSED: adapter registry row missing adapter_id")
        out[adapter_id] = row
    return out


def _validate_prep_packet(prep_packet: Dict[str, Any]) -> None:
    if str(prep_packet.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle prep packet must PASS")
    if str(prep_packet.get("prep_posture", "")).strip() != "STRONGER_NEW_CYCLE_REQUIRED__CHAOS_SPECIALIZE_CHAOS_TARGET_BOUND":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle prep packet posture mismatch")
    if str(prep_packet.get("branch_selection_posture", "")).strip() != "CHAOS_A_INDIVIDUAL_HYPERTRAINING_CHAOS_B_BRANCH_SELECTED":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle prep packet branch selection mismatch")
    if str(prep_packet.get("next_lawful_move", "")).strip() != "PREPARE_SCHEMA_BOUND_CHAOS_A_INDIVIDUAL_HYPERTRAINING_CHAOS_B_EVIDENCE":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle prep packet next_lawful_move mismatch")

    summary = prep_packet.get("current_cycle_ceiling_summary") if isinstance(prep_packet.get("current_cycle_ceiling_summary"), dict) else {}
    if bool(summary.get("router_superiority_earned")) is not False:
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence only applies after non-earned router superiority")
    if str(summary.get("canonical_router_status", "")).strip() != "STATIC_CANONICAL_BASELINE_ONLY":
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence requires static canonical baseline hold")
    if int(summary.get("non_stub_eval_entry_count", 0)) != 13:
        raise RuntimeError("FAIL_CLOSED: stronger-cycle evidence requires 13 non-stub eval entries in the current ceiling summary")


def _validate_forge_registry(forge_registry: Dict[str, Any], adapter_rows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    if str(forge_registry.get("schema_id", "")).strip() != "kt.operator.forge_cohort0_registry.unbound.v1":
        raise RuntimeError("FAIL_CLOSED: forge registry schema mismatch")
    if int(forge_registry.get("expected_adapter_count", 0)) != 13:
        raise RuntimeError("FAIL_CLOSED: forge registry expected_adapter_count must be 13")
    adapters = forge_registry.get("adapters")
    if not isinstance(adapters, list) or len(adapters) != 13:
        raise RuntimeError("FAIL_CLOSED: forge registry must contain exactly 13 adapters")

    seen_ids: set[str] = set()
    out: List[Dict[str, Any]] = []
    for row in adapters:
        if not isinstance(row, dict):
            raise RuntimeError("FAIL_CLOSED: forge registry adapter row must be object")
        adapter_id = str(row.get("adapter_id", "")).strip()
        output_name = str(row.get("output_name", "")).strip()
        dataset_relpath = str(row.get("dataset_relpath", "")).strip()
        training_params = row.get("training_params") if isinstance(row.get("training_params"), dict) else {}
        if not adapter_id or not output_name or not dataset_relpath:
            raise RuntimeError("FAIL_CLOSED: forge registry adapter row missing adapter_id/output_name/dataset_relpath")
        if adapter_id in seen_ids:
            raise RuntimeError(f"FAIL_CLOSED: duplicate adapter_id in forge registry: {adapter_id}")
        if adapter_id not in adapter_rows:
            raise RuntimeError(f"FAIL_CLOSED: adapter_id missing from authoritative adapter registry: {adapter_id}")
        seed = int(training_params.get("seed", 0))
        if seed <= 0:
            raise RuntimeError(f"FAIL_CLOSED: invalid seed for {adapter_id}")
        seen_ids.add(adapter_id)
        out.append(row)
    return out


def _build_stage_registry(base_registry: Dict[str, Any], *, registry_id: str, stage_id: str, seed_offset: int) -> Dict[str, Any]:
    registry = json.loads(json.dumps(base_registry))
    registry["registry_id"] = registry_id
    registry["cycle_stage_id"] = stage_id
    registry["default_training_params"] = {
        "engine": "hf_lora",
        "training_mode": "lora",
    }

    updated_rows: List[Dict[str, Any]] = []
    for row in registry["adapters"]:
        row = dict(row)
        training_params = dict(row.get("training_params", {}))
        base_seed = int(training_params.get("seed", 0))
        training_params["seed"] = base_seed + seed_offset
        training_params["engine"] = "hf_lora"
        training_params["training_mode"] = "lora"
        row["training_params"] = training_params
        updated_rows.append(row)
    registry["adapters"] = updated_rows
    return registry


def _parse_adapter_version(adapter_id: str) -> str:
    parts = [part for part in str(adapter_id).split(".") if part]
    if parts and parts[-1].startswith("v"):
        return parts[-1]
    return "v1"


def _build_hypertraining_config(row: Dict[str, Any]) -> Dict[str, Any]:
    training_params = row.get("training_params") if isinstance(row.get("training_params"), dict) else {}
    base_seed = int(training_params.get("seed", 0))
    adapter_id = str(row.get("adapter_id", "")).strip()
    return {
        "schema_id": "kt.operator.cohort0_hypertraining_config.unbound.v1",
        "stage_id": "INDIVIDUAL_HYPERTRAINING__13_ISOLATED_SPECIALIZATION_LANES",
        "job_id": f"cohort0_hypertrain_{adapter_id}",
        "adapter_id": adapter_id,
        "adapter_version": _parse_adapter_version(adapter_id),
        "training_mode": "lora",
        "seed": base_seed + HYPERTRAINING_SEED_OFFSET,
        "max_steps": 3,
        "batch_size": 1,
        "seq_len": 16,
        "lr": 0.0005,
        "lora_rank": 8,
        "lora_alpha": 16,
        "lora_dropout": 0.0,
        "config_claim_boundary": "Bounded stronger-cycle starter config only; not a claim of optimality or executed evidence.",
    }


def _build_hypertraining_lane_contract(
    *,
    row: Dict[str, Any],
    config_path: Path,
    registry_row: Dict[str, Any],
) -> Dict[str, Any]:
    adapter_id = str(row.get("adapter_id", "")).strip()
    dataset_relpath = str(row.get("dataset_relpath", "")).strip()
    return {
        "adapter_id": adapter_id,
        "registry_class": str(registry_row.get("registry_class", "")).strip(),
        "runtime_authority_class": str(registry_row.get("runtime_authority_class", "")).strip(),
        "dataset_relpath": dataset_relpath,
        "config_ref": config_path.as_posix(),
        "command_template": [
            "python",
            "-m",
            "tools.training.rapid_lora_loop",
            "--dataset",
            f"<stage_input_root>/{dataset_relpath}",
            "--config",
            config_path.as_posix(),
            "--engine",
            "hf_lora",
            "--enable-real-engine",
            "--base-model-dir",
            "<base_model_dir>",
            "--out-dir",
            f"<repo_root>/KT_PROD_CLEANROOM/exports/_runs/KT_STRONGER_CYCLE_HYPER/{adapter_id}",
        ],
        "expected_outputs": [
            "training_run_manifest.PASS.json",
            "train_manifest.json",
            "eval_report.json",
            "reasoning_trace.json",
            "dataset_hash_manifest.json",
            "verdict.txt",
            "adapter artifact bundle",
        ],
        "job_dir_manifest_derivation": {
            "mode": "REEXPORT_FROM_EVAL_REPORT_V2",
            "source_helper_ref": "KT_PROD_CLEANROOM/tools/operator/cohort0_tournament_admission_prep_tranche.py::_reexport_job_dir_manifest",
            "required_inputs": ["eval_report.json"],
            "expected_output": "job_dir_manifest.json",
        },
    }


def _build_stage_contract(
    *,
    stage_id: str,
    registry_id: str,
    registry_path: Path,
    run_label: str,
    purpose: str,
    expected_outputs: List[str],
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_cycle_stage_contract.unbound.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "stage_id": stage_id,
        "registry_id": registry_id,
        "registry_ref": registry_path.as_posix(),
        "purpose": purpose,
        "required_operator_inputs": [
            "new authoritative git head distinct from the current proof head",
            "staged_input_root with datasets + base snapshot",
            "base_model_dir containing a local offline model snapshot",
            "external_artifact_root outside the repo tree",
        ],
        "command_template": [
            "python",
            "-m",
            "tools.operator.forge_cohort0",
            "--registry",
            registry_path.as_posix(),
            "--input-root",
            "<staged_input_root>",
            "--artifact-root",
            "<external_artifact_root>",
            "--mode",
            "full",
            "--base-model-dir",
            "<base_model_dir>",
            "--enable-real-engine",
            "--run-label",
            run_label,
        ],
        "expected_outputs": expected_outputs,
    }


def _build_hypertraining_contract(
    *,
    lanes: List[Dict[str, Any]],
    config_root: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_hypertraining_contract.unbound.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "stage_id": "INDIVIDUAL_HYPERTRAINING__13_ISOLATED_SPECIALIZATION_LANES",
        "lane_count": len(lanes),
        "config_root": config_root.as_posix(),
        "execution_boundary": "Each lane executes independently with real-engine hf_lora and requires a same-head output family before Chaos Round B may begin.",
        "lanes": lanes,
    }


def _build_evidence_packet(
    *,
    current_head: str,
    prep_packet_path: Path,
    prep_packet: Dict[str, Any],
    forge_registry_path: Path,
    adapter_registry_path: Path,
    chaos_a_registry_path: Path,
    hypertraining_contract_path: Path,
    chaos_b_registry_path: Path,
    chaos_a_contract_path: Path,
    chaos_b_contract_path: Path,
    hypertraining_lane_count: int,
    adapter_ids: List[str],
) -> Dict[str, Any]:
    summary = prep_packet.get("current_cycle_ceiling_summary") if isinstance(prep_packet.get("current_cycle_ceiling_summary"), dict) else {}
    return {
        "schema_id": "kt.operator.cohort0_stronger_cycle_evidence_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": str(prep_packet.get("subject_head", "")).strip(),
        "source_stronger_cycle_prep_packet_ref": prep_packet_path.as_posix(),
        "source_forge_registry_ref": forge_registry_path.as_posix(),
        "source_authoritative_adapter_registry_ref": adapter_registry_path.as_posix(),
        "evidence_posture": "STRONGER_CYCLE_EVIDENCE_READY__CHAOS_A_HYPERTRAINING_CHAOS_B_BOUND",
        "claim_boundary": (
            "This packet binds only the lab-only stronger-cycle execution evidence surfaces after a truthful non-earned B04.R5 result. "
            "It does not reopen B04.R6, Gate E, Gate F, router authority, or commercialization."
        ),
        "current_cycle_ceiling_summary": {
            "proof_head": str(summary.get("proof_head", "")).strip(),
            "router_superiority_earned": bool(summary.get("router_superiority_earned")),
            "canonical_router_status": str(summary.get("canonical_router_status", "")).strip(),
            "current_tournament_champion_adapter_id": str(summary.get("current_tournament_champion_adapter_id", "")).strip(),
            "current_tournament_dominance_pair_count": int(summary.get("current_tournament_dominance_pair_count", 0)),
            "admissible_parent_pair_count": int(summary.get("admissible_parent_pair_count", 0)),
        },
        "stage_asset_refs": {
            "chaos_round_a_contract_ref": chaos_a_contract_path.as_posix(),
            "chaos_round_a_registry_ref": chaos_a_registry_path.as_posix(),
            "hypertraining_contract_ref": hypertraining_contract_path.as_posix(),
            "chaos_round_b_contract_ref": chaos_b_contract_path.as_posix(),
            "chaos_round_b_registry_ref": chaos_b_registry_path.as_posix(),
        },
        "adapter_count": len(adapter_ids),
        "hypertraining_lane_count": hypertraining_lane_count,
        "adapter_ids": adapter_ids,
        "execution_input_contract": {
            "new_authoritative_head_required": True,
            "stage_input_root_required": True,
            "base_model_dir_required": True,
            "external_artifact_root_required": True,
            "out_of_repo_worm_artifact_root_required": True,
        },
        "job_dir_manifest_strategy": {
            "mode": "REEXPORT_FROM_EVAL_REPORT_V2",
            "source_helper_ref": "KT_PROD_CLEANROOM/tools/operator/cohort0_tournament_admission_prep_tranche.py::_reexport_job_dir_manifest",
            "reason": "rapid_lora_loop emits eval_report.json, train_manifest.json, and training_run_manifest.PASS.json but not job_dir_manifest.json",
        },
        "success_criteria": [
            "Chaos Round A, all 13 hypertraining lanes, and Chaos Round B must run on a new authoritative head distinct from the current proof head.",
            "All 13 lanes must produce non-stub outputs with hf_lora engine plus eval_report.json, train_manifest.json, and training_run_manifest.PASS.json.",
            "The stronger-cycle downstream graph must then be rerun through the existing non-stub eval, tournament, merge, router-shadow, and R5 law surfaces without skipping steps.",
            "Only an actually earned future router_superiority_earned = true result may reopen B04.R6, Gate E, or Gate F.",
        ],
        "non_forward_motion_classes": [
            "Running Chaos A or Chaos B with stub engines or stub-eval artifacts.",
            "Skipping the 13 individual hypertraining lanes.",
            "Treating a new registry or config file as evidence without executing it on a new head.",
            "Jumping from training directly to router proof without new graph/tournament/merge surfaces.",
            "Narrating B04.R6, Gate E, Gate F, or commercialization from another non-earned proof line.",
        ],
        "next_lawful_move": "EXECUTE_CHAOS_A_ON_NEW_AUTHORITATIVE_HEAD_WITH_REAL_STAGE_INPUTS",
    }


def run_stronger_cycle_evidence_tranche(
    *,
    prep_packet_path: Path,
    forge_registry_path: Path,
    adapter_registry_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_prep_path, prep_packet = _resolve_authoritative(
        root,
        prep_packet_path.resolve(),
        "authoritative_stronger_cycle_prep_packet_ref",
        "cohort0 stronger cycle prep packet",
    )
    forge_registry = _load_json_required(forge_registry_path.resolve(), label="forge cohort0 registry")
    adapter_registry = _load_json_required(adapter_registry_path.resolve(), label="authoritative adapter registry")

    _validate_prep_packet(prep_packet)
    adapter_rows = _parse_adapter_rows(adapter_registry)
    validated_forge_rows = _validate_forge_registry(forge_registry, adapter_rows)

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_stronger_cycle_evidence_current_head").resolve()
    target_root.mkdir(parents=True, exist_ok=True)

    chaos_a_root = (target_root / "chaos_round_a").resolve()
    chaos_b_root = (target_root / "chaos_round_b").resolve()
    hyper_root = (target_root / "individual_hypertraining").resolve()
    config_root = (hyper_root / "configs").resolve()
    for path in (chaos_a_root, chaos_b_root, hyper_root, config_root):
        path.mkdir(parents=True, exist_ok=True)

    chaos_a_registry = _build_stage_registry(
        forge_registry,
        registry_id="KT_OPERATOR_FORGE_COHORT0_STRONGER_CYCLE_CHAOS_A_V1",
        stage_id="CHAOS_ROUND_A__ALL_13_SHARED_PRESSURE",
        seed_offset=CHAOS_A_SEED_OFFSET,
    )
    chaos_b_registry = _build_stage_registry(
        forge_registry,
        registry_id="KT_OPERATOR_FORGE_COHORT0_STRONGER_CYCLE_CHAOS_B_V1",
        stage_id="CHAOS_ROUND_B__REINTEGRATED_SHARED_PRESSURE",
        seed_offset=CHAOS_B_SEED_OFFSET,
    )

    chaos_a_registry_path = (chaos_a_root / "forge_cohort0_registry_hf_lora.json").resolve()
    chaos_b_registry_path = (chaos_b_root / "forge_cohort0_registry_hf_lora.json").resolve()
    write_json_stable(chaos_a_registry_path, chaos_a_registry)
    write_json_stable(chaos_b_registry_path, chaos_b_registry)

    lanes: List[Dict[str, Any]] = []
    for row in validated_forge_rows:
        adapter_id = str(row.get("adapter_id", "")).strip()
        config = _build_hypertraining_config(row)
        config_path = (config_root / f"{adapter_id}.rapid_lora_config.json").resolve()
        write_json_stable(config_path, config)
        lanes.append(
            _build_hypertraining_lane_contract(
                row=row,
                config_path=config_path,
                registry_row=adapter_rows[adapter_id],
            )
        )

    hyper_contract = _build_hypertraining_contract(lanes=lanes, config_root=config_root)
    hyper_contract_path = (hyper_root / "hypertraining_contract.json").resolve()
    write_json_stable(hyper_contract_path, hyper_contract)

    chaos_a_contract = _build_stage_contract(
        stage_id="CHAOS_ROUND_A__ALL_13_SHARED_PRESSURE",
        registry_id=str(chaos_a_registry.get("registry_id", "")).strip(),
        registry_path=chaos_a_registry_path,
        run_label="cohort0_stronger_cycle_chaos_a",
        purpose="Create a broader shared-pressure substrate across all 13 adapters before the specialization lanes.",
        expected_outputs=[
            "13 adapter_training_receipt.json",
            "13 adapter_reload_receipt.json",
            "13 adapter_eval_receipt.json",
            "run_manifest.json",
            "run_summary.json",
            "adapter_registry.json",
            "adapter_lineage_manifest.json",
        ],
    )
    chaos_b_contract = _build_stage_contract(
        stage_id="CHAOS_ROUND_B__REINTEGRATED_SHARED_PRESSURE",
        registry_id=str(chaos_b_registry.get("registry_id", "")).strip(),
        registry_path=chaos_b_registry_path,
        run_label="cohort0_stronger_cycle_chaos_b",
        purpose="Recombine the specialized set under shared pressure so the downstream graph can change structurally.",
        expected_outputs=[
            "13 adapter_training_receipt.json",
            "13 adapter_reload_receipt.json",
            "13 adapter_eval_receipt.json",
            "run_manifest.json",
            "run_summary.json",
            "adapter_registry.json",
            "adapter_lineage_manifest.json",
        ],
    )
    chaos_a_contract_path = (chaos_a_root / "chaos_round_a_execution_contract.json").resolve()
    chaos_b_contract_path = (chaos_b_root / "chaos_round_b_execution_contract.json").resolve()
    write_json_stable(chaos_a_contract_path, chaos_a_contract)
    write_json_stable(chaos_b_contract_path, chaos_b_contract)

    evidence_packet = _build_evidence_packet(
        current_head=_git_head(root),
        prep_packet_path=authoritative_prep_path,
        prep_packet=prep_packet,
        forge_registry_path=forge_registry_path.resolve(),
        adapter_registry_path=adapter_registry_path.resolve(),
        chaos_a_registry_path=chaos_a_registry_path,
        hypertraining_contract_path=hyper_contract_path,
        chaos_b_registry_path=chaos_b_registry_path,
        chaos_a_contract_path=chaos_a_contract_path,
        chaos_b_contract_path=chaos_b_contract_path,
        hypertraining_lane_count=len(lanes),
        adapter_ids=[str(row.get("adapter_id", "")).strip() for row in validated_forge_rows],
    )
    authoritative_packet_path = (target_root / "cohort0_stronger_cycle_evidence_packet.json").resolve()
    write_json_stable(authoritative_packet_path, evidence_packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_packet = dict(evidence_packet)
    tracked_packet["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_STRONGER_CYCLE_EVIDENCE_PACKET"
    tracked_packet["authoritative_stronger_cycle_evidence_packet_ref"] = authoritative_packet_path.as_posix()
    tracked_packet_path = (reports_root / Path(DEFAULT_EVIDENCE_PACKET_REL).name).resolve()
    write_json_stable(tracked_packet_path, tracked_packet)

    return {
        "stronger_cycle_evidence_packet": evidence_packet,
        "tracked_stronger_cycle_evidence_packet": tracked_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind schema-facing stronger-cycle execution evidence after stronger-cycle prep is selected.")
    ap.add_argument("--prep-packet", default=DEFAULT_PREP_PACKET_REL)
    ap.add_argument("--forge-registry", default=DEFAULT_FORGE_REGISTRY_REL)
    ap.add_argument("--adapter-registry", default=DEFAULT_ADAPTER_REGISTRY_REL)
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: <repo>/tmp/cohort0_stronger_cycle_evidence_current_head",
    )
    ap.add_argument(
        "--reports-root",
        default="KT_PROD_CLEANROOM/reports",
        help="Tracked carrier report root. Default: KT_PROD_CLEANROOM/reports",
    )
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_stronger_cycle_evidence_tranche(
        prep_packet_path=_resolve_path(root, str(args.prep_packet)),
        forge_registry_path=_resolve_path(root, str(args.forge_registry)),
        adapter_registry_path=_resolve_path(root, str(args.adapter_registry)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    packet = payload["stronger_cycle_evidence_packet"]
    print(
        json.dumps(
            {
                "status": packet["status"],
                "evidence_posture": packet["evidence_posture"],
                "hypertraining_lane_count": packet["hypertraining_lane_count"],
                "next_lawful_move": packet["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
