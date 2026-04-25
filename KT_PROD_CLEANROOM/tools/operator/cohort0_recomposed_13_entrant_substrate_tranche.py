from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator import cohort0_tournament_admission_prep_tranche as prep_tranche
from tools.operator import cohort0_tournament_fragility_probe_tranche as fragility_tranche
from tools.operator.titanium_common import load_json, repo_root, utc_now_compact_z, utc_now_iso_z, write_json_stable


DEFAULT_BASE_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_import_receipt.json"
DEFAULT_BASE_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_adapter_grade_receipt.json"
DEFAULT_BASE_REEXPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_entrant_authority_reexport_contract.json"
DEFAULT_TARGETED_IMPORT_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_import_receipt.json"
DEFAULT_TARGETED_GRADE_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_grade_receipt.json"
DEFAULT_TARGETED_STAGE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_targeted_hypertraining_stage_input_receipt.json"

DEFAULT_RECOMPOSED_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_manifest.json"
DEFAULT_RECOMPOSED_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_substrate_receipt.json"
DEFAULT_RECOMPOSED_FOLLOWTHROUGH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_13_entrant_followthrough_packet.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path.resolve(), label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    if authoritative_ref:
        authoritative_path = _resolve(root, authoritative_ref)
        return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")
    return tracked_path.resolve(), tracked


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_governance_adapter_ids(root: Path) -> List[str]:
    registry = _load_json_required(root / "KT_PROD_CLEANROOM" / "governance" / "adapter_registry.json", label="governance adapter registry")
    rows = list(registry.get("experimental_adapter_ids", [])) + list(registry.get("ratified_adapter_ids", []))
    adapter_ids = [str(x).strip() for x in rows if str(x).strip()]
    if len(adapter_ids) != 13 or len(set(adapter_ids)) != 13:
        raise RuntimeError("FAIL_CLOSED: governance adapter registry must resolve exactly 13 unique adapter ids")
    return adapter_ids


def _entry_by_adapter(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for row in entries:
        if isinstance(row, dict):
            adapter_id = str(row.get("adapter_id", "")).strip()
            if adapter_id:
                result[adapter_id] = row
    return result


def _targeted_inventory_map(targeted_import_path: Path) -> Dict[str, Dict[str, Any]]:
    inventory_path = targeted_import_path.parent / "cohort0_targeted_hypertraining_adapter_inventory.json"
    inventory = _load_json_required(inventory_path, label="targeted hypertraining adapter inventory")
    entries = inventory.get("entries") if isinstance(inventory.get("entries"), list) else []
    return _entry_by_adapter(entries)


def _baseline_inventory_map(base_import_path: Path) -> Dict[str, Dict[str, Any]]:
    inventory_path = base_import_path.parent / "cohort0_real_engine_adapter_inventory.json"
    inventory = _load_json_required(inventory_path, label="baseline adapter inventory")
    entries = inventory.get("entries") if isinstance(inventory.get("entries"), list) else []
    return _entry_by_adapter(entries)


def _targeted_bundle_root(targeted_import: Dict[str, Any]) -> Path:
    return _resolve(Path("/"), str(targeted_import.get("bundle_root", "")).strip())


def _copy_eval_report(source_path: Path, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, target_path)


def _copy_if_exists(source_path: Path, target_path: Path) -> None:
    if source_path.is_file():
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)


def _build_targeted_inventory_entry(*, adapter_id: str, bundle_root: Path, targeted_row: Dict[str, Any]) -> Dict[str, Any]:
    adapter_root = (bundle_root / "adapters" / adapter_id).resolve()
    training_receipt_ref = (adapter_root / "adapter_training_receipt.json").resolve()
    eval_receipt_ref = (adapter_root / "adapter_eval_receipt.json").resolve()
    reload_receipt_ref = (adapter_root / "adapter_reload_receipt.json").resolve()
    training_receipt = _load_json_required(training_receipt_ref, label=f"targeted training receipt {adapter_id}")
    eval_receipt = _load_json_required(eval_receipt_ref, label=f"targeted eval receipt {adapter_id}")
    return {
        "adapter_id": adapter_id,
        "adapter_root": adapter_root.as_posix(),
        "artifact_bytes": int(targeted_row.get("artifact_bytes", 0)),
        "artifact_path": str(targeted_row.get("artifact_path", "")).strip(),
        "artifact_sha256": str(targeted_row.get("artifact_sha256", "")).strip(),
        "baseline_eval_score": float(targeted_row.get("baseline_eval_score", 0.0)),
        "dataset_relpath": str(targeted_row.get("dataset_relpath", "")).strip(),
        "dataset_sha256": str(targeted_row.get("dataset_sha256", "")).strip(),
        "engine": "hf_lora",
        "eval_case_count": int(targeted_row.get("eval_case_count", 0)),
        "eval_receipt_ref": eval_receipt_ref.as_posix(),
        "eval_status": str(eval_receipt.get("status", "")).strip(),
        "promotion_ready_artifacts_present": bool(eval_receipt.get("promotion_ready_artifacts_present")),
        "reload_receipt_ref": reload_receipt_ref.as_posix(),
        "reload_status": "PASS",
        "source_eval_report_path": str(training_receipt.get("source_eval_report_path", "")).strip(),
        "source_eval_stub": bool(eval_receipt.get("source_eval_stub")),
        "source_train_manifest_path": str(training_receipt.get("source_train_manifest_path", "")).strip(),
        "source_training_run_manifest_path": str(training_receipt.get("source_training_run_manifest_path", "")).strip(),
        "training_mode": str(training_receipt.get("training_mode", "")).strip(),
        "training_receipt_ref": training_receipt_ref.as_posix(),
        "training_status": str(training_receipt.get("status", "")).strip(),
    }


def _recomposed_manifest(
    *,
    subject_head: str,
    current_head: str,
    updated_ids: List[str],
    control_ids: List[str],
    entries: List[Dict[str, Any]],
    authoritative_base_import_path: Path,
    authoritative_targeted_import_path: Path,
    prep_packet_path: Path,
    reexport_contract_path: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_recomposed_13_entrant_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This manifest binds only the recomposed 13-entrant substrate: six refreshed targeted-hypertraining entrants "
            "plus seven explicitly unchanged controls. It does not claim tournament, merge, router, or Gate E/F outcomes."
        ),
        "updated_entrant_ids": updated_ids,
        "carryforward_control_ids": control_ids,
        "entries": entries,
        "source_refs": {
            "baseline_import_receipt_ref": authoritative_base_import_path.as_posix(),
            "targeted_import_receipt_ref": authoritative_targeted_import_path.as_posix(),
            "reexport_contract_ref": reexport_contract_path.as_posix(),
            "prep_packet_ref": prep_packet_path.as_posix(),
        },
    }


def _recomposed_receipt(
    *,
    subject_head: str,
    current_head: str,
    prep_packet: Dict[str, Any],
    updated_ids: List[str],
    control_ids: List[str],
    recomposed_manifest_path: Path,
    reexport_contract_path: Path,
    import_receipt_path: Path,
    grade_receipt_path: Path,
) -> Dict[str, Any]:
    prep_posture = str(prep_packet.get("prep_posture", "")).strip()
    tournament_rerun_admissible = prep_posture == "TOURNAMENT_EXECUTION_READY"
    return {
        "schema_id": "kt.operator.cohort0_recomposed_13_entrant_substrate_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This receipt proves only that the six refreshed entrants and seven carryforward controls have been mechanically "
            "recomposed into one 13-entrant substrate and passed tournament-admission preparation on that recomposed root. "
            "It does not claim tournament outcomes, merge outcomes, router superiority, or Gate E/F opening."
        ),
        "recomposition_posture": (
            "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_RERUN_ADMISSIBLE"
            if tournament_rerun_admissible
            else "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_RERUN_NOT_YET_ADMISSIBLE"
        ),
        "updated_entrant_ids": updated_ids,
        "carryforward_control_ids": control_ids,
        "prep_posture": prep_posture,
        "tournament_rerun_admissible": tournament_rerun_admissible,
        "merge_rerun_admissible": False,
        "router_shadow_rerun_admissible": False,
        "r5_rerun_admissible": False,
        "next_lawful_move": "EXECUTE_RECOMPOSED_TOURNAMENT" if tournament_rerun_admissible else str(prep_packet.get("next_lawful_move", "")).strip(),
        "recomposed_manifest_ref": recomposed_manifest_path.as_posix(),
        "reexport_contract_ref": reexport_contract_path.as_posix(),
        "synthetic_import_receipt_ref": import_receipt_path.as_posix(),
        "synthetic_grade_receipt_ref": grade_receipt_path.as_posix(),
    }


def _recomposed_followthrough(
    *,
    prep_packet: Dict[str, Any],
    updated_ids: List[str],
    control_ids: List[str],
    reexport_contract_path: Path,
    prep_packet_path: Path,
) -> Dict[str, Any]:
    prep_posture = str(prep_packet.get("prep_posture", "")).strip()
    return {
        "schema_id": "kt.operator.cohort0_recomposed_13_entrant_followthrough_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "followthrough_posture": (
            "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__TOURNAMENT_EXECUTION_READY"
            if prep_posture == "TOURNAMENT_EXECUTION_READY"
            else "RECOMPOSED_13_ENTRANT_SUBSTRATE_BOUND__FOLLOWTHROUGH_STILL_BLOCKED"
        ),
        "claim_boundary": (
            "This followthrough packet answers only whether the recomposed 13-entrant substrate is now legally consumable by the downstream proof lane. "
            "It does not claim that tournament, merge, router shadow, or R5 have already moved."
        ),
        "updated_entrant_ids": updated_ids,
        "carryforward_control_ids": control_ids,
        "tournament_rerun_admissible": prep_posture == "TOURNAMENT_EXECUTION_READY",
        "merge_rerun_admissible": False,
        "router_shadow_rerun_admissible": False,
        "r5_rerun_admissible": False,
        "next_lawful_move": "EXECUTE_RECOMPOSED_TOURNAMENT" if prep_posture == "TOURNAMENT_EXECUTION_READY" else str(prep_packet.get("next_lawful_move", "")).strip(),
        "blockers": [] if prep_posture == "TOURNAMENT_EXECUTION_READY" else list(prep_packet.get("blockers", [])),
        "reexport_contract_ref": reexport_contract_path.as_posix(),
        "prep_packet_ref": prep_packet_path.as_posix(),
    }


def _extract_prep_packet(prep_payload: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(prep_payload.get("prep_packet"), dict):
        return prep_payload["prep_packet"]
    if isinstance(prep_payload.get("tournament_prep_packet"), dict):
        return prep_payload["tournament_prep_packet"]
    raise RuntimeError("FAIL_CLOSED: tournament prep tranche did not return a prep packet")


def run_recomposed_13_entrant_substrate_tranche(
    *,
    base_import_report_path: Path,
    base_grade_report_path: Path,
    base_reexport_report_path: Path,
    targeted_import_report_path: Path,
    targeted_grade_report_path: Path,
    targeted_stage_receipt_path: Path,
    authoritative_root: Path,
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()

    authoritative_base_import_path, base_import = _resolve_authoritative(
        root, base_import_report_path, "authoritative_import_receipt_ref", "baseline import receipt"
    )
    authoritative_base_grade_path, base_grade = _resolve_authoritative(
        root, base_grade_report_path, "authoritative_grade_receipt_ref", "baseline grade receipt"
    )
    authoritative_base_reexport_path, base_reexport = _resolve_authoritative(
        root, base_reexport_report_path, "authoritative_reexport_contract_ref", "baseline entrant reexport contract"
    )
    authoritative_targeted_import_path, targeted_import = _resolve_authoritative(
        root, targeted_import_report_path, "authoritative_targeted_hypertraining_import_receipt_ref", "targeted import receipt"
    )
    authoritative_targeted_grade_path, targeted_grade = _resolve_authoritative(
        root, targeted_grade_report_path, "authoritative_targeted_hypertraining_grade_receipt_ref", "targeted grade receipt"
    )
    authoritative_stage_receipt_path, targeted_stage_receipt = _resolve_authoritative(
        root, targeted_stage_receipt_path, "authoritative_targeted_hypertraining_stage_input_receipt_ref", "targeted stage receipt"
    )

    if str(base_import.get("subject_head", "")).strip() != str(targeted_import.get("subject_head", "")).strip():
        raise RuntimeError("FAIL_CLOSED: baseline and targeted imports must agree on subject_head")
    if str(base_grade.get("grade", "")).strip() != "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE":
        raise RuntimeError("FAIL_CLOSED: baseline grade must remain PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE")
    if str(targeted_grade.get("grade", "")).strip() != "PASS_AS_STRONGER_CYCLE_TARGETED_HYPERTRAINING_EVIDENCE":
        raise RuntimeError("FAIL_CLOSED: targeted grade mismatch")
    if str(targeted_import.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: targeted import must PASS")

    authoritative_ids = _load_governance_adapter_ids(root)
    target_ids = [str(x).strip() for x in targeted_stage_receipt.get("target_lobe_ids", [])]
    if len(target_ids) != 6:
        raise RuntimeError("FAIL_CLOSED: targeted stage receipt must bind 6 target ids")
    control_ids = [adapter_id for adapter_id in authoritative_ids if adapter_id not in target_ids]

    base_inventory = _baseline_inventory_map(authoritative_base_import_path)
    targeted_inventory = _targeted_inventory_map(authoritative_targeted_import_path)
    baseline_entries = base_reexport.get("entries") if isinstance(base_reexport.get("entries"), list) else []
    baseline_reexport_map = _entry_by_adapter(baseline_entries)
    targeted_bundle_root = _targeted_bundle_root(targeted_import)

    for adapter_id in authoritative_ids:
        if adapter_id in target_ids:
            if adapter_id not in targeted_inventory:
                raise RuntimeError(f"FAIL_CLOSED: missing targeted inventory row for {adapter_id}")
        else:
            if adapter_id not in base_inventory or adapter_id not in baseline_reexport_map:
                raise RuntimeError(f"FAIL_CLOSED: missing baseline control surfaces for {adapter_id}")
            if list(baseline_reexport_map[adapter_id].get("missing_for_tournament_entry", [])):
                raise RuntimeError(f"FAIL_CLOSED: control entrant not tournament-admissible: {adapter_id}")

    base_model_hashes = set()
    for adapter_id in authoritative_ids:
        if adapter_id in target_ids:
            receipt_path = targeted_bundle_root / "adapters" / adapter_id / "adapter_training_receipt.json"
        else:
            receipt_path = Path(str(base_inventory[adapter_id]["training_receipt_ref"])).resolve()
        training_receipt = _load_json_required(receipt_path, label=f"training receipt for {adapter_id}")
        base_model_hashes.add(str(training_receipt.get("base_model_root_hash", "")).strip())
    if len(base_model_hashes) != 1:
        raise RuntimeError("FAIL_CLOSED: recomposed substrate requires one shared base_model_root_hash")

    authoritative_root = authoritative_root.resolve()
    authoritative_root.mkdir(parents=True, exist_ok=True)
    synthetic_root = (authoritative_root / "synthetic_import").resolve()
    supplemental_root = (authoritative_root / "composite_supplemental_eval").resolve()
    prep_root = (authoritative_root / "tournament_prep").resolve()
    internal_reports_root = (authoritative_root / "internal_reports").resolve()
    for path in (synthetic_root, supplemental_root, prep_root, internal_reports_root):
        path.mkdir(parents=True, exist_ok=True)

    recomposed_entries: List[Dict[str, Any]] = []
    manifest_entries: List[Dict[str, Any]] = []
    for adapter_id in authoritative_ids:
        supplemental_eval_target = (supplemental_root / adapter_id / "eval_report.json").resolve()
        if adapter_id in target_ids:
            entry = _build_targeted_inventory_entry(adapter_id=adapter_id, bundle_root=targeted_bundle_root, targeted_row=targeted_inventory[adapter_id])
            eval_source = targeted_bundle_root / "adapters" / adapter_id / "eval_report.json"
            _copy_eval_report(eval_source, supplemental_eval_target)
            training_receipt = _load_json_required(Path(entry["training_receipt_ref"]), label=f"targeted training receipt {adapter_id}")
            eval_receipt = _load_json_required(Path(entry["eval_receipt_ref"]), label=f"targeted eval receipt {adapter_id}")
            manifest_entries.append(
                {
                    "adapter_id": adapter_id,
                    "entry_mode": "REFRESHED_TARGETED",
                    "artifact_sha256": str(entry["artifact_sha256"]),
                    "dataset_sha256": str(entry["dataset_sha256"]),
                    "source_training_receipt_ref": str(entry["training_receipt_ref"]),
                    "source_eval_receipt_ref": str(entry["eval_receipt_ref"]),
                    "source_eval_report_ref": eval_source.as_posix(),
                    "source_job_dir_manifest_ref": (targeted_bundle_root / "adapters" / adapter_id / "job_dir_manifest.json").as_posix(),
                    "base_snapshot_id": str(training_receipt.get("base_snapshot_id", "")).strip(),
                    "baseline_eval_score": float(eval_receipt.get("baseline_eval_score", 0.0)),
                }
            )
        else:
            entry = dict(base_inventory[adapter_id])
            prior_eval_ref = _resolve(root, str(baseline_reexport_map[adapter_id].get("entrant_eval_report_ref", "")).strip())
            if not prior_eval_ref.is_file():
                raise RuntimeError(f"FAIL_CLOSED: missing control entrant eval report for {adapter_id}: {prior_eval_ref.as_posix()}")
            _copy_eval_report(prior_eval_ref, supplemental_eval_target)
            manifest_entries.append(
                {
                    "adapter_id": adapter_id,
                    "entry_mode": "CARRYFORWARD_CONTROL",
                    "artifact_sha256": str(entry.get("artifact_sha256", "")).strip(),
                    "dataset_sha256": str(entry.get("dataset_sha256", "")).strip(),
                    "source_training_receipt_ref": str(entry.get("training_receipt_ref", "")).strip(),
                    "source_eval_receipt_ref": str(entry.get("eval_receipt_ref", "")).strip(),
                    "source_eval_report_ref": prior_eval_ref.as_posix(),
                    "source_job_dir_manifest_ref": str(baseline_reexport_map[adapter_id].get("reexported_job_dir_manifest_ref", "")).strip(),
                    "entrant_root_hash_before": str(baseline_reexport_map[adapter_id].get("entrant_root_hash", "")).strip(),
                    "control_status": "UNCHANGED_AND_ADMISSIBLE",
                }
            )
        recomposed_entries.append(entry)

    synthetic_inventory = {
        "schema_id": "kt.operator.cohort0_recomposed_adapter_inventory.v1",
        "generated_utc": utc_now_iso_z(),
        "adapter_count": len(recomposed_entries),
        "entries": recomposed_entries,
    }
    write_json_stable((synthetic_root / "cohort0_real_engine_adapter_inventory.json").resolve(), synthetic_inventory)

    synthetic_import_receipt = {
        "schema_id": "kt.operator.cohort0_recomposed_import_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(targeted_import.get("subject_head", "")).strip(),
        "current_git_head": _git_head(root),
        "base_snapshot_id": str(base_import.get("base_snapshot_id", "")).strip(),
        "registry_id": "KT_OPERATOR_FORGE_COHORT0_RECOMPOSED_TARGETED_HYPERTRAINING_V1",
        "adapter_count": 13,
        "adapter_ids": authoritative_ids,
        "claim_boundary": "Compatibility carrier import receipt for the recomposed 13-entrant substrate. It exists only to feed bounded tournament preparation on the recomposed entrant set.",
    }
    synthetic_grade_receipt = {
        "schema_id": "kt.operator.cohort0_recomposed_grade_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "grade": "PASS_AS_STRONG_GATE_D_ADAPTER_EVIDENCE",
        "claim_boundary": "Compatibility carrier grade receipt for the recomposed 13-entrant substrate. It does not itself claim tournament or router movement.",
        "adapter_count": 13,
        "source_import_receipt_subject_head": str(synthetic_import_receipt["subject_head"]),
    }
    synthetic_import_path = (synthetic_root / "cohort0_real_engine_adapter_import_receipt.json").resolve()
    synthetic_grade_path = (synthetic_root / "cohort0_real_engine_adapter_grade_receipt.json").resolve()
    write_json_stable(synthetic_import_path, synthetic_import_receipt)
    write_json_stable(synthetic_grade_path, synthetic_grade_receipt)

    prep_payload = prep_tranche.run_tournament_prep_tranche(
        import_report_path=synthetic_import_path,
        grade_report_path=synthetic_grade_path,
        authoritative_root=prep_root,
        reports_root=internal_reports_root,
        suite_id="SUITE_X",
        adversarial_suite_id="SUITE_X_ADV",
        lane_id="B04_GATE_D_RECOMPOSED_13_ENTRANT_TOURNAMENT_PREP",
        supplemental_evidence_root=supplemental_root,
        supplemental_evidence_zip=None,
        workspace_root=root,
    )

    prep_packet_path = (prep_root / "cohort0_tournament_admission_prep_packet.json").resolve()
    prep_packet = _extract_prep_packet(prep_payload)

    if str(prep_packet.get("prep_posture", "")).strip() == "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION":
        _ = fragility_tranche.run_tournament_fragility_probe_tranche(
            prep_report_path=prep_packet_path,
            authoritative_root=prep_root,
            reports_root=internal_reports_root,
            workspace_root=root,
        )
        prep_payload = prep_tranche.run_tournament_prep_tranche(
            import_report_path=synthetic_import_path,
            grade_report_path=synthetic_grade_path,
            authoritative_root=prep_root,
            reports_root=internal_reports_root,
            suite_id="SUITE_X",
            adversarial_suite_id="SUITE_X_ADV",
            lane_id="B04_GATE_D_RECOMPOSED_13_ENTRANT_TOURNAMENT_PREP",
            supplemental_evidence_root=supplemental_root,
            supplemental_evidence_zip=None,
            workspace_root=root,
        )
        prep_packet = _extract_prep_packet(prep_payload)

    reexport_contract_path = (prep_root / "cohort0_entrant_authority_reexport_contract.json").resolve()
    recomposed_manifest = _recomposed_manifest(
        subject_head=str(targeted_import.get("subject_head", "")).strip(),
        current_head=_git_head(root),
        updated_ids=target_ids,
        control_ids=control_ids,
        entries=manifest_entries,
        authoritative_base_import_path=authoritative_base_import_path,
        authoritative_targeted_import_path=authoritative_targeted_import_path,
        prep_packet_path=prep_packet_path,
        reexport_contract_path=reexport_contract_path,
    )
    recomposed_receipt = _recomposed_receipt(
        subject_head=str(targeted_import.get("subject_head", "")).strip(),
        current_head=_git_head(root),
        prep_packet=prep_packet,
        updated_ids=target_ids,
        control_ids=control_ids,
        recomposed_manifest_path=(reports_root / Path(DEFAULT_RECOMPOSED_MANIFEST_REL).name).resolve(),
        reexport_contract_path=reexport_contract_path,
        import_receipt_path=synthetic_import_path,
        grade_receipt_path=synthetic_grade_path,
    )
    recomposed_followthrough = _recomposed_followthrough(
        prep_packet=prep_packet,
        updated_ids=target_ids,
        control_ids=control_ids,
        reexport_contract_path=reexport_contract_path,
        prep_packet_path=prep_packet_path,
    )

    authoritative_manifest_path = (authoritative_root / "cohort0_recomposed_13_entrant_manifest.json").resolve()
    authoritative_receipt_path = (authoritative_root / "cohort0_recomposed_13_entrant_substrate_receipt.json").resolve()
    authoritative_follow_path = (authoritative_root / "cohort0_recomposed_13_entrant_followthrough_packet.json").resolve()
    write_json_stable(authoritative_manifest_path, recomposed_manifest)
    write_json_stable(authoritative_receipt_path, recomposed_receipt)
    write_json_stable(authoritative_follow_path, recomposed_followthrough)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_manifest = dict(recomposed_manifest)
    tracked_manifest["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_13_ENTRANT_MANIFEST"
    tracked_manifest["authoritative_recomposed_13_entrant_manifest_ref"] = authoritative_manifest_path.as_posix()
    tracked_receipt = dict(recomposed_receipt)
    tracked_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_13_ENTRANT_SUBSTRATE_RECEIPT"
    tracked_receipt["authoritative_recomposed_13_entrant_substrate_receipt_ref"] = authoritative_receipt_path.as_posix()
    tracked_follow = dict(recomposed_followthrough)
    tracked_follow["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_13_ENTRANT_FOLLOWTHROUGH_PACKET"
    tracked_follow["authoritative_recomposed_13_entrant_followthrough_packet_ref"] = authoritative_follow_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_RECOMPOSED_MANIFEST_REL).name).resolve(), tracked_manifest)
    write_json_stable((reports_root / Path(DEFAULT_RECOMPOSED_RECEIPT_REL).name).resolve(), tracked_receipt)
    write_json_stable((reports_root / Path(DEFAULT_RECOMPOSED_FOLLOWTHROUGH_REL).name).resolve(), tracked_follow)

    return {
        "recomposed_manifest": recomposed_manifest,
        "recomposed_receipt": recomposed_receipt,
        "recomposed_followthrough": recomposed_followthrough,
        "prep_packet": prep_packet,
        "tournament_prep_packet": prep_packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Recompose the six refreshed targeted entrants with seven stable controls into one 13-entrant proof substrate.")
    ap.add_argument("--base-import-report", default=DEFAULT_BASE_IMPORT_REPORT_REL)
    ap.add_argument("--base-grade-report", default=DEFAULT_BASE_GRADE_REPORT_REL)
    ap.add_argument("--base-reexport-report", default=DEFAULT_BASE_REEXPORT_REPORT_REL)
    ap.add_argument("--targeted-import-report", default=DEFAULT_TARGETED_IMPORT_REPORT_REL)
    ap.add_argument("--targeted-grade-report", default=DEFAULT_TARGETED_GRADE_REPORT_REL)
    ap.add_argument("--targeted-stage-receipt", default=DEFAULT_TARGETED_STAGE_RECEIPT_REL)
    ap.add_argument("--authoritative-root", default="", help="Optional authoritative output root. Default: tmp/cohort0_recomposed_13_entrant_substrate_<utc>/")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    authoritative_root = (
        _resolve(root, str(args.authoritative_root))
        if str(args.authoritative_root).strip()
        else (root / "tmp" / f"cohort0_recomposed_13_entrant_substrate_{utc_now_compact_z()}").resolve()
    )
    payload = run_recomposed_13_entrant_substrate_tranche(
        base_import_report_path=_resolve(root, str(args.base_import_report)),
        base_grade_report_path=_resolve(root, str(args.base_grade_report)),
        base_reexport_report_path=_resolve(root, str(args.base_reexport_report)),
        targeted_import_report_path=_resolve(root, str(args.targeted_import_report)),
        targeted_grade_report_path=_resolve(root, str(args.targeted_grade_report)),
        targeted_stage_receipt_path=_resolve(root, str(args.targeted_stage_receipt)),
        authoritative_root=authoritative_root,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    print(
        {
            "status": payload["recomposed_receipt"]["status"],
            "recomposition_posture": payload["recomposed_receipt"]["recomposition_posture"],
            "prep_posture": payload["tournament_prep_packet"]["prep_posture"],
            "next_lawful_move": payload["recomposed_followthrough"]["next_lawful_move"],
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
