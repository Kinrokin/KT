from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_DIAGNOSIS_REL = "KT_PROD_CLEANROOM/reports/router_failure_diagnosis_packet.json"
DEFAULT_STAGE_PACK_MANIFEST_REL = "KT_PROD_CLEANROOM/reports/route_bearing_stage_pack_manifest.json"
DEFAULT_ORACLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/oracle_router_local_scorecard.json"
DEFAULT_LOBE_SURVIVAL_REL = "KT_PROD_CLEANROOM/reports/lobe_survival_verdicts.json"
DEFAULT_ALPHA_LOSE_REL = "KT_PROD_CLEANROOM/reports/alpha_should_lose_here_manifest.json"
DEFAULT_NEGATIVE_LEDGER_REL = "KT_PROD_CLEANROOM/reports/negative_result_ledger.json"

PRIMARY_AXES = {
    "P2_SIGNAL_NOISE_SEPARATION": ("adversarial_ambiguity", "cross_domain_overlay"),
    "CHILD_ANOMALY_PRESERVATION": ("cross_domain_overlay", "paradox_intensity"),
    "STRATEGIST_CONSEQUENCE_CHAIN": ("causal_branching", "hop_depth"),
    "BETA_SECOND_ORDER_REFRAME": ("paradox_intensity", "adversarial_ambiguity"),
    "SCOUT_SPARSE_SEARCH": ("hop_depth", "temporal_distortion"),
    "AUDITOR_ADMISSIBILITY_FAIL_CLOSED": ("governed_execution_burden", "refusal_calibration"),
    "BOUNDARY_ABSTENTION_CONTROL": ("refusal_calibration", "governed_execution_burden"),
    "STATIC_NO_ROUTE_CONTROL": ("static_regression_hold", "none"),
}


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _resolve_subject_head(*, packets: Sequence[Dict[str, Any]]) -> str:
    subject_heads = {
        str(packet.get("subject_head", "")).strip()
        for packet in packets
        if isinstance(packet, dict) and str(packet.get("subject_head", "")).strip()
    }
    if not subject_heads:
        raise RuntimeError("FAIL_CLOSED: crucible escalation packet could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: crucible escalation packet requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    diagnosis: Dict[str, Any],
    stage_pack_manifest: Dict[str, Any],
    oracle_scorecard: Dict[str, Any],
    lobe_survival: Dict[str, Any],
    alpha_manifest: Dict[str, Any],
    negative_ledger: Dict[str, Any],
) -> None:
    if str(diagnosis.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: router failure diagnosis packet must PASS")
    if str(stage_pack_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: route bearing stage pack manifest must PASS")
    if str(oracle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: oracle scorecard must PASS")
    if str(lobe_survival.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: lobe survival verdicts must PASS")
    if str(alpha_manifest.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: alpha should lose manifest must PASS")
    if str(negative_ledger.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: negative result ledger must PASS")
    if not isinstance(stage_pack_manifest.get("family_rows"), list) or not stage_pack_manifest["family_rows"]:
        raise RuntimeError("FAIL_CLOSED: route bearing stage pack manifest missing family_rows")
    if not isinstance(oracle_scorecard.get("oracle_positive_family_ids"), list) or not oracle_scorecard["oracle_positive_family_ids"]:
        raise RuntimeError("FAIL_CLOSED: oracle scorecard missing oracle_positive_family_ids")


def _family_rows(stage_pack_manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [row for row in stage_pack_manifest.get("family_rows", []) if isinstance(row, dict)]


def _build_crucible_registry(families: List[Dict[str, Any]]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    for family in families:
        family_id = str(family.get("family_id", "")).strip()
        target_lobe_id = str(family.get("target_lobe_id", "")).strip()
        primary_axis, secondary_axis = PRIMARY_AXES.get(family_id, ("cross_domain_overlay", "adversarial_ambiguity"))
        entries.append(
            {
                "crucible_id": f"RECOVER__{family_id}__SINGLE_AXIS",
                "family_id": family_id,
                "target_lobe_id": target_lobe_id,
                "phase": "SINGLE_AXIS_OVERDRIVE",
                "promotion_scope": "LAB_ONLY_UNTIL_TRANSFER_RULE_SATISFIED",
                "trust_zone": "LAB",
                "primary_axis": primary_axis,
                "secondary_axis": "none",
            }
        )
        if family_id not in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"}:
            entries.append(
                {
                    "crucible_id": f"RECOVER__{family_id}__PAIRWISE",
                    "family_id": family_id,
                    "target_lobe_id": target_lobe_id,
                    "phase": "PAIRWISE_INTERACTION",
                    "promotion_scope": "LAB_ONLY_UNTIL_TRANSFER_RULE_SATISFIED",
                    "trust_zone": "LAB",
                    "primary_axis": primary_axis,
                    "secondary_axis": secondary_axis,
                }
            )
            entries.append(
                {
                    "crucible_id": f"RECOVER__{family_id}__COMPOSITE",
                    "family_id": family_id,
                    "target_lobe_id": target_lobe_id,
                    "phase": "COMPOSITE_OVERLOAD",
                    "promotion_scope": "LAB_ONLY_UNTIL_TRANSFER_RULE_SATISFIED",
                    "trust_zone": "LAB",
                    "primary_axis": primary_axis,
                    "secondary_axis": secondary_axis,
                }
            )
    return {
        "schema_id": "kt.operator.cohort0_router_recovery_crucible_registry.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "entry_count": len(entries),
        "claim_boundary": "This registry is lab-only escalation planning. It does not widen the counted proof lane.",
        "entries": entries,
    }


def _build_pressure_taxonomy() -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_policy_c_pressure_taxonomy.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": "This taxonomy governs lab-only pressure escalation and does not directly authorize counted-lane claims.",
        "axes": [
            {"axis_id": "paradox_intensity", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "temporal_distortion", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "hop_depth", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "causal_branching", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "cross_domain_overlay", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "adversarial_ambiguity", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "refusal_calibration", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "governed_execution_burden", "phase_order": ["SINGLE_AXIS_OVERDRIVE", "PAIRWISE_INTERACTION", "COMPOSITE_OVERLOAD"]},
            {"axis_id": "static_regression_hold", "phase_order": ["SINGLE_AXIS_OVERDRIVE"]},
        ],
    }


def _build_epoch_coverage_matrix(families: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for family in families:
        family_id = str(family.get("family_id", "")).strip()
        target_lobe_id = str(family.get("target_lobe_id", "")).strip()
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": target_lobe_id,
                "single_axis_ready": True,
                "pairwise_ready": family_id not in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"},
                "composite_ready": family_id not in {"BOUNDARY_ABSTENTION_CONTROL", "STATIC_NO_ROUTE_CONTROL"},
                "held_out_mutation_preserved": True,
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_epoch_coverage_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": "This matrix governs lab-only pressure sequencing and held-out preservation.",
        "rows": rows,
    }


def _build_pressure_delta_summary(families: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for family in families:
        family_id = str(family.get("family_id", "")).strip()
        primary_axis, secondary_axis = PRIMARY_AXES.get(family_id, ("cross_domain_overlay", "adversarial_ambiguity"))
        rows.append(
            {
                "family_id": family_id,
                "target_lobe_id": str(family.get("target_lobe_id", "")).strip(),
                "primary_axis": primary_axis,
                "secondary_axis": secondary_axis,
                "named_wedge_sharpening": f"{family_id}__WEDGE_SHARPENING",
                "named_anti_alpha_liability": str(family.get("alpha_liability", "")).strip(),
                "measurable_route_delta_hypothesis": f"{family_id}__ROUTE_DELTA_GT_PREVIOUS_SHADOW_BASELINE",
                "new_admissible_eval_family": f"{family_id}__CRUCIBLE_MUTATION_FAMILY",
            }
        )
    return {
        "schema_id": "kt.operator.cohort0_pressure_delta_summary.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "claim_boundary": "This summary records only lab-side pressure hypotheses. Nothing here widens the counted proof lane by itself.",
        "rows": rows,
    }


def _build_execution_receipt(subject_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_crucible_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "execution_posture": "LAB_ONLY_CRUCIBLE_ESCALATION_PACKET_BOUND__COUNTED_LANE_UNCHANGED",
        "claim_boundary": "This receipt authorizes only lab-side pressure sweeps. The counted proof lane remains unchanged.",
        "next_lawful_move": "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS",
    }


def _build_packet(
    *,
    subject_head: str,
    current_head: str,
    diagnosis_path: Path,
    stage_pack_manifest_path: Path,
    oracle_scorecard_path: Path,
    lobe_survival_path: Path,
    alpha_manifest_path: Path,
    negative_ledger_path: Path,
    registry_path: Path,
    pressure_taxonomy_path: Path,
    epoch_matrix_path: Path,
    execution_receipt_path: Path,
    pressure_delta_summary_path: Path,
) -> Dict[str, Any]:
    return {
        "schema_id": "kt.operator.cohort0_crucible_escalation_packet.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "packet_posture": "LAB_FULL_POWER_READY__COUNTED_PROOF_LANE_STILL_SEPARATE",
        "claim_boundary": (
            "This packet defines the lab-only crucible escalation lane. It does not reopen the counted lane and cannot be used as proof "
            "until the hard transfer rule is satisfied."
        ),
        "source_refs": {
            "diagnosis_packet_ref": diagnosis_path.as_posix(),
            "route_bearing_stage_pack_manifest_ref": stage_pack_manifest_path.as_posix(),
            "oracle_router_local_scorecard_ref": oracle_scorecard_path.as_posix(),
            "lobe_survival_verdicts_ref": lobe_survival_path.as_posix(),
            "alpha_should_lose_here_manifest_ref": alpha_manifest_path.as_posix(),
            "negative_result_ledger_ref": negative_ledger_path.as_posix(),
        },
        "emitted_surfaces": {
            "crucible_registry_ref": registry_path.as_posix(),
            "policy_c_pressure_taxonomy_ref": pressure_taxonomy_path.as_posix(),
            "epoch_coverage_matrix_ref": epoch_matrix_path.as_posix(),
            "crucible_execution_receipt_ref": execution_receipt_path.as_posix(),
            "pressure_delta_summary_ref": pressure_delta_summary_path.as_posix(),
        },
        "counted_lane_contamination_forbidden": True,
        "transfer_rule": {
            "named_wedge_sharpening_required": True,
            "named_anti_alpha_liability_required": True,
            "measurable_route_delta_hypothesis_required": True,
            "new_admissible_eval_family_required": True,
            "counts_as_counted_progress_only_after_rerun_proof_objects_move": True,
        },
        "next_lawful_move": "AUTHOR_SINGLE_AXIS_CRUCIBLE_INPUTS_AND_EXECUTE_LAB_ONLY_SWEEPS",
    }


def run_crucible_escalation_packet_tranche(
    *,
    diagnosis_path: Path,
    stage_pack_manifest_path: Path,
    oracle_scorecard_path: Path,
    lobe_survival_path: Path,
    alpha_manifest_path: Path,
    negative_ledger_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_diagnosis_path, diagnosis = _resolve_authoritative(root, diagnosis_path.resolve(), "authoritative_router_failure_diagnosis_packet_ref", "diagnosis packet")
    authoritative_stage_pack_manifest_path, stage_pack_manifest = _resolve_authoritative(root, stage_pack_manifest_path.resolve(), "authoritative_route_bearing_stage_pack_manifest_ref", "stage pack manifest")
    authoritative_oracle_scorecard_path, oracle_scorecard = _resolve_authoritative(root, oracle_scorecard_path.resolve(), "authoritative_oracle_router_local_scorecard_ref", "oracle scorecard")
    authoritative_lobe_survival_path, lobe_survival = _resolve_authoritative(root, lobe_survival_path.resolve(), "authoritative_lobe_survival_verdicts_ref", "lobe survival verdicts")
    authoritative_alpha_manifest_path, alpha_manifest = _resolve_authoritative(root, alpha_manifest_path.resolve(), "authoritative_alpha_should_lose_here_manifest_ref", "alpha should lose manifest")
    authoritative_negative_ledger_path, negative_ledger = _resolve_authoritative(root, negative_ledger_path.resolve(), "authoritative_negative_result_ledger_ref", "negative result ledger")

    _validate_inputs(
        diagnosis=diagnosis,
        stage_pack_manifest=stage_pack_manifest,
        oracle_scorecard=oracle_scorecard,
        lobe_survival=lobe_survival,
        alpha_manifest=alpha_manifest,
        negative_ledger=negative_ledger,
    )

    subject_head = _resolve_subject_head(packets=[diagnosis, stage_pack_manifest, oracle_scorecard])
    families = _family_rows(stage_pack_manifest)

    target_root = authoritative_root.resolve() if authoritative_root is not None else (root / "tmp" / "cohort0_crucible_escalation_packet").resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    registry_path = (target_root / "crucible_registry.json").resolve()
    pressure_taxonomy_path = (target_root / "policy_c_pressure_taxonomy.json").resolve()
    epoch_matrix_path = (target_root / "epoch_coverage_matrix.json").resolve()
    execution_receipt_path = (target_root / "crucible_execution_receipt.json").resolve()
    pressure_delta_summary_path = (target_root / "pressure_delta_summary.json").resolve()
    packet_path = (target_root / "crucible_escalation_packet.json").resolve()

    registry = _build_crucible_registry(families)
    write_json_stable(registry_path, registry)
    pressure_taxonomy = _build_pressure_taxonomy()
    write_json_stable(pressure_taxonomy_path, pressure_taxonomy)
    epoch_matrix = _build_epoch_coverage_matrix(families)
    write_json_stable(epoch_matrix_path, epoch_matrix)
    execution_receipt = _build_execution_receipt(subject_head)
    write_json_stable(execution_receipt_path, execution_receipt)
    pressure_delta_summary = _build_pressure_delta_summary(families)
    write_json_stable(pressure_delta_summary_path, pressure_delta_summary)
    packet = _build_packet(
        subject_head=subject_head,
        current_head=current_head,
        diagnosis_path=authoritative_diagnosis_path,
        stage_pack_manifest_path=authoritative_stage_pack_manifest_path,
        oracle_scorecard_path=authoritative_oracle_scorecard_path,
        lobe_survival_path=authoritative_lobe_survival_path,
        alpha_manifest_path=authoritative_alpha_manifest_path,
        negative_ledger_path=authoritative_negative_ledger_path,
        registry_path=registry_path,
        pressure_taxonomy_path=pressure_taxonomy_path,
        epoch_matrix_path=epoch_matrix_path,
        execution_receipt_path=execution_receipt_path,
        pressure_delta_summary_path=pressure_delta_summary_path,
    )
    write_json_stable(packet_path, packet)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_packet = dict(packet)
    tracked_packet["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_COHORT0_CRUCIBLE_ESCALATION_PACKET"
    tracked_packet["authoritative_crucible_escalation_packet_ref"] = packet_path.as_posix()
    write_json_stable((reports_root / "cohort0_crucible_escalation_packet.json").resolve(), tracked_packet)

    return {
        "crucible_registry": registry,
        "policy_c_pressure_taxonomy": pressure_taxonomy,
        "epoch_coverage_matrix": epoch_matrix,
        "crucible_execution_receipt": execution_receipt,
        "pressure_delta_summary": pressure_delta_summary,
        "crucible_escalation_packet": packet,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Emit a lab-only crucible escalation packet that stays separate from the counted proof lane.")
    ap.add_argument("--diagnosis", default=DEFAULT_DIAGNOSIS_REL)
    ap.add_argument("--stage-pack-manifest", default=DEFAULT_STAGE_PACK_MANIFEST_REL)
    ap.add_argument("--oracle-scorecard", default=DEFAULT_ORACLE_SCORECARD_REL)
    ap.add_argument("--lobe-survival", default=DEFAULT_LOBE_SURVIVAL_REL)
    ap.add_argument("--alpha-manifest", default=DEFAULT_ALPHA_LOSE_REL)
    ap.add_argument("--negative-ledger", default=DEFAULT_NEGATIVE_LEDGER_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_crucible_escalation_packet_tranche(
        diagnosis_path=_resolve(root, str(args.diagnosis)),
        stage_pack_manifest_path=_resolve(root, str(args.stage_pack_manifest)),
        oracle_scorecard_path=_resolve(root, str(args.oracle_scorecard)),
        lobe_survival_path=_resolve(root, str(args.lobe_survival)),
        alpha_manifest_path=_resolve(root, str(args.alpha_manifest)),
        negative_ledger_path=_resolve(root, str(args.negative_ledger)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    packet = payload["crucible_escalation_packet"]
    print(json.dumps({"status": packet["status"], "packet_posture": packet["packet_posture"], "next_lawful_move": packet["next_lawful_move"]}, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
