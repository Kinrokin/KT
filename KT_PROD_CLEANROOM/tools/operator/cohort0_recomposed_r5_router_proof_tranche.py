from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_BRIDGE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_bridge_receipt.json"
DEFAULT_SHADOW_MATRIX_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_shadow_eval_matrix.json"
DEFAULT_HEALTH_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_route_distribution_health.json"
DEFAULT_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/cohort0_recomposed_router_superiority_scorecard.json"
DEFAULT_PRE_KAGGLE_HEALTH_REL = "KT_PROD_CLEANROOM/reports/route_distribution_health.json"
DEFAULT_PRE_KAGGLE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/router_superiority_scorecard.json"

VERDICT_SUPERIORITY = "ROUTER_SUPERIORITY_EARNED"
VERDICT_MATERIAL_ADVANCE = "GATE_D_MATERIALLY_ADVANCED__REMAIN_AT_R5_CEILING"
VERDICT_STATIC_HOLD = "REMAIN_AT_R5_CEILING"

NEXT_MOVE_EARNED = "ROUTER_SUPERIORITY_EARNED"
NEXT_MOVE_RESIDUAL = "AUTHOR_RESIDUAL_ALPHA_DOMINANCE_PACKET"
NEXT_MOVE_HOLD = "REMAIN_AT_R5_CEILING"


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
        raise RuntimeError("FAIL_CLOSED: recomposed R5 proof tranche could not resolve any subject head")
    if len(subject_heads) != 1:
        raise RuntimeError("FAIL_CLOSED: recomposed R5 proof tranche requires one consistent subject head")
    return next(iter(subject_heads))


def _validate_inputs(
    *,
    bridge_receipt: Dict[str, Any],
    shadow_matrix: Dict[str, Any],
    health_report: Dict[str, Any],
    scorecard: Dict[str, Any],
    pre_kaggle_health: Dict[str, Any],
    pre_kaggle_scorecard: Dict[str, Any],
) -> None:
    if str(bridge_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow bridge receipt must PASS")
    if bool(bridge_receipt.get("r5_admissible")) is not True:
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow bridge must make R5 admissible")
    if str(shadow_matrix.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router shadow eval matrix must PASS")
    if str(health_report.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed route distribution health must PASS")
    if str(scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: recomposed router superiority scorecard must PASS")
    if str(pre_kaggle_health.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pre-kaggle route distribution health must PASS")
    if str(pre_kaggle_scorecard.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: pre-kaggle router superiority scorecard must PASS")


def _material_advance(
    *,
    health_report: Dict[str, Any],
    scorecard: Dict[str, Any],
    pre_kaggle_health: Dict[str, Any],
) -> bool:
    route_delta_count = int(health_report.get("route_distribution_delta_count", 0))
    pre_delta = int(pre_kaggle_health.get("route_distribution_delta_count", 0))
    exact_path_universality_broken = bool(health_report.get("exact_path_universality_broken"))
    pre_shadow_match_rate = float(pre_kaggle_health.get("shadow_match_rate", 0.0))
    new_shadow_match_rate = float(health_report.get("shadow_match_rate", 0.0))
    route_collapse = bool(health_report.get("route_collapse_detected"))
    unique_route_target_count = len(health_report.get("unique_route_targets", []))
    r5_admissible = bool(scorecard.get("r5_admissible"))
    return (
        route_delta_count > pre_delta
        and exact_path_universality_broken
        and new_shadow_match_rate < pre_shadow_match_rate
        and not route_collapse
        and unique_route_target_count >= 3
        and r5_admissible
    )


def _ordered_outcome(*, superiority_earned: bool, material_advance: bool) -> Tuple[str, str, str]:
    if superiority_earned:
        return (
            "PASS_ROUTER_SUPERIORITY_EARNED",
            "EARNED_RECOMPOSED_ROUTER_SUPERIORITY",
            VERDICT_SUPERIORITY,
        )
    if material_advance:
        return (
            "PASS_MATERIAL_ADVANCE_STATIC_BASELINE_STILL_CANONICAL",
            "NOT_EARNED_MATERIAL_ROUTE_VALUE_PRESENT_STATIC_BASELINE_RETAINS_CANONICAL_STATUS",
            VERDICT_MATERIAL_ADVANCE,
        )
    return (
        "PASS_HOLD_RECOMPOSED_R5_CEILING",
        "NOT_EARNED_RECOMPOSED_SHADOW_CEILING_RETAINS_STATIC_BASELINE",
        VERDICT_STATIC_HOLD,
    )


def _build_ordered_receipt(
    *,
    subject_head: str,
    current_head: str,
    bridge_receipt_path: Path,
    shadow_matrix_path: Path,
    health_report_path: Path,
    scorecard_path: Path,
    pre_kaggle_health_path: Path,
    pre_kaggle_scorecard_path: Path,
    bridge_receipt: Dict[str, Any],
    health_report: Dict[str, Any],
    scorecard: Dict[str, Any],
    pre_kaggle_health: Dict[str, Any],
    material_advance: bool,
) -> Dict[str, Any]:
    superiority_earned = bool(scorecard.get("router_superiority_earned"))
    ordered_proof_outcome, exact_superiority_outcome, verdict_posture = _ordered_outcome(
        superiority_earned=superiority_earned,
        material_advance=material_advance,
    )
    route_delta_count = int(health_report.get("route_distribution_delta_count", 0))
    pre_delta = int(pre_kaggle_health.get("route_distribution_delta_count", 0))
    shadow_match_rate = float(health_report.get("shadow_match_rate", 0.0))
    pre_shadow_match_rate = float(pre_kaggle_health.get("shadow_match_rate", 0.0))
    candidate_status = (
        "LEARNED_ROUTER_CANDIDATE_SIGNAL_PRESENT__AUTHORIZATION_STILL_BLOCKED"
        if material_advance and not superiority_earned
        else "NO_LIVE_LEARNED_ROUTER_CANDIDATE"
    )
    checks = [
        {"check_id": "recomposed_shadow_bridge_passed", "pass": str(bridge_receipt.get("status", "")).strip() == "PASS"},
        {"check_id": "current_static_comparator_is_alpha", "pass": str(scorecard.get("best_static_baseline", {}).get("adapter_id", "")).strip() == "lobe.alpha.v1"},
        {"check_id": "proof_objects_moved_vs_pre_kaggle_delta_baseline", "pass": route_delta_count > pre_delta},
        {"check_id": "exact_path_universality_broken_vs_pre_kaggle_shadow", "pass": bool(health_report.get("exact_path_universality_broken")) and float(pre_kaggle_health.get("shadow_match_rate", 0.0)) == 1.0},
        {"check_id": "route_collapse_absent", "pass": bool(health_report.get("route_collapse_detected")) is False},
        {"check_id": "superiority_claim_kept_honest", "pass": superiority_earned is False},
    ]
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_ordered_proof_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "claim_boundary": (
            "This receipt proves only recomposed ordered proof movement against the pre-Kaggle router ceiling and the current static alpha comparator. "
            "It does not authorize learned-router cutover, Gate E/F, or commercial widening."
        ),
        "bridge_receipt_ref": bridge_receipt_path.as_posix(),
        "shadow_matrix_ref": shadow_matrix_path.as_posix(),
        "route_distribution_health_ref": health_report_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "pre_kaggle_route_distribution_health_ref": pre_kaggle_health_path.as_posix(),
        "pre_kaggle_router_superiority_scorecard_ref": pre_kaggle_scorecard_path.as_posix(),
        "ordered_proof_outcome": ordered_proof_outcome,
        "exact_superiority_outcome": exact_superiority_outcome,
        "verdict_posture": verdict_posture,
        "learned_router_candidate_status": candidate_status,
        "material_advance_detected": material_advance,
        "proof_object_deltas": {
            "route_distribution_delta_count_previous": pre_delta,
            "route_distribution_delta_count_current": route_delta_count,
            "route_distribution_delta_count_delta": route_delta_count - pre_delta,
            "shadow_match_rate_previous": pre_shadow_match_rate,
            "shadow_match_rate_current": shadow_match_rate,
            "shadow_match_rate_delta": round(shadow_match_rate - pre_shadow_match_rate, 4),
            "exact_path_universality_broken_current": bool(health_report.get("exact_path_universality_broken")),
            "unique_route_target_count_current": len(health_report.get("unique_route_targets", [])),
        },
        "checks": checks,
    }


def _build_r5_receipt(
    *,
    subject_head: str,
    current_head: str,
    ordered_receipt_path: Path,
    ordered_receipt: Dict[str, Any],
    scorecard_path: Path,
    scorecard: Dict[str, Any],
) -> Dict[str, Any]:
    superiority_earned = bool(scorecard.get("router_superiority_earned"))
    material_advance = bool(ordered_receipt.get("material_advance_detected"))
    verdict_posture = str(ordered_receipt.get("verdict_posture", "")).strip()
    next_lawful_move = NEXT_MOVE_EARNED if superiority_earned else (NEXT_MOVE_RESIDUAL if material_advance else NEXT_MOVE_HOLD)
    return {
        "schema_id": "kt.operator.cohort0_recomposed_router_vs_best_adapter_proof_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if str(ordered_receipt.get("status", "")).strip() == "PASS" else "FAIL",
        "subject_head": subject_head,
        "current_git_head": current_head,
        "workstream_id": "B04_R5_ROUTER_VS_BEST_ADAPTER_PROOF__RECOMPOSED_SUBSTRATE",
        "receipt_role": "COUNTED_RECOMPOSED_B04_R5_ROUTER_PROOF_ARTIFACT_ONLY",
        "claim_boundary": (
            "This receipt proves only the recomposed R5 router-versus-best-adapter proof result on the promotion-and-merge-bound substrate. "
            "It does not authorize learned-router cutover or Gate E/F unless superiority is actually earned."
        ),
        "ordered_proof_receipt_ref": ordered_receipt_path.as_posix(),
        "router_superiority_scorecard_ref": scorecard_path.as_posix(),
        "router_proof_summary": {
            "best_static_adapter_id": str(scorecard.get("best_static_baseline", {}).get("adapter_id", "")).strip(),
            "router_superiority_earned": superiority_earned,
            "ordered_proof_outcome": str(ordered_receipt.get("ordered_proof_outcome", "")).strip(),
            "exact_superiority_outcome": str(ordered_receipt.get("exact_superiority_outcome", "")).strip(),
            "material_advance_detected": material_advance,
            "learned_router_candidate_status": str(ordered_receipt.get("learned_router_candidate_status", "")).strip(),
        },
        "verdict_posture": verdict_posture,
        "next_lawful_move": next_lawful_move,
    }


def run_recomposed_r5_router_proof_tranche(
    *,
    bridge_receipt_path: Path,
    shadow_matrix_path: Path,
    health_report_path: Path,
    scorecard_path: Path,
    pre_kaggle_health_path: Path,
    pre_kaggle_scorecard_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    current_head = _git_head(root)

    authoritative_bridge_receipt_path, bridge_receipt = _resolve_authoritative(
        root, bridge_receipt_path.resolve(), "authoritative_recomposed_router_shadow_bridge_receipt_ref", "recomposed bridge receipt"
    )
    authoritative_shadow_matrix_path, shadow_matrix = _resolve_authoritative(
        root, shadow_matrix_path.resolve(), "authoritative_recomposed_router_shadow_eval_matrix_ref", "recomposed shadow matrix"
    )
    authoritative_health_path, health_report = _resolve_authoritative(
        root, health_report_path.resolve(), "authoritative_recomposed_route_distribution_health_ref", "recomposed route health"
    )
    authoritative_scorecard_path, scorecard = _resolve_authoritative(
        root, scorecard_path.resolve(), "authoritative_recomposed_router_superiority_scorecard_ref", "recomposed scorecard"
    )
    authoritative_pre_kaggle_health_path, pre_kaggle_health = _resolve_authoritative(
        root, pre_kaggle_health_path.resolve(), "", "pre-kaggle route health"
    )
    authoritative_pre_kaggle_scorecard_path, pre_kaggle_scorecard = _resolve_authoritative(
        root, pre_kaggle_scorecard_path.resolve(), "", "pre-kaggle scorecard"
    )

    _validate_inputs(
        bridge_receipt=bridge_receipt,
        shadow_matrix=shadow_matrix,
        health_report=health_report,
        scorecard=scorecard,
        pre_kaggle_health=pre_kaggle_health,
        pre_kaggle_scorecard=pre_kaggle_scorecard,
    )

    subject_head = _resolve_subject_head(
        packets=[
            bridge_receipt,
            shadow_matrix,
            health_report,
            scorecard,
            pre_kaggle_health,
            pre_kaggle_scorecard,
        ]
    )
    material_advance = _material_advance(
        health_report=health_report,
        scorecard=scorecard,
        pre_kaggle_health=pre_kaggle_health,
    )

    target_root = authoritative_root.resolve() if authoritative_root is not None else authoritative_bridge_receipt_path.parent.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    ordered_receipt_path = (target_root / "cohort0_recomposed_router_ordered_proof_receipt.json").resolve()
    r5_receipt_path = (target_root / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json").resolve()

    ordered_receipt = _build_ordered_receipt(
        subject_head=subject_head,
        current_head=current_head,
        bridge_receipt_path=authoritative_bridge_receipt_path,
        shadow_matrix_path=authoritative_shadow_matrix_path,
        health_report_path=authoritative_health_path,
        scorecard_path=authoritative_scorecard_path,
        pre_kaggle_health_path=authoritative_pre_kaggle_health_path,
        pre_kaggle_scorecard_path=authoritative_pre_kaggle_scorecard_path,
        bridge_receipt=bridge_receipt,
        health_report=health_report,
        scorecard=scorecard,
        pre_kaggle_health=pre_kaggle_health,
        material_advance=material_advance,
    )
    write_json_stable(ordered_receipt_path, ordered_receipt)

    r5_receipt = _build_r5_receipt(
        subject_head=subject_head,
        current_head=current_head,
        ordered_receipt_path=ordered_receipt_path,
        ordered_receipt=ordered_receipt,
        scorecard_path=authoritative_scorecard_path,
        scorecard=scorecard,
    )
    write_json_stable(r5_receipt_path, r5_receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_ordered = dict(ordered_receipt)
    tracked_ordered["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_ORDERED_PROOF_RECEIPT"
    tracked_ordered["authoritative_recomposed_router_ordered_proof_receipt_ref"] = ordered_receipt_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_ordered_proof_receipt.json").resolve(), tracked_ordered)

    tracked_r5 = dict(r5_receipt)
    tracked_r5["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_RECOMPOSED_ROUTER_VS_BEST_ADAPTER_PROOF_RECEIPT"
    tracked_r5["authoritative_recomposed_router_vs_best_adapter_proof_receipt_ref"] = r5_receipt_path.as_posix()
    write_json_stable((reports_root / "cohort0_recomposed_router_vs_best_adapter_proof_receipt.json").resolve(), tracked_r5)

    return {
        "router_ordered_proof_receipt": ordered_receipt,
        "router_vs_best_adapter_proof_receipt": r5_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Ratify recomposed R5 router proof on the promotion-and-merge-bound substrate.")
    ap.add_argument("--bridge-receipt", default=DEFAULT_BRIDGE_RECEIPT_REL)
    ap.add_argument("--shadow-matrix", default=DEFAULT_SHADOW_MATRIX_REL)
    ap.add_argument("--health-report", default=DEFAULT_HEALTH_REL)
    ap.add_argument("--scorecard", default=DEFAULT_SCORECARD_REL)
    ap.add_argument("--pre-kaggle-health", default=DEFAULT_PRE_KAGGLE_HEALTH_REL)
    ap.add_argument("--pre-kaggle-scorecard", default=DEFAULT_PRE_KAGGLE_SCORECARD_REL)
    ap.add_argument("--authoritative-root", default="")
    ap.add_argument("--reports-root", default="KT_PROD_CLEANROOM/reports")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root().resolve()
    payload = run_recomposed_r5_router_proof_tranche(
        bridge_receipt_path=_resolve(root, str(args.bridge_receipt)),
        shadow_matrix_path=_resolve(root, str(args.shadow_matrix)),
        health_report_path=_resolve(root, str(args.health_report)),
        scorecard_path=_resolve(root, str(args.scorecard)),
        pre_kaggle_health_path=_resolve(root, str(args.pre_kaggle_health)),
        pre_kaggle_scorecard_path=_resolve(root, str(args.pre_kaggle_scorecard)),
        authoritative_root=_resolve(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve(root, str(args.reports_root)),
        workspace_root=root,
    )
    receipt = payload["router_vs_best_adapter_proof_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "verdict_posture": receipt["verdict_posture"],
                "router_superiority_earned": receipt["router_proof_summary"]["router_superiority_earned"],
                "material_advance_detected": receipt["router_proof_summary"]["material_advance_detected"],
                "next_lawful_move": receipt["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
