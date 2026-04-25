from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_PROMOTION_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_candidate_receipt.json"
DEFAULT_FOLLOWTHROUGH_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_real_engine_tournament_followthrough_packet.json"
DEFAULT_CHILD_EVAL_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_child_evaluation_receipt.json"
DEFAULT_PROMOTION_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_promotion_outcome_binding_receipt.json"
DEFAULT_MERGE_OUTCOME_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_merge_outcome_binding_receipt.json"
NEXT_ROUTER_STEP_ID = "B04_R4_ROUTER_SHADOW_EVALUATION_RATIFICATION"


def _load_json_required(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    return load_json(path)


def _resolve_path(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()
    return path


def _resolve_authoritative(root: Path, tracked_path: Path, ref_field: str, label: str) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(tracked_path, label=f"tracked {label}")
    authoritative_ref = str(tracked.get(ref_field, "")).strip()
    authoritative_path = _resolve_path(root, authoritative_ref) if authoritative_ref else tracked_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label=f"authoritative {label}")


def _load_merge_outcome_family(*, root: Path, child_eval_receipt: Dict[str, Any], followthrough: Dict[str, Any]) -> Dict[str, Any]:
    merge_eval_receipt_path = _resolve_path(root, str(child_eval_receipt.get("merge_eval_receipt_ref", "")).strip())
    merge_eval_receipt = _load_json_required(merge_eval_receipt_path, label="merge eval receipt")
    merge_tournament_result_path = _resolve_path(root, str(child_eval_receipt.get("merge_tournament_result_ref", "")).strip())
    merge_tournament_result = _load_json_required(merge_tournament_result_path, label="merge tournament result")
    merge_rollback_plan_path = _resolve_path(root, str(child_eval_receipt.get("merge_rollback_plan_ref", "")).strip())
    merge_rollback_plan = _load_json_required(merge_rollback_plan_path, label="merge rollback plan")

    merge_followthrough = followthrough.get("merge_followthrough", {}) if isinstance(followthrough.get("merge_followthrough"), dict) else {}
    merge_manifest_path = _resolve_path(root, str(merge_followthrough.get("merge_manifest_ref", "")).strip())
    merge_manifest = _load_json_required(merge_manifest_path, label="merge manifest")
    child_candidate_receipt_path = _resolve_path(root, str(child_eval_receipt.get("merge_child_candidate_receipt_ref", "")).strip())
    child_candidate_receipt = _load_json_required(child_candidate_receipt_path, label="merge child candidate receipt")

    if str(merge_eval_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: outcome binding requires PASS merge eval receipt")
    if merge_eval_receipt.get("utility_gate_pass") is not True:
        raise RuntimeError("FAIL_CLOSED: outcome binding requires utility_gate_pass = true")
    if merge_eval_receipt.get("safety_regression") is not False:
        raise RuntimeError("FAIL_CLOSED: outcome binding requires safety_regression = false")
    if str(merge_tournament_result.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: outcome binding requires PASS merge tournament result")

    return {
        "merge_eval_receipt_path": merge_eval_receipt_path,
        "merge_eval_receipt": merge_eval_receipt,
        "merge_tournament_result_path": merge_tournament_result_path,
        "merge_tournament_result": merge_tournament_result,
        "merge_rollback_plan_path": merge_rollback_plan_path,
        "merge_rollback_plan": merge_rollback_plan,
        "merge_manifest_path": merge_manifest_path,
        "merge_manifest": merge_manifest,
        "child_candidate_receipt_path": child_candidate_receipt_path,
        "child_candidate_receipt": child_candidate_receipt,
    }


def _build_promotion_outcome_receipt(
    *,
    subject_head: str,
    promotion_receipt_path: Path,
    followthrough_path: Path,
    child_eval_receipt_path: Path,
    merge_outcome_receipt_path: Path,
    promotion_receipt: Dict[str, Any],
    merge_family: Dict[str, Any],
) -> Dict[str, Any]:
    candidate = dict(promotion_receipt.get("candidate", {}))
    return {
        "schema_id": "kt.operator.cohort0_promotion_outcome_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "promotion_posture": "PROMOTION_OUTCOME_BOUND__MERGE_PASS_CHILD_READY_FOR_ROUTER_SHADOW_EVALUATION",
        "claim_boundary": "This receipt binds only the bounded promotion outcome after a PASS merge-child evaluation with rollback prepared. It does not declare router authority, router superiority, externality widening, comparative claims, or commercial activation.",
        "source_promotion_candidate_receipt_ref": promotion_receipt_path.as_posix(),
        "source_followthrough_packet_ref": followthrough_path.as_posix(),
        "source_merge_child_evaluation_receipt_ref": child_eval_receipt_path.as_posix(),
        "source_merge_outcome_binding_receipt_ref": merge_outcome_receipt_path.as_posix(),
        "candidate": candidate,
        "merge_support": {
            "merge_eval_status": str(merge_family["merge_eval_receipt"].get("status", "")).strip(),
            "merge_manifest_ref": merge_family["merge_manifest_path"].as_posix(),
            "merge_eval_receipt_ref": merge_family["merge_eval_receipt_path"].as_posix(),
            "merge_rollback_plan_ref": merge_family["merge_rollback_plan_path"].as_posix(),
            "merge_tournament_result_ref": merge_family["merge_tournament_result_path"].as_posix(),
        },
        "next_lawful_move": NEXT_ROUTER_STEP_ID,
    }


def _build_merge_outcome_receipt(
    *,
    subject_head: str,
    child_eval_receipt_path: Path,
    followthrough_path: Path,
    merge_family: Dict[str, Any],
    followthrough: Dict[str, Any],
) -> Dict[str, Any]:
    merge_followthrough = followthrough.get("merge_followthrough", {}) if isinstance(followthrough.get("merge_followthrough"), dict) else {}
    return {
        "schema_id": "kt.operator.cohort0_merge_outcome_binding_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": subject_head,
        "merge_outcome_posture": "MERGE_OUTCOME_BOUND__PASS__ROLLBACK_READY",
        "claim_boundary": "This receipt binds only the bounded merge outcome on the admitted parent pair and child candidate, with rollback prepared. It does not declare router authority, externality widening, comparative claims, or commercial activation.",
        "source_followthrough_packet_ref": followthrough_path.as_posix(),
        "source_merge_child_evaluation_receipt_ref": child_eval_receipt_path.as_posix(),
        "source_merge_child_candidate_receipt_ref": merge_family["child_candidate_receipt_path"].as_posix(),
        "source_merge_manifest_ref": merge_family["merge_manifest_path"].as_posix(),
        "source_merge_eval_receipt_ref": merge_family["merge_eval_receipt_path"].as_posix(),
        "source_merge_tournament_result_ref": merge_family["merge_tournament_result_path"].as_posix(),
        "source_merge_rollback_plan_ref": merge_family["merge_rollback_plan_path"].as_posix(),
        "child_candidate": dict(merge_family["child_candidate_receipt"].get("child_candidate", {})),
        "parent_pair": list(merge_followthrough.get("recommended_parent_seeds", [])),
        "utility_gate_pass": bool(merge_family["merge_eval_receipt"].get("utility_gate_pass")),
        "safety_regression": bool(merge_family["merge_eval_receipt"].get("safety_regression")),
        "next_lawful_move": NEXT_ROUTER_STEP_ID,
    }


def _build_updated_followthrough_packet(
    *,
    existing_followthrough: Dict[str, Any],
    promotion_outcome_receipt_path: Path,
    merge_outcome_receipt_path: Path,
) -> Dict[str, Any]:
    packet = dict(existing_followthrough)
    packet["generated_utc"] = utc_now_iso_z()
    packet["followthrough_posture"] = "PROMOTION_AND_MERGE_OUTCOME_BOUND__ROUTER_SHADOW_EVALUATION_REQUIRED"
    packet["promotion_outcome_binding_receipt_ref"] = promotion_outcome_receipt_path.as_posix()
    packet["merge_outcome_binding_receipt_ref"] = merge_outcome_receipt_path.as_posix()
    packet["next_lawful_move"] = NEXT_ROUTER_STEP_ID

    promotion_followthrough = dict(packet.get("promotion_followthrough", {}))
    promotion_followthrough["execution_ready"] = True
    promotion_followthrough["blocked_by"] = "ROUTER_SHADOW_EVALUATION_NOT_PREPARED"
    promotion_followthrough["outcome_binding_receipt_ref"] = promotion_outcome_receipt_path.as_posix()
    promotion_followthrough["next_lawful_move"] = NEXT_ROUTER_STEP_ID
    packet["promotion_followthrough"] = promotion_followthrough

    merge_followthrough = dict(packet.get("merge_followthrough", {}))
    merge_followthrough["execution_ready"] = True
    merge_followthrough["blockers"] = []
    merge_followthrough["outcome_binding_receipt_ref"] = merge_outcome_receipt_path.as_posix()
    merge_followthrough["next_lawful_move"] = NEXT_ROUTER_STEP_ID
    packet["merge_followthrough"] = merge_followthrough

    packet["next_question"] = "How should the bounded promoted/merge-cleared child be admitted to router-shadow evaluation against the static baseline?"
    return packet


def run_promotion_merge_outcome_binding_tranche(
    *,
    promotion_report_path: Path,
    followthrough_report_path: Path,
    child_eval_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_promotion_path, promotion_receipt = _resolve_authoritative(
        root,
        promotion_report_path.resolve(),
        "authoritative_promotion_candidate_receipt_ref",
        "cohort0 promotion candidate receipt",
    )
    authoritative_followthrough_path, followthrough = _resolve_authoritative(
        root,
        followthrough_report_path.resolve(),
        "authoritative_followthrough_packet_ref",
        "cohort0 tournament followthrough packet",
    )
    authoritative_child_eval_path, child_eval_receipt = _resolve_authoritative(
        root,
        child_eval_report_path.resolve(),
        "authoritative_merge_child_evaluation_receipt_ref",
        "cohort0 merge child evaluation receipt",
    )

    if str(child_eval_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: outcome binding requires PASS merge child evaluation receipt")
    if str(child_eval_receipt.get("evaluation_posture", "")).strip() != "MERGE_CHILD_EVALUATED__PASS__PROMOTION_AND_ROLLBACK_BINDING_READY":
        raise RuntimeError("FAIL_CLOSED: outcome binding requires merge-child pass posture")

    subject_head = str(child_eval_receipt.get("subject_head", "")).strip()
    merge_family = _load_merge_outcome_family(root=root, child_eval_receipt=child_eval_receipt, followthrough=followthrough)

    target_root = authoritative_root.resolve() if authoritative_root is not None else authoritative_child_eval_path.parent.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    authoritative_promotion_outcome_path = (target_root / "cohort0_promotion_outcome_binding_receipt.json").resolve()
    authoritative_merge_outcome_path = (target_root / "cohort0_merge_outcome_binding_receipt.json").resolve()
    authoritative_followthrough_out_path = (target_root / "cohort0_real_engine_tournament_followthrough_packet.json").resolve()

    merge_outcome_receipt = _build_merge_outcome_receipt(
        subject_head=subject_head,
        child_eval_receipt_path=authoritative_child_eval_path,
        followthrough_path=authoritative_followthrough_path,
        merge_family=merge_family,
        followthrough=followthrough,
    )
    write_json_stable(authoritative_merge_outcome_path, merge_outcome_receipt)

    promotion_outcome_receipt = _build_promotion_outcome_receipt(
        subject_head=subject_head,
        promotion_receipt_path=authoritative_promotion_path,
        followthrough_path=authoritative_followthrough_path,
        child_eval_receipt_path=authoritative_child_eval_path,
        merge_outcome_receipt_path=authoritative_merge_outcome_path,
        promotion_receipt=promotion_receipt,
        merge_family=merge_family,
    )
    write_json_stable(authoritative_promotion_outcome_path, promotion_outcome_receipt)

    updated_followthrough = _build_updated_followthrough_packet(
        existing_followthrough=followthrough,
        promotion_outcome_receipt_path=authoritative_promotion_outcome_path,
        merge_outcome_receipt_path=authoritative_merge_outcome_path,
    )
    write_json_stable(authoritative_followthrough_out_path, updated_followthrough)

    reports_root.mkdir(parents=True, exist_ok=True)
    tracked_promotion = dict(promotion_outcome_receipt)
    tracked_promotion["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_PROMOTION_OUTCOME_BINDING_RECEIPT"
    tracked_promotion["authoritative_promotion_outcome_binding_receipt_ref"] = authoritative_promotion_outcome_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_PROMOTION_OUTCOME_REPORT_REL).name).resolve(), tracked_promotion)

    tracked_merge = dict(merge_outcome_receipt)
    tracked_merge["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_MERGE_OUTCOME_BINDING_RECEIPT"
    tracked_merge["authoritative_merge_outcome_binding_receipt_ref"] = authoritative_merge_outcome_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_MERGE_OUTCOME_REPORT_REL).name).resolve(), tracked_merge)

    tracked_followthrough = dict(updated_followthrough)
    tracked_followthrough["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FOLLOWTHROUGH_ARTIFACT"
    tracked_followthrough["authoritative_followthrough_packet_ref"] = authoritative_followthrough_out_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FOLLOWTHROUGH_REPORT_REL).name).resolve(), tracked_followthrough)

    return {
        "promotion_outcome_binding_receipt": promotion_outcome_receipt,
        "merge_outcome_binding_receipt": merge_outcome_receipt,
        "followthrough_packet": updated_followthrough,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Bind bounded promotion/merge outcomes after a PASS Cohort-0 merge-child evaluation.")
    ap.add_argument(
        "--promotion-report",
        default=DEFAULT_PROMOTION_REPORT_REL,
        help=f"Tracked promotion candidate report path. Default: {DEFAULT_PROMOTION_REPORT_REL}",
    )
    ap.add_argument(
        "--followthrough-report",
        default=DEFAULT_FOLLOWTHROUGH_REPORT_REL,
        help=f"Tracked tournament followthrough report path. Default: {DEFAULT_FOLLOWTHROUGH_REPORT_REL}",
    )
    ap.add_argument(
        "--child-eval-report",
        default=DEFAULT_CHILD_EVAL_REPORT_REL,
        help=f"Tracked merge child evaluation report path. Default: {DEFAULT_CHILD_EVAL_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: authoritative child-eval parent.",
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
    payload = run_promotion_merge_outcome_binding_tranche(
        promotion_report_path=_resolve_path(root, str(args.promotion_report)),
        followthrough_report_path=_resolve_path(root, str(args.followthrough_report)),
        child_eval_report_path=_resolve_path(root, str(args.child_eval_report)),
        authoritative_root=_resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None,
        reports_root=_resolve_path(root, str(args.reports_root)),
        workspace_root=root,
    )
    promotion = payload["promotion_outcome_binding_receipt"]
    merge = payload["merge_outcome_binding_receipt"]
    print(
        json.dumps(
            {
                "status": promotion["status"],
                "promotion_posture": promotion["promotion_posture"],
                "merge_outcome_posture": merge["merge_outcome_posture"],
                "next_lawful_move": promotion["next_lawful_move"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
