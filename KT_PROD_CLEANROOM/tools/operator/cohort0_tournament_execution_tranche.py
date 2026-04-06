from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.tournament.run_tournament import run_tournament


DEFAULT_PREP_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_admission_prep_packet.json"
DEFAULT_EXEC_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_execution_receipt.json"


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


def _resolve_authoritative_prep(root: Path, prep_report_path: Path) -> Tuple[Path, Dict[str, Any]]:
    tracked = _load_json_required(prep_report_path, label="tracked tournament prep packet")
    authoritative_ref = str(tracked.get("authoritative_prep_packet_ref", "")).strip()
    if authoritative_ref:
        authoritative_path = _resolve_path(root, authoritative_ref)
    else:
        authoritative_path = prep_report_path.resolve()
    return authoritative_path, _load_json_required(authoritative_path, label="authoritative tournament prep packet")


def run_tournament_execution_tranche(
    *,
    prep_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_prep_path, prep_packet = _resolve_authoritative_prep(root, prep_report_path.resolve())
    if str(prep_packet.get("prep_posture", "")).strip() != "TOURNAMENT_EXECUTION_READY":
        raise RuntimeError("FAIL_CLOSED: tournament execution tranche requires TOURNAMENT_EXECUTION_READY posture")

    refs = prep_packet.get("refs") if isinstance(prep_packet.get("refs"), dict) else {}
    tournament_plan_path = _resolve_path(root, str(refs.get("tournament_plan_ref", "")).strip())
    tournament_entrants_root = _resolve_path(root, str(refs.get("tournament_entrants_root_ref", "")).strip())
    evaluation_admission_path = _resolve_path(root, str(refs.get("evaluation_admission_ref", "")).strip())
    break_hypothesis_path = _resolve_path(root, str(refs.get("break_hypothesis_ref", "")).strip())
    counterpressure_plan_path = _resolve_path(root, str(refs.get("counterpressure_plan_ref", "")).strip())
    fragility_probe_result_path = _resolve_path(root, str(refs.get("fragility_probe_result_ref", "")).strip())
    for path, label in (
        (tournament_plan_path, "tournament plan"),
        (tournament_entrants_root, "tournament entrants root"),
        (evaluation_admission_path, "evaluation admission receipt"),
        (break_hypothesis_path, "break hypothesis"),
        (counterpressure_plan_path, "counterpressure plan"),
        (fragility_probe_result_path, "fragility probe result"),
    ):
        if not path.exists():
            raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")

    execution_root = authoritative_root.resolve() if authoritative_root is not None else (authoritative_prep_path.parent / "tournament_execution").resolve()
    execution_root.mkdir(parents=True, exist_ok=True)

    result = run_tournament(
        repo_root=root,
        plan_path=tournament_plan_path,
        entrants_root=tournament_entrants_root,
        out_dir=execution_root,
        admission_receipt_path=evaluation_admission_path,
        break_hypothesis_path=break_hypothesis_path,
        counterpressure_plan_path=counterpressure_plan_path,
        fragility_probe_result_path=fragility_probe_result_path,
    )
    tournament_result_path = (execution_root / "tournament_result.json").resolve()
    tournament_result = _load_json_required(tournament_result_path, label="tournament result")

    receipt = {
        "schema_id": "kt.operator.cohort0_tournament_execution_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(prep_packet.get("subject_head", "")).strip(),
        "claim_boundary": "This receipt captures only bounded tournament execution from the prepared Cohort-0 entrant set. It does not by itself declare promotion, merge, router authority, or externality widening.",
        "source_prep_packet_ref": authoritative_prep_path.as_posix(),
        "tournament_result_ref": tournament_result_path.as_posix(),
        "tournament_plan_ref": tournament_plan_path.as_posix(),
        "champion_count": len(list(tournament_result.get("champion_set", []))),
        "champion_set": list(tournament_result.get("champion_set", [])),
        "dominance_pair_count": len(list(tournament_result.get("dominance_pairs", []))),
        "next_lawful_move": "PREPARE_PROMOTION_AND_MERGE_FOLLOWTHROUGH",
    }
    authoritative_receipt_path = (authoritative_prep_path.parent / "cohort0_tournament_execution_receipt.json").resolve()
    write_json_stable(authoritative_receipt_path, receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_receipt = dict(receipt)
    carrier_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_EXECUTION_RECEIPT"
    carrier_receipt["authoritative_tournament_execution_receipt_ref"] = authoritative_receipt_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_EXEC_REPORT_REL).name).resolve(), carrier_receipt)

    return {
        "tournament_result": result,
        "tournament_execution_receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Execute the bounded Cohort-0 tournament once the prep packet is execution-ready.")
    ap.add_argument(
        "--prep-report",
        default=DEFAULT_PREP_REPORT_REL,
        help=f"Tracked tournament prep report path. Default: {DEFAULT_PREP_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional tournament execution output root. Default: <authoritative_prep_parent>/tournament_execution",
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
    prep_report_path = _resolve_path(root, str(args.prep_report))
    authoritative_root = _resolve_path(root, str(args.authoritative_root)) if str(args.authoritative_root).strip() else None
    reports_root = _resolve_path(root, str(args.reports_root))
    payload = run_tournament_execution_tranche(
        prep_report_path=prep_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    receipt = payload["tournament_execution_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "champion_count": receipt["champion_count"],
                "next_lawful_move": receipt["next_lawful_move"],
                "tournament_result_ref": receipt["tournament_result_ref"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
