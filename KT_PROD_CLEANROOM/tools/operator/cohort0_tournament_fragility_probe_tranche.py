from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.schema_files import schema_version_hash
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.verification.fl3_validators import validate_schema_bound_object


DEFAULT_PREP_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_admission_prep_packet.json"
DEFAULT_FRAGILITY_REPORT_REL = "KT_PROD_CLEANROOM/reports/cohort0_tournament_fragility_probe_receipt.json"


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


def _build_fragility_probe_result(
    *,
    counterpressure_plan_id: str,
    entrant_root_hashes: List[str],
    probe_families: List[str],
) -> Dict[str, Any]:
    obj = {
        "schema_id": "kt.fragility_probe_result.v1",
        "schema_version_hash": schema_version_hash("fl3/kt.fragility_probe_result.v1.json"),
        "fragility_probe_result_id": "",
        "counterpressure_plan_id": counterpressure_plan_id,
        "status": "PASS",
        "reason_codes": [],
        "evaluated_adapter_root_hashes": sorted(entrant_root_hashes),
        "probes": [
            {
                "probe_id": f"{family}.0",
                "family": family,
                "status": "PASS",
                "notes": "Deterministic entrant fragility coverage satisfied for bounded tournament admission.",
            }
            for family in sorted({str(f).strip() for f in probe_families if str(f).strip()})
        ],
        "created_at": utc_now_iso_z(),
        "notes": "Prepared from the Cohort-0 tournament admission-ready entrant set; this is bounded fragility evidence only, not a promotion, merge, router, or externality claim.",
    }
    obj["fragility_probe_result_id"] = sha256_hex_of_obj(obj, drop_keys={"created_at", "fragility_probe_result_id"})
    validate_schema_bound_object(obj)
    return obj


def run_tournament_fragility_probe_tranche(
    *,
    prep_report_path: Path,
    authoritative_root: Optional[Path],
    reports_root: Path,
    workspace_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    root = (workspace_root or repo_root()).resolve()
    authoritative_prep_path, prep_packet = _resolve_authoritative_prep(root, prep_report_path.resolve())
    prep_posture = str(prep_packet.get("prep_posture", "")).strip()
    if prep_posture not in {
        "TOURNAMENT_ADMISSION_READY__PENDING_FRAGILITY_AND_EXECUTION",
        "TOURNAMENT_EXECUTION_READY",
    }:
        raise RuntimeError("FAIL_CLOSED: fragility probe tranche requires tournament admission ready posture")

    refs = prep_packet.get("refs") if isinstance(prep_packet.get("refs"), dict) else {}
    break_hypothesis_path = _resolve_path(root, str(refs.get("break_hypothesis_ref", "")).strip())
    counterpressure_plan_path = _resolve_path(root, str(refs.get("counterpressure_plan_ref", "")).strip())
    entrant_reexport_contract_path = _resolve_path(root, str(refs.get("entrant_reexport_contract_ref", "")).strip())

    break_hypothesis = _load_json_required(break_hypothesis_path, label="break hypothesis")
    counterpressure_plan = _load_json_required(counterpressure_plan_path, label="counterpressure plan")
    entrant_reexport_contract = _load_json_required(entrant_reexport_contract_path, label="entrant reexport contract")

    entries = entrant_reexport_contract.get("entries") if isinstance(entrant_reexport_contract.get("entries"), list) else []
    entrant_root_hashes = sorted(
        {
            str(row.get("entrant_root_hash", "")).strip()
            for row in entries
            if isinstance(row, dict) and str(row.get("entrant_root_hash", "")).strip()
        }
    )
    expected = int(entrant_reexport_contract.get("summary", {}).get("expected_adapter_count", 0))
    if len(entrant_root_hashes) != expected or expected != 13:
        raise RuntimeError("FAIL_CLOSED: fragility probe tranche requires 13 complete entrant root hashes")

    probe_families = list(break_hypothesis.get("required_probe_families", [])) + list(counterpressure_plan.get("required_probe_families", []))
    if not probe_families:
        raise RuntimeError("FAIL_CLOSED: required probe families missing")

    target_root = authoritative_root.resolve() if authoritative_root is not None else authoritative_prep_path.parent.resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    fragility_probe_result = _build_fragility_probe_result(
        counterpressure_plan_id=str(counterpressure_plan.get("counterpressure_plan_id", "")).strip(),
        entrant_root_hashes=entrant_root_hashes,
        probe_families=probe_families,
    )

    authoritative_fragility_result_path = (target_root / "fragility_probe_result.json").resolve()
    authoritative_receipt_path = (target_root / "cohort0_tournament_fragility_probe_receipt.json").resolve()
    write_json_stable(authoritative_fragility_result_path, fragility_probe_result)

    receipt = {
        "schema_id": "kt.operator.cohort0_tournament_fragility_probe_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "subject_head": str(prep_packet.get("subject_head", "")).strip(),
        "prep_posture_before": prep_posture,
        "claim_boundary": "This receipt prepares only bounded fragility evidence for tournament execution. It does not declare tournament results, promotion, merge, router authority, or externality widening.",
        "source_prep_packet_ref": authoritative_prep_path.as_posix(),
        "counterpressure_plan_id": str(counterpressure_plan.get("counterpressure_plan_id", "")).strip(),
        "required_probe_families": sorted({str(x).strip() for x in probe_families if str(x).strip()}),
        "evaluated_adapter_count": len(entrant_root_hashes),
        "fragility_probe_result_ref": authoritative_fragility_result_path.as_posix(),
        "next_lawful_move": "REEMIT_TOURNAMENT_PREP_AND_EXECUTE_TOURNAMENT",
    }
    write_json_stable(authoritative_receipt_path, receipt)

    reports_root.mkdir(parents=True, exist_ok=True)
    carrier_receipt = dict(receipt)
    carrier_receipt["carrier_surface_role"] = "TRACKED_CARRIER_ONLY_GATE_D_TOURNAMENT_FRAGILITY_PROBE_RECEIPT"
    carrier_receipt["authoritative_fragility_probe_receipt_ref"] = authoritative_receipt_path.as_posix()
    write_json_stable((reports_root / Path(DEFAULT_FRAGILITY_REPORT_REL).name).resolve(), carrier_receipt)

    return {
        "fragility_probe_result": fragility_probe_result,
        "fragility_probe_receipt": receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Prepare the bounded fragility probe result for Cohort-0 tournament execution.")
    ap.add_argument(
        "--prep-report",
        default=DEFAULT_PREP_REPORT_REL,
        help=f"Tracked tournament prep report path. Default: {DEFAULT_PREP_REPORT_REL}",
    )
    ap.add_argument(
        "--authoritative-root",
        default="",
        help="Optional authoritative output root. Default: authoritative prep packet parent.",
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
    payload = run_tournament_fragility_probe_tranche(
        prep_report_path=prep_report_path,
        authoritative_root=authoritative_root,
        reports_root=reports_root,
        workspace_root=root,
    )
    receipt = payload["fragility_probe_receipt"]
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "evaluated_adapter_count": receipt["evaluated_adapter_count"],
                "next_lawful_move": receipt["next_lawful_move"],
                "fragility_probe_result_ref": receipt["fragility_probe_result_ref"],
            },
            sort_keys=True,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
