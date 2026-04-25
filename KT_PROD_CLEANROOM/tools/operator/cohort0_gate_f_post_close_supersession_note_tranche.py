from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import (
    cohort0_gate_f_post_close_live_product_truth_tranche as live_product_truth_tranche,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


OUTPUT_NOTE = "cohort0_gate_f_post_close_supersession_note.json"
OUTPUT_RECEIPT = "cohort0_gate_f_post_close_supersession_note_receipt.json"
OUTPUT_REPORT = "COHORT0_GATE_F_POST_CLOSE_SUPERSESSION_REPORT.md"

EXECUTION_STATUS = "PASS__GATE_F_POST_CLOSE_SUPERSESSION_BOUND"

HISTORICAL_SURFACE_REFS = (
    f"{common.REPORTS_ROOT_REL}/commercial_truth_packet.json",
    f"{common.PRODUCT_ROOT_REL}/final_product_truth_boundary.json",
    f"{common.REPORTS_ROOT_REL}/kt_product_surface_manifest.json",
    f"{common.REPORTS_ROOT_REL}/kt_product_surface_receipt.json",
    f"{common.REPORTS_ROOT_REL}/kt_product_wedge_activation_receipt.json",
)


def _resolve(root: Path, raw: str | Path) -> Path:
    return common.resolve_path(root, raw)


def _load_json_object(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")
    payload = load_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {label} must be a JSON object: {path.as_posix()}")
    return payload


def run(
    *,
    reports_root: Path,
    live_product_truth_packet_path: Path,
    live_product_truth_receipt_path: Path,
) -> Dict[str, str]:
    root = repo_root()
    live_product_truth_packet = common.load_json_required(
        root, live_product_truth_packet_path, label="Gate F live product truth packet"
    )
    live_product_truth_receipt = common.load_json_required(
        root, live_product_truth_receipt_path, label="Gate F live product truth receipt"
    )
    common.ensure_pass(live_product_truth_packet, label="Gate F live product truth packet")
    common.ensure_pass(live_product_truth_receipt, label="Gate F live product truth receipt")
    if str(live_product_truth_receipt.get("current_product_posture", "")).strip() != common.GATE_F_CONFIRMED_POSTURE:
        raise RuntimeError("FAIL_CLOSED: Gate F post-close supersession requires the confirmed narrow-wedge posture")

    historical_refs = []
    for rel in HISTORICAL_SURFACE_REFS:
        path = _resolve(root, rel)
        _load_json_object(path, label=Path(rel).name)
        historical_refs.append(path.resolve().as_posix())

    note = {
        "schema_id": "kt.operator.cohort0_gate_f_post_close_supersession_note.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": (
            "This note preserves older product/commercial surfaces as historical lineage while freezing the "
            "Gate F one-wedge product truth as the only live product posture."
        ),
        "execution_status": EXECUTION_STATUS,
        "historical_product_truth_not_erased": True,
        "historically_valid_but_live_superseded_surfaces": historical_refs,
        "authoritative_live_product_surfaces_now": [
            live_product_truth_packet_path.resolve().as_posix(),
            live_product_truth_receipt_path.resolve().as_posix(),
        ],
        "gate_f_post_close_live_product_truth_supersedes_prior_product_headers_for_live_posture": True,
        "supersession_rule": (
            "Earlier bounded product/commercial surfaces remain historically valid. "
            "For live product posture only, they are superseded by the Gate F post-close live product truth packet "
            "and receipt."
        ),
        "next_lawful_move": common.NEXT_MOVE_POST_F_REAUDIT,
        "subject_head": str(live_product_truth_receipt.get("subject_head", "")).strip(),
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_gate_f_post_close_supersession_note_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "claim_boundary": note["claim_boundary"],
        "execution_status": EXECUTION_STATUS,
        "gate_f_post_close_live_product_truth_supersedes_prior_product_headers_for_live_posture": True,
        "historical_product_truth_not_erased": True,
        "next_lawful_move": common.NEXT_MOVE_POST_F_REAUDIT,
        "subject_head": note["subject_head"],
    }
    report = common.report_lines(
        "Cohort0 Gate F Post-Close Supersession Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            "- Historical product/commercial lineage preserved: `True`",
            "- Live product posture supersession bound: `True`",
            f"- Next lawful move: `{common.NEXT_MOVE_POST_F_REAUDIT}`",
        ],
    )

    note_path = (reports_root / OUTPUT_NOTE).resolve()
    receipt_path = (reports_root / OUTPUT_RECEIPT).resolve()
    report_path = (reports_root / OUTPUT_REPORT).resolve()
    write_json_stable(note_path, note)
    write_json_stable(receipt_path, receipt)
    common.write_text(report_path, report)
    return {
        "note_path": note_path.as_posix(),
        "receipt_path": receipt_path.as_posix(),
        "report_path": report_path.as_posix(),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the Gate F post-close supersession note.")
    parser.add_argument(
        "--live-product-truth-packet",
        default=f"{common.REPORTS_ROOT_REL}/{live_product_truth_tranche.OUTPUT_PACKET}",
    )
    parser.add_argument(
        "--live-product-truth-receipt",
        default=f"{common.REPORTS_ROOT_REL}/{live_product_truth_tranche.OUTPUT_RECEIPT}",
    )
    args = parser.parse_args(argv)
    root = repo_root()
    result = run(
        reports_root=common.resolve_path(root, args.reports_root),
        live_product_truth_packet_path=common.resolve_path(root, args.live_product_truth_packet),
        live_product_truth_receipt_path=common.resolve_path(root, args.live_product_truth_receipt),
    )
    print(result["note_path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
