from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet_tranche as t01
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_full_red_to_green_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_full_red_to_green_receipt.json"
OUTPUT_BLOCKERS = "cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_FULL_RED_TO_GREEN_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_FULL_RED_TO_GREEN_BOUND"
OUTCOME = "POST_F_PR15_FL3_REMEDIATION_GREEN__MERGE_READINESS_GRADE"
NEXT_MOVE = "MERGE_PR15_THEN_EXECUTE_CANONICAL_TRUTH_ENGINE_REPLAY_ON_MAIN"

AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
T01_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json"
T02_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_active_tree_asset_expectation_drift_receipt.json"
T03_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_archive_assumption_decontamination_receipt.json"
T04_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_phase_path_normalization_receipt.json"
BUNDLE_PATH = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json"
BUNDLE_SHA_PATH = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256"


def _current_branch_name(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip() or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def _git_rev_parse(root: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout.strip()


def _py_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str((root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()),
            str((root / "KT_PROD_CLEANROOM").resolve()),
        ]
    )
    return env


def _run_meta_evaluator(root: Path) -> Dict[str, Any]:
    result = subprocess.run(
        ["python", "-m", "tools.verification.fl3_meta_evaluator"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_py_env(root),
    )
    combined = "\n".join([part for part in [result.stdout.strip(), result.stderr.strip()] if part])
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "combined_tail": combined[-2000:],
    }


def _parse_pytest_summary(text: str) -> Dict[str, Any]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    summary_line = ""
    for line in reversed(lines):
        if " passed" in line or " failed" in line or " skipped" in line:
            summary_line = line
            break
    counts: Dict[str, int] = {}
    for label in ("passed", "failed", "skipped", "xfailed", "xpassed", "errors"):
        m = re.search(rf"(\d+)\s+{label}", summary_line)
        counts[label] = int(m.group(1)) if m else 0
    return {
        "summary_line": summary_line,
        "counts": counts,
    }


def _run_full_fl3_suite(root: Path) -> Dict[str, Any]:
    result = subprocess.run(
        ["python", "-m", "pytest", "-q", "-o", "addopts=''", "KT_PROD_CLEANROOM/tests/fl3"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    combined = "\n".join([part for part in [result.stdout.strip(), result.stderr.strip()] if part])
    parsed = _parse_pytest_summary(combined)
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "combined_tail": combined[-4000:],
        "summary_line": parsed["summary_line"],
        "counts": parsed["counts"],
    }


def _select_authoritative_ref(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not matches:
        raise RuntimeError("FAIL_CLOSED: no support-chain matches available for authoritative selection")
    return max(matches, key=lambda item: (str(item.get("created_at", "")), str(item.get("path", ""))))


def _require_cleared_tranche(receipt: Dict[str, Any], *, tranche_id: str) -> None:
    if str(receipt.get("tranche_id", "")).strip() != tranche_id:
        raise RuntimeError(f"FAIL_CLOSED: expected receipt for {tranche_id}")
    if str(receipt.get("tranche_state", "")).strip() != "cleared":
        raise RuntimeError(f"FAIL_CLOSED: {tranche_id} is not cleared")


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    authority_packet: Dict[str, Any],
    bundle_hash: str,
    pinned_hash: str,
    amendment_ref: Dict[str, Any],
    change_receipt_ref: Dict[str, Any],
    meta_eval: Dict[str, Any],
    fl3_suite: Dict[str, Any],
    tranche_receipts: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any] | str]:
    blocker_ledger = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_full_red_to_green_blocker_ledger.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "blocking_blocker_count": 0,
        "tranche_states": {
            tranche_id: {
                "tranche_state": str(receipt.get("tranche_state", "")),
                "lane_outcome": str(receipt.get("lane_outcome", "")),
            }
            for tranche_id, receipt in tranche_receipts.items()
        },
        "t05_validation": {
            "meta_evaluator_clean_exit": meta_eval["returncode"] == 0,
            "full_fl3_suite_green": fl3_suite["returncode"] == 0,
            "full_fl3_summary": fl3_suite["summary_line"],
        },
        "live_blockers": [],
    }
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_full_red_to_green_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "claim_boundary": (
            "This packet closes PR15 FL3 remediation scope only. Package promotion remains deferred, truth-engine law remains unchanged, "
            "and canonical replay on main still waits for PR #15 to land."
        ),
        "authority_header": {
            "authoritative_branch": branch_name,
            "authoritative_branch_head": branch_head,
            "package_promotion_still_deferred": bool(
                authority_packet.get("authority_header", {}).get("package_promotion_still_deferred", False)
            ),
            "truth_engine_law_unchanged": bool(
                authority_packet.get("authority_header", {}).get("truth_engine_law_unchanged", False)
            ),
            "replay_on_main_still_deferred_until_pr15_merge": bool(
                authority_packet.get("authority_header", {}).get("replay_on_main_still_deferred_until_pr15_merge", False)
            ),
        },
        "t05_header": {
            "tranche_id": "T05",
            "tranche_name": "full_red_to_green",
            "ordered_blocker_position": 5,
            "tranche_state": "complete",
        },
        "final_law_bundle_state": {
            "bundle_manifest_path": common.resolve_path(repo_root(), BUNDLE_PATH).as_posix(),
            "bundle_sha_pin_path": common.resolve_path(repo_root(), BUNDLE_SHA_PATH).as_posix(),
            "computed_bundle_hash": bundle_hash,
            "pinned_bundle_hash": pinned_hash,
            "pin_matches_current": bundle_hash == pinned_hash,
            "authoritative_amendment_ref": amendment_ref["path"],
            "authoritative_change_receipt_ref": change_receipt_ref["path"],
            "authoritative_amendment_id": amendment_ref.get("amendment_id"),
            "authoritative_change_receipt_id": change_receipt_ref.get("receipt_id"),
        },
        "validation_result": {
            "meta_evaluator": {
                "returncode": meta_eval["returncode"],
                "tail": meta_eval["combined_tail"],
            },
            "full_fl3_suite": {
                "returncode": fl3_suite["returncode"],
                "summary_line": fl3_suite["summary_line"],
                "counts": fl3_suite["counts"],
            },
        },
        "tranche_clearance": {
            "T01": "cleared",
            "T02": "cleared",
            "T03": "cleared",
            "T04": "cleared",
            "T05": "complete_via_full_red_to_green_validation",
        },
        "boundary_preservation": {
            "pr15_merge_readiness_closeout_only": True,
            "package_promotion_still_deferred": True,
            "truth_engine_law_still_unchanged": True,
            "main_replay_still_deferred_until_pr15_lands": True,
            "untracked_wave_residue_explicitly_out_of_scope": True,
        },
        "blocker_ledger_ref": common.resolve_path(
            repo_root(), f"KT_PROD_CLEANROOM/reports/{OUTPUT_BLOCKERS}"
        ).as_posix(),
        "source_refs": common.output_ref_dict(
            remediation_authority_packet=common.resolve_path(repo_root(), AUTHORITY_PACKET_PATH),
            tranche1_receipt=common.resolve_path(repo_root(), T01_RECEIPT_PATH),
            tranche2_receipt=common.resolve_path(repo_root(), T02_RECEIPT_PATH),
            tranche3_receipt=common.resolve_path(repo_root(), T03_RECEIPT_PATH),
            tranche4_receipt=common.resolve_path(repo_root(), T04_RECEIPT_PATH),
            law_bundle_sha=common.resolve_path(repo_root(), BUNDLE_SHA_PATH),
            law_bundle=common.resolve_path(repo_root(), BUNDLE_PATH),
        ),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_full_red_to_green_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "blocking_blocker_count": 0,
        "bundle_hash": bundle_hash,
        "meta_evaluator_returncode": meta_eval["returncode"],
        "full_fl3_summary": fl3_suite["summary_line"],
        "full_fl3_counts": fl3_suite["counts"],
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Full Red To Green Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{OUTCOME}`",
            f"- Final bundle hash: `{bundle_hash}`",
            f"- Meta evaluator returncode: `{meta_eval['returncode']}`",
            f"- Full FL3 suite: `{fl3_suite['summary_line']}`",
            "- Tranche 1 cleared.",
            "- Tranche 2 cleared.",
            "- Tranche 3 cleared.",
            "- Tranche 4 cleared.",
            "- Tranche 5 complete via full red-to-green validation.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "blockers": blocker_ledger, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    tranche1_receipt_path: Path,
    tranche2_receipt_path: Path,
    tranche3_receipt_path: Path,
    tranche4_receipt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T05 must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T05 requires a clean tracked worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 FL3 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 FL3 remediation authority receipt")
    tranche1_receipt = common.load_json_required(root, tranche1_receipt_path, label="tranche T01 receipt")
    tranche2_receipt = common.load_json_required(root, tranche2_receipt_path, label="tranche T02 receipt")
    tranche3_receipt = common.load_json_required(root, tranche3_receipt_path, label="tranche T03 receipt")
    tranche4_receipt = common.load_json_required(root, tranche4_receipt_path, label="tranche T04 receipt")
    common.ensure_pass(authority_packet, label="PR15 FL3 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 FL3 remediation authority receipt")
    common.ensure_pass(tranche1_receipt, label="tranche T01 receipt")
    common.ensure_pass(tranche2_receipt, label="tranche T02 receipt")
    common.ensure_pass(tranche3_receipt, label="tranche T03 receipt")
    common.ensure_pass(tranche4_receipt, label="tranche T04 receipt")
    _require_cleared_tranche(tranche1_receipt, tranche_id="T01")
    _require_cleared_tranche(tranche2_receipt, tranche_id="T02")
    _require_cleared_tranche(tranche3_receipt, tranche_id="T03")
    _require_cleared_tranche(tranche4_receipt, tranche_id="T04")
    if str(tranche4_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_PR15_FL3_FULL_RED_TO_GREEN_PACKET":
        raise RuntimeError("FAIL_CLOSED: tranche T04 receipt no longer authorizes tranche T05 packet")

    bundle = t01._load_law_bundle(root)
    bundle_hash = t01._compute_bundle_hash(root, bundle)
    pinned_hash = common.resolve_path(root, BUNDLE_SHA_PATH).read_text(encoding="utf-8").strip()
    if bundle_hash != pinned_hash:
        raise RuntimeError("FAIL_CLOSED: final bundle hash does not match pinned LAW_BUNDLE_FL3.sha256")

    amendment_matches = t01._scan_amendment_support(root, bundle_hash)
    change_receipt_matches = t01._scan_change_receipt_support(root, bundle_hash)
    if not amendment_matches or not change_receipt_matches:
        raise RuntimeError("FAIL_CLOSED: current bundle hash lacks complete support chain")
    amendment_ref = _select_authoritative_ref(amendment_matches)
    change_receipt_ref = _select_authoritative_ref(change_receipt_matches)

    meta_eval = _run_meta_evaluator(root)
    if int(meta_eval["returncode"]) != 0:
        raise RuntimeError(f"FAIL_CLOSED: fl3_meta_evaluator still red\n{meta_eval['combined_tail']}")
    fl3_suite = _run_full_fl3_suite(root)
    if int(fl3_suite["returncode"]) != 0:
        raise RuntimeError(f"FAIL_CLOSED: full FL3 suite still red\n{fl3_suite['combined_tail']}")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_packet=authority_packet,
        bundle_hash=bundle_hash,
        pinned_hash=pinned_hash,
        amendment_ref=amendment_ref,
        change_receipt_ref=change_receipt_ref,
        meta_eval=meta_eval,
        fl3_suite=fl3_suite,
        tranche_receipts={
            "T01": tranche1_receipt,
            "T02": tranche2_receipt,
            "T03": tranche3_receipt,
            "T04": tranche4_receipt,
        },
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    common.write_text(
        (reports_root / OUTPUT_BLOCKERS).resolve(),
        __import__("json").dumps(outputs["blockers"], indent=2, sort_keys=True) + "\n",
    )
    return {
        "lane_outcome": OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Freeze PR15 FL3 tranche T05 full red-to-green closeout.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--tranche1-receipt", default=T01_RECEIPT_PATH)
    parser.add_argument("--tranche2-receipt", default=T02_RECEIPT_PATH)
    parser.add_argument("--tranche3-receipt", default=T03_RECEIPT_PATH)
    parser.add_argument("--tranche4-receipt", default=T04_RECEIPT_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        tranche1_receipt_path=common.resolve_path(root, args.tranche1_receipt),
        tranche2_receipt_path=common.resolve_path(root, args.tranche2_receipt),
        tranche3_receipt_path=common.resolve_path(root, args.tranche3_receipt),
        tranche4_receipt_path=common.resolve_path(root, args.tranche4_receipt),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
