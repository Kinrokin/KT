from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REPORT.md"

REQUIRED_BRANCH = "authoritative/post-f-pr15-fl3-remediation"
EXECUTION_STATUS = "PASS__POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_BOUND"
OUTCOME = "POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_DEFINED__CURRENT_HASH_SUPPORT_CHAIN_MISSING"
NEXT_MOVE = "EXECUTE_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_REMEDIATION"

BUNDLE_PATH = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.json"
BUNDLE_SHA_PATH = "KT_PROD_CLEANROOM/AUDITS/LAW_BUNDLE_FL3.sha256"
AUTHORITY_PACKET_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_packet.json"
AUTHORITY_RECEIPT_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_authority_receipt.json"
BLOCKER_LEDGER_PATH = "KT_PROD_CLEANROOM/reports/cohort0_post_f_pr15_fl3_remediation_blocker_ledger.json"


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
        ["git", "status", "--porcelain"],
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


def _load_law_bundle(root: Path) -> Dict[str, Any]:
    return common.load_json_required(root, common.resolve_path(root, BUNDLE_PATH), label="LAW_BUNDLE_FL3")


def _read_sha_pin(root: Path) -> str:
    return common.resolve_path(root, BUNDLE_SHA_PATH).read_text(encoding="utf-8").strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_bundle_member(root: Path, rel_path: str) -> str:
    path = common.resolve_path(root, rel_path)
    data = path.read_bytes()
    if path.suffix.lower() == ".json":
        obj = json.loads(data.decode("utf-8"))
        if rel_path.replace("\\", "/").endswith("FL4_DETERMINISM_CONTRACT.json") and isinstance(obj, dict):
            obj = dict(obj)
            obj.pop("canary_expected_hash_manifest_root_hash", None)
            obj.pop("determinism_contract_id", None)
        canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return _sha256_bytes(canon)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _sha256_bytes(data)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _sha256_bytes(text.encode("utf-8"))


def _compute_bundle_hash(root: Path, bundle: Dict[str, Any]) -> str:
    paths = sorted(str(item["path"]) for item in bundle.get("files", []))
    lines = [f"{rel}:{_hash_bundle_member(root, rel)}\n" for rel in paths]
    laws = bundle.get("laws", [])
    laws_canon = json.dumps(laws, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    lines.append(f"__LAWS__:{_sha256_bytes(laws_canon)}\n")
    return _sha256_bytes("".join(lines).encode("utf-8"))


def _scan_amendment_support(root: Path, bundle_hash: str) -> List[Dict[str, Any]]:
    audits_root = common.resolve_path(root, "KT_PROD_CLEANROOM/AUDITS")
    matches: List[Dict[str, Any]] = []
    for path in sorted(audits_root.glob("LAW_AMENDMENT_FL3_*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if payload.get("schema_id") != "kt.law_amendment.v2":
            continue
        if payload.get("bundle_hash") != bundle_hash:
            continue
        matches.append(
            {
                "path": path.resolve().as_posix(),
                "amendment_id": payload.get("amendment_id"),
                "attestation_mode": payload.get("attestation_mode"),
                "bundle_hash": payload.get("bundle_hash"),
                "created_at": payload.get("created_at"),
            }
        )
    return matches


def _scan_change_receipt_support(root: Path, bundle_hash: str) -> List[Dict[str, Any]]:
    audits_root = common.resolve_path(root, "KT_PROD_CLEANROOM/AUDITS")
    matches: List[Dict[str, Any]] = []
    for path in sorted(audits_root.glob("LAW_BUNDLE_CHANGE_RECEIPT_FL3_*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if payload.get("schema_id") != "kt.law_bundle_change_receipt.v1":
            continue
        if payload.get("new_bundle_hash") != bundle_hash:
            continue
        matches.append(
            {
                "path": path.resolve().as_posix(),
                "receipt_id": payload.get("receipt_id"),
                "new_bundle_hash": payload.get("new_bundle_hash"),
                "old_bundle_hash": payload.get("old_bundle_hash"),
                "created_at": payload.get("created_at"),
            }
        )
    return matches


def _probe_fl3_meta_evaluator(root: Path) -> Dict[str, Any]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str((root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src").resolve()),
            str((root / "KT_PROD_CLEANROOM").resolve()),
        ]
    )
    result = subprocess.run(
        ["python", "-m", "tools.verification.fl3_meta_evaluator"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
    )
    combined = "\n".join([part for part in [result.stdout.strip(), result.stderr.strip()] if part])
    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "combined_tail": combined[-1600:],
    }


def _resolution_classes() -> List[Dict[str, str]]:
    return [
        {
            "class_id": "UPDATE_EVALUATOR_EXPECTATION",
            "summary": "Use only if the evaluator is asserting the wrong bundle identifier, amendment family, or change-receipt family.",
        },
        {
            "class_id": "RESTORE_MISSING_LAW_BUNDLE_ARTIFACT",
            "summary": "Use when the active bundle hash is correct but one or more required support artifacts are absent from the active tree.",
        },
        {
            "class_id": "BIND_SUPERSESSION_AND_AMENDMENT_MAPPING",
            "summary": "Use when the active tree has advanced to a new bundle hash and needs a new lawful amendment/change-receipt chain that supersedes the prior documented hash.",
        },
        {
            "class_id": "QUARANTINE_STALE_ASSUMPTION",
            "summary": "Use when a stale pin or historical support surface is still being treated like current truth and must be explicitly demoted to lineage-only.",
        },
    ]


def _mismatch_class(*, computed_hash: str, pinned_hash: str, current_amendments: List[Dict[str, Any]], current_receipts: List[Dict[str, Any]]) -> str:
    if computed_hash != pinned_hash and not current_amendments and not current_receipts:
        return "ACTIVE_TREE_BUNDLE_AHEAD_OF_STALE_SUPPORT_CHAIN"
    if computed_hash == pinned_hash and (not current_amendments or not current_receipts):
        return "PIN_MATCHES__SUPPORT_CHAIN_PARTIAL"
    if computed_hash != pinned_hash:
        return "HASH_PIN_AND_ACTIVE_TREE_DIVERGED"
    return "MISMATCH_CLASS_NOT_APPLICABLE"


def build_outputs(
    *,
    branch_name: str,
    branch_head: str,
    authority_packet: Dict[str, Any],
    blocker_ledger: Dict[str, Any],
    bundle: Dict[str, Any],
    computed_hash: str,
    pinned_hash: str,
    current_amendments: List[Dict[str, Any]],
    current_receipts: List[Dict[str, Any]],
    pinned_amendments: List[Dict[str, Any]],
    pinned_receipts: List[Dict[str, Any]],
    meta_probe: Dict[str, Any],
) -> Dict[str, Dict[str, Any] | str]:
    mismatch_class = _mismatch_class(
        computed_hash=computed_hash,
        pinned_hash=pinned_hash,
        current_amendments=current_amendments,
        current_receipts=current_receipts,
    )
    packet = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "claim_boundary": (
            "This packet freezes tranche T01 only. It does not change package truth, truth-engine law, replay timing on main, "
            "or archive/canonical authority boundaries."
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
        "tranche_header": {
            "tranche_id": "T01",
            "tranche_name": "law_bundle_and_amendment_mismatch",
            "ordered_blocker_position": 1,
            "mismatch_class": mismatch_class,
        },
        "evaluator_assertion": {
            "bundle_id": str(bundle.get("bundle_id", "")),
            "active_law_id": str((bundle.get("laws") or [{}])[0].get("law_id", "")),
            "amendment_schema_id_required": "kt.law_amendment.v2",
            "change_receipt_schema_id_required": "kt.law_bundle_change_receipt.v1",
            "evaluator_probe_returncode": int(meta_probe.get("returncode", 1)),
            "evaluator_probe_tail": meta_probe.get("combined_tail", ""),
        },
        "live_bundle_state": {
            "bundle_manifest_path": common.resolve_path(repo_root(), BUNDLE_PATH).as_posix(),
            "bundle_sha_pin_path": common.resolve_path(repo_root(), BUNDLE_SHA_PATH).as_posix(),
            "bundle_file_count": len(bundle.get("files", [])),
            "law_count": len(bundle.get("laws", [])),
            "computed_bundle_hash": computed_hash,
            "pinned_bundle_hash": pinned_hash,
            "pin_matches_current": computed_hash == pinned_hash,
        },
        "support_chain_state": {
            "current_hash": {
                "bundle_hash": computed_hash,
                "matching_law_amendment_v2_count": len(current_amendments),
                "matching_law_amendment_v2_refs": [entry["path"] for entry in current_amendments],
                "matching_change_receipt_count": len(current_receipts),
                "matching_change_receipt_refs": [entry["path"] for entry in current_receipts],
            },
            "pinned_hash": {
                "bundle_hash": pinned_hash,
                "matching_law_amendment_v2_count": len(pinned_amendments),
                "matching_law_amendment_v2_refs": [entry["path"] for entry in pinned_amendments],
                "matching_change_receipt_count": len(pinned_receipts),
                "matching_change_receipt_refs": [entry["path"] for entry in pinned_receipts],
            },
        },
        "precedence_rule": {
            "winning_source": "computed_active_tree_law_bundle_hash",
            "winning_rule": (
                "The active-tree LAW_BUNDLE hash computed from LAW_BUNDLE_FL3.json membership and current member bytes outranks "
                "the pinned sha file and prior amendment/change-receipt lineage when they disagree."
            ),
            "staleness_decision_rule": (
                "If the current active-tree hash lacks a matching kt.law_amendment.v2 or kt.law_bundle_change_receipt.v1 while "
                "the pinned hash still has them, the support chain is stale relative to the active tree; the evaluator contract is not stale."
            ),
            "resolution_decision_rule": (
                "Prefer binding a new lawful amendment/change-receipt chain for the active hash over weakening the evaluator contract."
            ),
        },
        "allowed_resolution_classes": _resolution_classes(),
        "live_resolution_read": {
            "evaluator_contract_is_stale": False,
            "active_tree_bundle_hash_has_complete_support_chain": bool(current_amendments and current_receipts),
            "stale_pinned_support_chain_present": bool(pinned_amendments and pinned_receipts),
            "recommended_resolution_class": "BIND_SUPERSESSION_AND_AMENDMENT_MAPPING",
            "recommended_resolution_summary": (
                "The active tree has advanced to a new bundle hash, while the current support chain still terminates at the prior pinned hash."
            ),
        },
        "do_not_widen_boundaries": authority_packet.get("do_not_widen_boundaries", []),
        "success_condition": {
            "mismatch_class_resolved_and_receipted": True,
            "blocker_ledger_advances_to_tranche_2": True,
            "package_truth_unchanged": True,
            "truth_engine_law_unchanged": True,
            "main_replay_still_deferred": True,
            "archive_promotion_forbidden": True,
        },
        "source_refs": common.output_ref_dict(
            remediation_authority_packet=common.resolve_path(repo_root(), AUTHORITY_PACKET_PATH),
            remediation_authority_receipt=common.resolve_path(repo_root(), AUTHORITY_RECEIPT_PATH),
            remediation_blocker_ledger=common.resolve_path(repo_root(), BLOCKER_LEDGER_PATH),
            law_bundle=common.resolve_path(repo_root(), BUNDLE_PATH),
            law_bundle_sha=common.resolve_path(repo_root(), BUNDLE_SHA_PATH),
            fl3_meta_evaluator=common.resolve_path(repo_root(), "KT_PROD_CLEANROOM/tools/verification/fl3_meta_evaluator.py"),
        ),
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_pr15_fl3_law_bundle_and_amendment_mismatch_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "lane_outcome": OUTCOME,
        "tranche_id": "T01",
        "mismatch_class": mismatch_class,
        "computed_bundle_hash": computed_hash,
        "pinned_bundle_hash": pinned_hash,
        "current_hash_support_complete": bool(current_amendments and current_receipts),
        "pinned_hash_support_present": bool(pinned_amendments and pinned_receipts),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F PR15 FL3 Law Bundle And Amendment Mismatch Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Lane outcome: `{OUTCOME}`",
            "- Tranche: `T01 law_bundle_and_amendment_mismatch`",
            f"- Computed active-tree bundle hash: `{computed_hash}`",
            f"- Pinned LAW_BUNDLE hash: `{pinned_hash}`",
            f"- Current-hash amendment matches: `{len(current_amendments)}`",
            f"- Current-hash change receipt matches: `{len(current_receipts)}`",
            f"- Pinned-hash amendment matches: `{len(pinned_amendments)}`",
            f"- Pinned-hash change receipt matches: `{len(pinned_receipts)}`",
            "- Evaluator contract remains on `kt.law_amendment.v2` plus `kt.law_bundle_change_receipt.v1`.",
            "- Recommended resolution class: `BIND_SUPERSESSION_AND_AMENDMENT_MAPPING`.",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    authority_packet_path: Path,
    authority_receipt_path: Path,
    blocker_ledger_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_BRANCH:
        raise RuntimeError(f"FAIL_CLOSED: tranche T01 must run on {REQUIRED_BRANCH}")
    if _git_status_porcelain(root).strip():
        raise RuntimeError("FAIL_CLOSED: tranche T01 requires a clean worktree")

    authority_packet = common.load_json_required(root, authority_packet_path, label="PR15 FL3 remediation authority packet")
    authority_receipt = common.load_json_required(root, authority_receipt_path, label="PR15 FL3 remediation authority receipt")
    blocker_ledger = common.load_json_required(root, blocker_ledger_path, label="PR15 FL3 remediation blocker ledger")
    common.ensure_pass(authority_packet, label="PR15 FL3 remediation authority packet")
    common.ensure_pass(authority_receipt, label="PR15 FL3 remediation authority receipt")
    common.ensure_pass(blocker_ledger, label="PR15 FL3 remediation blocker ledger")

    if str(authority_receipt.get("next_lawful_move", "")).strip() != "AUTHOR_POST_F_PR15_FL3_LAW_BUNDLE_AND_AMENDMENT_MISMATCH_PACKET":
        raise RuntimeError("FAIL_CLOSED: remediation authority lane no longer authorizes tranche T01 packet")

    blockers = blocker_ledger.get("blockers")
    if not isinstance(blockers, list) or not blockers or blockers[0].get("tranche_id") != "T01":
        raise RuntimeError("FAIL_CLOSED: blocker ledger no longer binds tranche T01 as the first remediation blocker")

    bundle = _load_law_bundle(root)
    computed_hash = _compute_bundle_hash(root, bundle)
    pinned_hash = _read_sha_pin(root)
    current_amendments = _scan_amendment_support(root, computed_hash)
    current_receipts = _scan_change_receipt_support(root, computed_hash)
    pinned_amendments = _scan_amendment_support(root, pinned_hash)
    pinned_receipts = _scan_change_receipt_support(root, pinned_hash)
    meta_probe = _probe_fl3_meta_evaluator(root)

    if computed_hash == pinned_hash:
        raise RuntimeError("FAIL_CLOSED: tranche T01 packet is only lawful while the active-tree LAW_BUNDLE hash and pinned hash still diverge")
    if not pinned_amendments or not pinned_receipts:
        raise RuntimeError("FAIL_CLOSED: expected stale pinned support chain is missing; tranche T01 evidence no longer matches the frozen blocker class")

    outputs = build_outputs(
        branch_name=branch_name,
        branch_head=_git_rev_parse(root, "HEAD"),
        authority_packet=authority_packet,
        blocker_ledger=blocker_ledger,
        bundle=bundle,
        computed_hash=computed_hash,
        pinned_hash=pinned_hash,
        current_amendments=current_amendments,
        current_receipts=current_receipts,
        pinned_amendments=pinned_amendments,
        pinned_receipts=pinned_receipts,
        meta_probe=meta_probe,
    )
    common.write_outputs(
        packet_path=(reports_root / OUTPUT_PACKET).resolve(),
        receipt_path=(reports_root / OUTPUT_RECEIPT).resolve(),
        report_path=(reports_root / OUTPUT_REPORT).resolve(),
        packet=outputs["packet"],
        receipt=outputs["receipt"],
        report_text=str(outputs["report"]),
    )
    return {
        "lane_outcome": OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind tranche T01 for PR15 FL3 law-bundle and amendment mismatch.")
    parser.add_argument("--authority-packet", default=AUTHORITY_PACKET_PATH)
    parser.add_argument("--authority-receipt", default=AUTHORITY_RECEIPT_PATH)
    parser.add_argument("--blocker-ledger", default=BLOCKER_LEDGER_PATH)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        authority_packet_path=common.resolve_path(root, args.authority_packet),
        authority_receipt_path=common.resolve_path(root, args.authority_receipt),
        blocker_ledger_path=common.resolve_path(root, args.blocker_ledger),
    )
    print(result["lane_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
