from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.operator import cohort0_gate_f_common as common
from tools.operator import cohort0_post_f_track_01_final_summary_packet_tranche as track01_final
from tools.operator.titanium_common import repo_root, utc_now_iso_z


OUTPUT_PACKET = "cohort0_post_f_track_02_dual_audit_scope_packet.json"
OUTPUT_RECEIPT = "cohort0_post_f_track_02_dual_audit_scope_receipt.json"
OUTPUT_REPORT = "COHORT0_POST_F_TRACK_02_DUAL_AUDIT_SCOPE_REPORT.md"

EXECUTION_STATUS = "PASS__POST_F_TRACK_02_DUAL_AUDIT_SCOPE_BOUND"
SCOPE_OUTCOME = "POST_F_TRACK_02_DUAL_AUDIT_SCOPE_DEFINED__SEPARATE_BASELINE_AND_CURRENT_TRUTH_VERDICTS"
TRACK_ID = "POST_F_TRACK_02_DUAL_AUDIT"
NEXT_MOVE = "EXECUTE_POST_F_TRACK_02_SHARED_EVIDENCE_HARVEST_AND_AUTHORITY_PARTITION"

REQUIRED_WORK_ORDER_ID = "cohort0_post_f_track_02_dual_audit_work_order"
REQUIRED_SCHEMA_VERSION = "1.1.0"
REQUIRED_BASELINE_PROMPT_ID = "KT_SUPER_HARSH_ADVERSARIAL_AUDIT_V3_1_SCOPE_NORMALIZED"
REQUIRED_CURRENT_PROMPT_ID = "KT_MAX_POWER_ADVERSARIAL_AUDIT_PLUS_ELEVATION_BRIEF__POST_F_HARDENED"
REQUIRED_CANONICAL_BRANCH = "main"
REQUIRED_WORKING_BRANCH = "expansion/post-f-track-01"
REQUIRED_BASELINE_TAG = "kt-post-f-reaudit-pass"


def _require_pass(payload: Dict[str, Any], *, label: str) -> None:
    if str(payload.get("status", "")).strip() != "PASS":
        raise RuntimeError(f"FAIL_CLOSED: {label} must have status PASS")


def _current_branch_name(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return "UNKNOWN_BRANCH"
    branch = result.stdout.strip()
    return branch or "UNKNOWN_BRANCH"


def _git_status_porcelain(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception as exc:
        raise RuntimeError(f"FAIL_CLOSED: unable to read git status: {exc}") from exc
    return result.stdout


def _git_tag_exists(root: Path, ref_name: str) -> bool:
    try:
        result = subprocess.run(
            ["git", "tag", "--list", ref_name],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
    except Exception:
        return False
    return any(line.strip() == ref_name for line in result.stdout.splitlines())


def _sha256_hex(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_file(path: Path, *, label: str) -> None:
    if not path.is_file():
        raise RuntimeError(f"FAIL_CLOSED: missing required {label}: {path.as_posix()}")


def _load_work_order(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("FAIL_CLOSED: Track 02 work order must be a JSON object")
    return payload


def build_outputs(
    *,
    root: Path,
    branch_name: str,
    subject_head: str,
    track01_packet: Dict[str, Any],
    work_order_path: Path,
    work_order: Dict[str, Any],
    baseline_prompt_path: Path,
    baseline_prompt_sha: str,
    current_prompt_path: Path,
    current_prompt_sha: str,
) -> Dict[str, Dict[str, Any] | str]:
    authority_header = dict(track01_packet.get("authority_header", {}))
    prompt_artifacts = dict(work_order.get("prompt_artifacts", {}))
    baseline_prompt_cfg = dict(prompt_artifacts.get("baseline_frozen", {}))
    current_prompt_cfg = dict(prompt_artifacts.get("current_truth_hardened", {}))
    repo_cfg = dict(work_order.get("repo", {}))
    anchors = dict(work_order.get("anchors", {}))
    shared_evidence_harvest = dict(work_order.get("shared_evidence_harvest", {}))
    authority_partition = dict(work_order.get("authority_partition", {}))
    audit_runs = list(work_order.get("audit_runs", []))
    delta_crosswalk = dict(work_order.get("delta_crosswalk", {}))
    meta_summary = dict(work_order.get("meta_summary", {}))

    packet = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_scope_packet.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "claim_boundary": (
            "This packet binds only the Track 02 dual-audit scope. It freezes one unchanged baseline audit, one hardened current-truth audit, "
            "and one delta crosswalk from a shared evidence harvest, while preserving separate verdicts."
        ),
        "track_identity": {
            "track_id": TRACK_ID,
            "track_name": "Post-F Dual Audit",
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
        },
        "authority_header": {
            "canonical_authority_branch": REQUIRED_CANONICAL_BRANCH,
            "working_branch": branch_name,
            "working_branch_non_authoritative_until_protected_merge": True,
            "gate_d_cleared_on_successor_line": bool(authority_header.get("gate_d_cleared_on_successor_line", False)),
            "gate_e_open_on_successor_line": bool(authority_header.get("gate_e_open_on_successor_line", False)),
            "gate_f_narrow_wedge_confirmed": bool(authority_header.get("gate_f_narrow_wedge_confirmed", False)),
            "gate_f_open": bool(authority_header.get("gate_f_open", False)),
            "post_f_reaudit_passed": bool(authority_header.get("post_f_reaudit_passed", False)),
            "track_01_closed_as_bounded_proof_packet": str(track01_packet.get("summary_outcome", "")).strip() == track01_final.SUMMARY_OUTCOME,
        },
        "work_order_binding": {
            "work_order_id": str(work_order.get("work_order_id", "")).strip(),
            "schema_version": str(work_order.get("schema_version", "")).strip(),
            "objective": str(work_order.get("objective", "")).strip(),
            "work_order_path": work_order_path.resolve().as_posix(),
            "work_order_sha256": _sha256_hex(work_order_path),
            "constitutional_order_ref": dict(work_order.get("constitutional_order_ref", {})),
            "repo_requirements": {
                "canonical_authority_branch": str(repo_cfg.get("canonical_authority_branch", "")).strip(),
                "working_branch": str(repo_cfg.get("working_branch", "")).strip(),
                "require_clean_worktree": bool(repo_cfg.get("require_clean_worktree", False)),
                "fail_closed_on_dirty_state": bool(repo_cfg.get("fail_closed_on_dirty_state", False)),
            },
        },
        "prompt_artifact_binding": {
            "storage_model": str(prompt_artifacts.get("storage_model", "")).strip(),
            "baseline_frozen": {
                "prompt_id": str(baseline_prompt_cfg.get("prompt_id", "")).strip(),
                "source_path": baseline_prompt_path.resolve().as_posix(),
                "sha256": baseline_prompt_sha,
                "expected_sha256": str(baseline_prompt_cfg.get("sha256", "")).strip().lower(),
                "unchanged_required": bool(baseline_prompt_cfg.get("unchanged_required", False)),
            },
            "current_truth_hardened": {
                "prompt_id": str(current_prompt_cfg.get("prompt_id", "")).strip(),
                "source_path": current_prompt_path.resolve().as_posix(),
                "sha256": current_prompt_sha,
                "expected_sha256": str(current_prompt_cfg.get("sha256", "")).strip().lower(),
                "authorized_mutation_allowed": bool(current_prompt_cfg.get("authorized_mutation_allowed", False)),
                "current_truth_overrides_are_inside_prompt_artifact": bool(current_prompt_cfg.get("current_truth_overrides_are_inside_prompt_artifact", False)),
            },
        },
        "anchor_binding": {
            "frozen_baseline": dict(anchors.get("frozen_baseline", {})),
            "current_truth": dict(anchors.get("current_truth", {})),
            "supporting_release_tags": list(anchors.get("supporting_release_tags", [])),
        },
        "execution_plan": {
            "shared_evidence_harvest": {
                "mode": str(shared_evidence_harvest.get("mode", "")).strip(),
                "one_harvest_two_views": bool(shared_evidence_harvest.get("one_harvest_two_views", False)),
                "source_count": len(shared_evidence_harvest.get("sources", [])) if isinstance(shared_evidence_harvest.get("sources", []), list) else 0,
                "secret_policy": dict(shared_evidence_harvest.get("secret_policy", {})),
            },
            "authority_partition": {
                "precedence_order": list(authority_partition.get("precedence_order", [])),
                "stale_if": list(authority_partition.get("stale_if", [])),
                "view_rules": dict(authority_partition.get("view_rules", {})),
            },
            "audit_runs": [
                {
                    "run_id": str(run.get("run_id", "")).strip(),
                    "prompt_ref": str(run.get("prompt_ref", "")).strip(),
                    "anchor_ref": str(run.get("anchor_ref", "")).strip(),
                    "evidence_view_mode": str(run.get("evidence_view_mode", "")).strip(),
                    "output_paths": dict(run.get("outputs", {})),
                }
                for run in audit_runs
                if isinstance(run, dict)
            ],
            "delta_crosswalk_enabled": bool(delta_crosswalk.get("enabled", False)),
            "meta_summary_enabled": bool(meta_summary.get("enabled", False)),
        },
        "separation_contract": {
            "baseline_and_current_truth_verdicts_must_remain_separate": True,
            "baseline_prompt_must_remain_unchanged": True,
            "historical_receipts_may_inform_lineage_not_override_live_header": True,
            "track_01_bounded_proof_may_inform_benchmark_readiness_not_full_system_superiority": True,
        },
        "source_refs": common.output_ref_dict(
            track01_final_summary_packet=common.resolve_path(root, f"{common.REPORTS_ROOT_REL}/{track01_final.OUTPUT_PACKET}"),
            baseline_prompt=baseline_prompt_path,
            current_truth_prompt=current_prompt_path,
            dual_audit_work_order=work_order_path,
        ),
        "subject_head": subject_head,
        "next_lawful_move": NEXT_MOVE,
    }
    receipt = {
        "schema_id": "kt.operator.cohort0_post_f_track_02_dual_audit_scope_receipt.v1",
        "status": "PASS",
        "generated_utc": utc_now_iso_z(),
        "execution_status": EXECUTION_STATUS,
        "scope_outcome": SCOPE_OUTCOME,
        "track_id": TRACK_ID,
        "subject_head": subject_head,
        "working_branch": branch_name,
        "working_branch_non_authoritative_until_protected_merge": True,
        "baseline_prompt_hash_verified": True,
        "current_truth_prompt_hash_verified": True,
        "audit_run_count": len(packet["execution_plan"]["audit_runs"]),
        "next_lawful_move": NEXT_MOVE,
    }
    report = common.report_lines(
        "Cohort0 Post-F Track 02 Dual Audit Scope Report",
        [
            f"- Execution status: `{EXECUTION_STATUS}`",
            f"- Scope outcome: `{SCOPE_OUTCOME}`",
            f"- Working branch: `{branch_name}`",
            f"- Baseline prompt hash verified: `{True}`",
            f"- Current-truth prompt hash verified: `{True}`",
            f"- Audit runs bound: `{len(packet['execution_plan']['audit_runs'])}`",
            f"- Next lawful move: `{NEXT_MOVE}`",
        ],
    )
    return {"packet": packet, "receipt": receipt, "report": report}


def run(
    *,
    reports_root: Path,
    track01_final_summary_packet_path: Path,
    work_order_path: Path,
    baseline_prompt_path: Path,
    current_truth_prompt_path: Path,
) -> Dict[str, Any]:
    root = repo_root()
    track01_packet = common.load_json_required(root, track01_final_summary_packet_path, label="Track 01 final summary packet")
    _require_pass(track01_packet, label="Track 01 final summary packet")
    if str(track01_packet.get("summary_outcome", "")).strip() != track01_final.SUMMARY_OUTCOME:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires the closed Track 01 proof packet")

    _require_file(work_order_path, label="Track 02 dual audit work order")
    _require_file(baseline_prompt_path, label="Track 02 frozen baseline prompt")
    _require_file(current_truth_prompt_path, label="Track 02 current-truth hardened prompt")
    work_order = _load_work_order(work_order_path)

    if str(work_order.get("work_order_id", "")).strip() != REQUIRED_WORK_ORDER_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected Track 02 work order id")
    if str(work_order.get("schema_version", "")).strip() != REQUIRED_SCHEMA_VERSION:
        raise RuntimeError("FAIL_CLOSED: unexpected Track 02 work order schema version")

    repo_cfg = dict(work_order.get("repo", {}))
    if str(repo_cfg.get("canonical_authority_branch", "")).strip() != REQUIRED_CANONICAL_BRANCH:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires main as canonical authority branch")
    if str(repo_cfg.get("working_branch", "")).strip() != REQUIRED_WORKING_BRANCH:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires expansion/post-f-track-01 as working branch")
    if bool(repo_cfg.get("require_clean_worktree", False)):
        if _git_status_porcelain(root).strip():
            raise RuntimeError("FAIL_CLOSED: Track 02 scope requires a clean worktree")

    branch_name = _current_branch_name(root)
    if branch_name != REQUIRED_WORKING_BRANCH:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope must be bound on expansion/post-f-track-01")

    anchors = dict(work_order.get("anchors", {}))
    frozen_baseline = dict(anchors.get("frozen_baseline", {}))
    current_truth = dict(anchors.get("current_truth", {}))
    baseline_tag = str(frozen_baseline.get("ref_name", "")).strip()
    current_branch_ref = str(current_truth.get("ref_name", "")).strip()
    if baseline_tag != REQUIRED_BASELINE_TAG:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires kt-post-f-reaudit-pass as frozen baseline tag")
    if current_branch_ref != REQUIRED_WORKING_BRANCH:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires expansion/post-f-track-01 as current-truth anchor")
    if not _git_tag_exists(root, baseline_tag):
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires the frozen baseline tag to exist locally")
    for tag in list(anchors.get("supporting_release_tags", [])):
        if str(tag).strip() and not _git_tag_exists(root, str(tag).strip()):
            raise RuntimeError(f"FAIL_CLOSED: missing supporting release tag {tag}")

    prompt_artifacts = dict(work_order.get("prompt_artifacts", {}))
    baseline_cfg = dict(prompt_artifacts.get("baseline_frozen", {}))
    current_cfg = dict(prompt_artifacts.get("current_truth_hardened", {}))
    if str(baseline_cfg.get("prompt_id", "")).strip() != REQUIRED_BASELINE_PROMPT_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected baseline prompt id")
    if str(current_cfg.get("prompt_id", "")).strip() != REQUIRED_CURRENT_PROMPT_ID:
        raise RuntimeError("FAIL_CLOSED: unexpected current-truth prompt id")

    baseline_sha = _sha256_hex(baseline_prompt_path).lower()
    current_sha = _sha256_hex(current_truth_prompt_path).lower()
    if baseline_sha != str(baseline_cfg.get("sha256", "")).strip().lower():
        raise RuntimeError("FAIL_CLOSED: baseline prompt hash mismatch")
    if current_sha != str(current_cfg.get("sha256", "")).strip().lower():
        raise RuntimeError("FAIL_CLOSED: current-truth prompt hash mismatch")

    audit_runs = work_order.get("audit_runs", [])
    if not isinstance(audit_runs, list) or len(audit_runs) != 2:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires exactly two audit runs before the crosswalk layer")

    subject_head = str(track01_packet.get("subject_head", "")).strip()
    if not subject_head:
        raise RuntimeError("FAIL_CLOSED: Track 02 scope requires a subject head")

    outputs = build_outputs(
        root=root,
        branch_name=branch_name,
        subject_head=subject_head,
        track01_packet=track01_packet,
        work_order_path=work_order_path,
        work_order=work_order,
        baseline_prompt_path=baseline_prompt_path,
        baseline_prompt_sha=baseline_sha,
        current_prompt_path=current_truth_prompt_path,
        current_prompt_sha=current_sha,
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
        "scope_outcome": SCOPE_OUTCOME,
        "receipt_path": (reports_root / OUTPUT_RECEIPT).resolve().as_posix(),
        "next_lawful_move": NEXT_MOVE,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = common.main_parser("Bind the Track 02 dual audit scope packet.")
    parser.add_argument(
        "--track01-final-summary-packet",
        default=f"{common.REPORTS_ROOT_REL}/{track01_final.OUTPUT_PACKET}",
    )
    parser.add_argument("--work-order", required=True)
    parser.add_argument("--baseline-prompt", required=True)
    parser.add_argument("--current-truth-prompt", required=True)
    args = parser.parse_args(argv)
    root = repo_root()
    reports_root = common.resolve_path(root, args.reports_root)
    result = run(
        reports_root=reports_root,
        track01_final_summary_packet_path=common.resolve_path(root, args.track01_final_summary_packet),
        work_order_path=common.resolve_path(root, args.work_order),
        baseline_prompt_path=common.resolve_path(root, args.baseline_prompt),
        current_truth_prompt_path=common.resolve_path(root, args.current_truth_prompt),
    )
    print(result["scope_outcome"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
