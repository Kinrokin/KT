from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


SCHEMA_ID = "kt.hold_state_surface_basis_validation_receipt.v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json_dict(path: Path, *, name: str) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: {name} must be a JSON object")
    return payload


def _resolve(root: Path, ref: str) -> Path:
    candidate = Path(ref)
    if candidate.is_absolute():
        return candidate
    return root / ref


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def build_hold_state_surface_basis_validation_receipt(
    *,
    root: Path,
    actual_repo_head: str,
    overlay: Dict[str, Any],
    next_workstream: Dict[str, Any],
    resume_blockers: Dict[str, Any],
    reanchor: Dict[str, Any],
    overlay_ref: str,
    next_workstream_ref: str,
    resume_blockers_ref: str,
    reanchor_ref: str,
) -> Dict[str, Any]:
    basis_heads = {
        "current_campaign_state_overlay": str(overlay.get("repo_state", {}).get("current_git_head", "")).strip(),
        "resume_blockers_receipt": str(resume_blockers.get("current_git_head", "")).strip(),
        "gate_d_decision_reanchor_packet": str(reanchor.get("current_repo_state", {}).get("current_git_head", "")).strip(),
    }
    nonempty_basis_heads = {head for head in basis_heads.values() if head}
    basis_head = next(iter(nonempty_basis_heads), "")

    overlay_scope = str(overlay.get("next_counted_workstream_scope", "")).strip()
    overlay_why = str(overlay.get("executable_now_why", "")).strip()
    overlay_authoritative_basis = " ".join(
        str(item).strip()
        for item in overlay.get("current_lawful_gate_standing", {}).get("authoritative_basis", [])
        if str(item).strip()
    )
    next_objective = str(next_workstream.get("workstream_objective", "")).strip()
    next_domain_surface = str(next_workstream.get("gate_domain_product_split", {}).get("domain_surface", "")).strip()
    resume_why = str(resume_blockers.get("why_not_executable_now", "")).strip()
    reanchor_note = str(reanchor.get("current_bounded_limitations", {}).get("note", "")).strip()
    reanchor_router_status = str(reanchor.get("current_bounded_limitations", {}).get("router_status", "")).strip()
    combined_policy_text = " ".join(
        [
            overlay_scope,
            overlay_why,
            overlay_authoritative_basis,
            next_objective,
            next_domain_surface,
            resume_why,
            reanchor_note,
            reanchor_router_status,
        ]
    )

    checks = [
        {
            "check_id": "tracked_hold_surfaces_share_single_basis_head",
            "pass": len(nonempty_basis_heads) == 1,
        },
        {
            "check_id": "tracked_hold_surfaces_recognize_preseal_basis_split",
            "pass": bool(basis_head) and basis_head != actual_repo_head,
        },
        {
            "check_id": "same_head_reemit_rule_is_explicit",
            "pass": "actual candidate head" in combined_policy_text and "re-em" in combined_policy_text,
        },
        {
            "check_id": "counted_lane_remains_closed",
            "pass": bool(overlay.get("repo_state_executable_now") is False)
            and bool(next_workstream.get("repo_state_executable_now") is False)
            and str(overlay.get("next_counted_workstream_id", "")).strip() == "B04_R6_LEARNED_ROUTER_AUTHORIZATION"
            and str(next_workstream.get("exact_next_counted_workstream_id", "")).strip()
            == "B04_R6_LEARNED_ROUTER_AUTHORIZATION",
        },
        {
            "check_id": "static_baseline_still_canonical_in_hold_state",
            "pass": ("static baseline" in combined_policy_text.lower() and "canonical" in combined_policy_text.lower())
            or reanchor_router_status == "STATIC_CANONICAL_BASELINE_ONLY",
        },
    ]
    status = "PASS" if all(item["pass"] for item in checks) else "FAIL"

    return {
        "schema_id": SCHEMA_ID,
        "generated_utc": _utc_now(),
        "mode": "LAB_ONLY_NONCANONICAL",
        "status": status,
        "head_alignment_posture": (
            "PRE_SEAL_HOLD_STATE_BASIS_CONFIRMED" if status == "PASS" else "HOLD_STATE_BASIS_ALIGNMENT_FAIL_CLOSED"
        ),
        "actual_repo_head": actual_repo_head,
        "tracked_surface_basis_head": basis_head,
        "basis_heads_by_surface": basis_heads,
        "claim_boundary": (
            "This receipt validates only the tracked hold-state basis split for the frozen lab-only reconsideration path. "
            "It does not reopen the counted lane, does not count as R5 evidence, and does not unlock R6."
        ),
        "resolution_rule": (
            "Treat the tracked hold surfaces as pre-seal basis only. Any future router-readiness reconsideration attempt "
            "must re-emit both fresh receipts on the actual candidate head before prepare or consume may proceed: the "
            "same-head single-path guard and the preserved-basis receipt that remains non-authoritative."
        ),
        "checks": checks,
        "source_packet_refs": {
            "current_campaign_state_overlay_ref": overlay_ref,
            "next_counted_workstream_contract_ref": next_workstream_ref,
            "resume_blockers_receipt_ref": resume_blockers_ref,
            "gate_d_decision_reanchor_packet_ref": reanchor_ref,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate that tracked hold surfaces are treated as pre-seal basis only.")
    parser.add_argument(
        "--current-campaign-state-overlay",
        default="reports/current_campaign_state_overlay.json",
    )
    parser.add_argument(
        "--next-counted-workstream-contract",
        default="reports/next_counted_workstream_contract.json",
    )
    parser.add_argument(
        "--resume-blockers-receipt",
        default="reports/resume_blockers_receipt.json",
    )
    parser.add_argument(
        "--gate-d-decision-reanchor-packet",
        default="reports/gate_d_decision_reanchor_packet.json",
    )
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[2]
    overlay_ref = str(args.current_campaign_state_overlay)
    next_ref = str(args.next_counted_workstream_contract)
    resume_ref = str(args.resume_blockers_receipt)
    reanchor_ref = str(args.gate_d_decision_reanchor_packet)
    receipt = build_hold_state_surface_basis_validation_receipt(
        root=root,
        actual_repo_head=_git_head(root),
        overlay=_load_json_dict(_resolve(root, overlay_ref), name="current_campaign_state_overlay"),
        next_workstream=_load_json_dict(_resolve(root, next_ref), name="next_counted_workstream_contract"),
        resume_blockers=_load_json_dict(_resolve(root, resume_ref), name="resume_blockers_receipt"),
        reanchor=_load_json_dict(_resolve(root, reanchor_ref), name="gate_d_decision_reanchor_packet"),
        overlay_ref=overlay_ref,
        next_workstream_ref=next_ref,
        resume_blockers_ref=resume_ref,
        reanchor_ref=reanchor_ref,
    )
    output_path = _resolve(root, str(args.output))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "head_alignment_posture": receipt["head_alignment_posture"]}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
