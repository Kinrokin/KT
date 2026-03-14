from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.runtime_boundary_integrity import build_runtime_boundary_report
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
H1_ACTIVATION_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/h1_activation_gate_receipt.json"
NEXT_HORIZON_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/next_horizon_activation_receipt.json"
FRONTIER_SETTLEMENT_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/frontier_settlement_receipt.json"

PUBLISHED_HEAD_PROOF_CLASS = "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
NEXT_HORIZON_H1_SINGLE_ADAPTER = "H1_SINGLE_ADAPTER_TRUTH"

H1_GATE_VERDICT_ALLOWED = "H1_ALLOWED_SINGLE_ADAPTER_ONLY"
H1_GATE_VERDICT_BLOCKED = "H1_BLOCKED"

FRONTIER_VERDICT_ALLOWED = "FRONTIER_SETTLED_H1_SINGLE_ADAPTER_ALLOWED"
FRONTIER_VERDICT_BLOCKED = "FRONTIER_SETTLED_WITH_H1_BLOCK"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {path.as_posix()}")
    return load_json(path)


def _proof_programs(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    bundles = payload.get("bundles") if isinstance(payload.get("bundles"), list) else []
    rows: List[Dict[str, str]] = []
    for row in bundles:
        if not isinstance(row, dict):
            continue
        rows.append(
            {
                "program_id": str(row.get("program_id", "")).strip(),
                "proof_id": str(row.get("proof_id", "")).strip(),
                "validated_head_sha": str(row.get("validated_head_sha", "")).strip(),
            }
        )
    return rows


def _h1_blockers_and_prerequisites(
    *,
    board: Dict[str, Any],
    published_head: Dict[str, Any],
    authority_convergence: Dict[str, Any],
) -> Tuple[List[str], List[str]]:
    blockers: List[str] = []
    prerequisites_missing: List[str] = []
    program_gates = board.get("program_gates") if isinstance(board.get("program_gates"), dict) else {}

    published_proof_class = str(published_head.get("proof_class", "")).strip()
    if published_proof_class != PUBLISHED_HEAD_PROOF_CLASS:
        blockers.append("PUBLISHED_HEAD_SELF_CONVERGENCE_UNRESOLVED")
        prerequisites_missing.append(
            "KT_PROD_CLEANROOM/reports/published_head_self_convergence_receipt.json proof_class=PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
        )

    if not bool(program_gates.get("TRUTH_PUBLICATION_STABILIZED")):
        blockers.append("TRUTH_PUBLICATION_STABILIZED_FALSE")
        prerequisites_missing.append(
            "KT_PROD_CLEANROOM/governance/execution_board.json program_gates.TRUTH_PUBLICATION_STABILIZED=true"
        )

    if not bool(program_gates.get("H1_ACTIVATION_ALLOWED")):
        blockers.append("H1_ACTIVATION_ALLOWED_FALSE")
        prerequisites_missing.append(
            "KT_PROD_CLEANROOM/governance/execution_board.json program_gates.H1_ACTIVATION_ALLOWED=true"
        )

    if str(authority_convergence.get("status", "")).strip() != "PASS":
        blockers.append("AUTHORITY_CONVERGENCE_UNRESOLVED")
        prerequisites_missing.append("KT_PROD_CLEANROOM/reports/authority_convergence_receipt.json status=PASS")

    return blockers, prerequisites_missing


def build_h1_activation_gate_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    board = _load_required(root, "KT_PROD_CLEANROOM/governance/execution_board.json")
    published_head = _load_required(root, f"{report_root_rel}/published_head_self_convergence_receipt.json")
    authority_convergence = _load_required(root, f"{report_root_rel}/authority_convergence_receipt.json")
    representative = _load_required(root, f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json")
    runtime_boundary_report = build_runtime_boundary_report(root=root, report_root_rel=report_root_rel)
    verifier_report = build_public_verifier_report(root=root, report_root_rel=report_root_rel)

    compiled_head_commit = _git_head(root)
    blockers, prerequisites_missing = _h1_blockers_and_prerequisites(
        board=board,
        published_head=published_head,
        authority_convergence=authority_convergence,
    )
    published_proof_class = str(published_head.get("proof_class", "")).strip()
    h1_allowed = not blockers

    return {
        "schema_id": "kt.operator.h1_activation_gate_receipt.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if h1_allowed else "BLOCKED",
        "compiled_head_commit": compiled_head_commit,
        "claim_boundary": (
            "This receipt evaluates H1 admissibility for compiled_head_commit only. "
            "A later repository head that contains this receipt must not be described as the compiled head unless the SHAs match."
        ),
        "h1_gate_verdict": H1_GATE_VERDICT_ALLOWED if h1_allowed else H1_GATE_VERDICT_BLOCKED,
        "validated_head_sha": compiled_head_commit,
        "proof_class": published_proof_class or str(authority_convergence.get("proof_class", "")).strip(),
        "published_head_authority_claimed": published_proof_class == PUBLISHED_HEAD_PROOF_CLASS,
        "h1_allowed": h1_allowed,
        "single_adapter_benchmarking_allowed": h1_allowed,
        "router_and_multi_adapter_blocked": True,
        "next_allowed_transition": (
            NEXT_HORIZON_H1_SINGLE_ADAPTER
            if h1_allowed
            else "PUBLISHED_HEAD_SELF_CONVERGENCE_PROVEN"
        ),
        "prerequisites_missing": prerequisites_missing,
        "blockers": blockers,
        "truth_head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "platform_governance_head_claim_verdict": str(
            verifier_report.get("platform_governance_head_claim_verdict", "")
        ).strip(),
        "runtime_boundary_head_claim_verdict": str(runtime_boundary_report.get("runtime_boundary_head_claim_verdict", "")).strip(),
        "representative_authority_lane_proven": bool(representative.get("representative_authority_lane_proven")),
        "representative_authority_lane_subject_commit": str(representative.get("validated_head_sha", "")).strip(),
        "supporting_evidence_refs": [
            "KT_PROD_CLEANROOM/governance/execution_board.json",
            f"{report_root_rel}/published_head_self_convergence_receipt.json",
            f"{report_root_rel}/authority_convergence_receipt.json",
            f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json",
            f"{report_root_rel}/public_verifier_manifest.json",
            f"{report_root_rel}/runtime_boundary_integrity_receipt.json",
        ],
    }


def build_next_horizon_activation_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    h1_gate = build_h1_activation_gate_receipt(root=root, report_root_rel=report_root_rel)
    return {
        "schema_id": "kt.next_horizon_activation_receipt.v2",
        "created_utc": utc_now_iso_z(),
        "status": "READY" if bool(h1_gate.get("h1_allowed")) else "HOLD",
        "compiled_head_commit": str(h1_gate.get("compiled_head_commit", "")).strip(),
        "claim_boundary": (
            "This receipt evaluates next-horizon activation for compiled_head_commit only. "
            "A later repository head that contains this receipt must not be described as the compiled head unless the SHAs match."
        ),
        "next_horizon": NEXT_HORIZON_H1_SINGLE_ADAPTER,
        "activation_allowed": bool(h1_gate.get("h1_allowed")),
        "single_adapter_only": True,
        "router_and_multi_adapter_blocked": True,
        "prerequisites_missing": list(h1_gate.get("prerequisites_missing", [])),
        "h1_gate_verdict": str(h1_gate.get("h1_gate_verdict", "")).strip(),
        "supporting_evidence_refs": list(h1_gate.get("supporting_evidence_refs", [])),
    }


def build_frontier_settlement_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    verifier_report = build_public_verifier_report(root=root, report_root_rel=report_root_rel)
    runtime_boundary_report = build_runtime_boundary_report(root=root, report_root_rel=report_root_rel)
    h1_gate = build_h1_activation_gate_receipt(root=root, report_root_rel=report_root_rel)
    next_horizon = build_next_horizon_activation_receipt(root=root, report_root_rel=report_root_rel)
    proof_index = _load_required(root, f"{report_root_rel}/proofrunbundle_index.json")
    representative = _load_required(root, f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json")
    commercial_claims = _load_required(root, f"{report_root_rel}/commercial_claim_compiler_receipt.json")
    published_head = _load_required(root, f"{report_root_rel}/published_head_self_convergence_receipt.json")
    authority_convergence = _load_required(root, f"{report_root_rel}/authority_convergence_receipt.json")

    evaluation_failures: List[str] = []
    if str(representative.get("status", "")).strip() != "PASS":
        evaluation_failures.append("representative_authority_lane_reproducibility_not_pass")
    if not bool(representative.get("representative_authority_lane_proven")):
        evaluation_failures.append("representative_authority_lane_not_proven")
    if str(runtime_boundary_report.get("status", "")).strip() != "PASS":
        evaluation_failures.append("runtime_boundary_report_not_pass")
    if str(commercial_claims.get("status", "")).strip() != "PASS":
        evaluation_failures.append("commercial_claim_compiler_not_pass")

    return {
        "schema_id": "kt.operator.frontier_settlement_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not evaluation_failures else "FAIL",
        "compiled_head_commit": str(h1_gate.get("compiled_head_commit", "")).strip(),
        "claim_boundary": (
            "This receipt compiles frontier settlement and H1 gate evaluation for compiled_head_commit only. "
            "A later repository head that contains this receipt must not be described as the compiled head unless the SHAs match."
        ),
        "frontier_settlement_verdict": (
            FRONTIER_VERDICT_ALLOWED if bool(h1_gate.get("h1_allowed")) else FRONTIER_VERDICT_BLOCKED
        ),
        "truth_subject_commit": str(verifier_report.get("truth_subject_commit", "")).strip(),
        "truth_evidence_commit": str(verifier_report.get("evidence_commit", "")).strip(),
        "truth_head_claim_verdict": str(verifier_report.get("head_claim_verdict", "")).strip(),
        "platform_governance_subject_commit": str(verifier_report.get("platform_governance_subject_commit", "")).strip(),
        "platform_governance_head_claim_verdict": str(
            verifier_report.get("platform_governance_head_claim_verdict", "")
        ).strip(),
        "enterprise_legitimacy_ceiling": str(verifier_report.get("enterprise_legitimacy_ceiling", "")).strip(),
        "runtime_boundary_subject_commit": str(runtime_boundary_report.get("runtime_boundary_subject_commit", "")).strip(),
        "runtime_boundary_evidence_commit": str(runtime_boundary_report.get("runtime_boundary_evidence_commit", "")).strip(),
        "runtime_boundary_head_claim_verdict": str(
            runtime_boundary_report.get("runtime_boundary_head_claim_verdict", "")
        ).strip(),
        "runtime_boundary_claim_admissible": bool(runtime_boundary_report.get("runtime_boundary_claim_admissible")),
        "representative_authority_lane_subject_commit": str(representative.get("validated_head_sha", "")).strip(),
        "representative_authority_lane_proven": bool(representative.get("representative_authority_lane_proven")),
        "representative_authority_lane_program_id": str(
            representative.get("representative_authority_lane_program_id", "")
        ).strip(),
        "demonstrated_programs": _proof_programs(proof_index),
        "commercial_claims_status": str(commercial_claims.get("status", "")).strip(),
        "commercial_claim_compiler_compiled_head_commit": str(
            commercial_claims.get("compiled_head_commit", commercial_claims.get("current_head_commit", ""))
        ).strip(),
        "active_truth_source_ref": str(commercial_claims.get("active_truth_source_ref", "")).strip(),
        "documentary_mirror_ref": str(commercial_claims.get("documentary_mirror_ref", "")).strip(),
        "h1_allowed": bool(h1_gate.get("h1_allowed")),
        "h1_gate_verdict": str(h1_gate.get("h1_gate_verdict", "")).strip(),
        "single_adapter_benchmarking_allowed": bool(h1_gate.get("single_adapter_benchmarking_allowed")),
        "router_and_multi_adapter_blocked": bool(h1_gate.get("router_and_multi_adapter_blocked")),
        "next_horizon": str(next_horizon.get("next_horizon", "")).strip(),
        "published_head_self_convergence_status": str(published_head.get("status", "")).strip(),
        "published_head_self_convergence_proof_class": str(published_head.get("proof_class", "")).strip(),
        "authority_convergence_status": str(authority_convergence.get("status", "")).strip(),
        "authority_convergence_proof_class": str(authority_convergence.get("proof_class", "")).strip(),
        "blockers": list(h1_gate.get("blockers", [])),
        "prerequisites_missing": list(next_horizon.get("prerequisites_missing", [])),
        "evaluation_failures": evaluation_failures,
        "supporting_evidence_refs": [
            f"{report_root_rel}/public_verifier_manifest.json",
            f"{report_root_rel}/runtime_boundary_integrity_receipt.json",
            f"{report_root_rel}/commercial_claim_compiler_receipt.json",
            f"{report_root_rel}/representative_authority_lane_reproducibility_receipt.json",
            f"{report_root_rel}/proofrunbundle_index.json",
            f"{report_root_rel}/published_head_self_convergence_receipt.json",
            f"{report_root_rel}/authority_convergence_receipt.json",
            H1_ACTIVATION_RECEIPT_REL,
            NEXT_HORIZON_RECEIPT_REL,
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit final frontier settlement and H1 gate evaluation receipts.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report_root_rel = str(args.report_root)
    report_root = Path(report_root_rel)
    if not report_root.is_absolute():
        report_root = (root / report_root).resolve()

    h1_gate = build_h1_activation_gate_receipt(root=root, report_root_rel=report_root_rel)
    next_horizon = build_next_horizon_activation_receipt(root=root, report_root_rel=report_root_rel)
    frontier = build_frontier_settlement_receipt(root=root, report_root_rel=report_root_rel)

    write_json_stable(report_root / "h1_activation_gate_receipt.json", h1_gate)
    write_json_stable(report_root / "next_horizon_activation_receipt.json", next_horizon)
    write_json_stable(report_root / "frontier_settlement_receipt.json", frontier)
    print(json.dumps(frontier, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if frontier["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
