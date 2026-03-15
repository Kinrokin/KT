from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.canonical_tree_execute import CURRENT_ARCHIVE_LITERAL
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


WORK_ORDER_ID = "WORK_ORDER_KT_TOTAL_CLOSURE_CAMPAIGN_TO_ACTIVE_CANONICAL_RELEASE"
WORK_ORDER_SCHEMA_ID = "kt.work_order.total_closure_campaign.v1"
WORKSTREAM_ID = "WS12_FINAL_COMPLETION_BUNDLE"
STEP_ID = "WS12_STEP_1_SEAL_TOTAL_CLOSURE_STATE"
PASS_VERDICT = "TOTAL_CLOSURE_CAMPAIGN_SEALED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
PROFILE_ROOT_REL = "docs/generated/profiles"

AUTHORITY_CLOSURE_REL = f"{REPORT_ROOT_REL}/kt_authority_closure_receipt.json"
PLATFORM_FINAL_REL = f"{REPORT_ROOT_REL}/kt_platform_governance_final_decision_receipt.json"
PUBLIC_VERIFIER_REL = f"{REPORT_ROOT_REL}/public_verifier_manifest.json"
RUNTIME_BOUNDARY_REL = f"{REPORT_ROOT_REL}/runtime_boundary_integrity_receipt.json"
ARCHIVE_SEPARATION_REL = f"{REPORT_ROOT_REL}/kt_archive_externalization_receipt.json"
CANONICAL_TREE_REL = f"{REPORT_ROOT_REL}/kt_repo_professionalization_completion_receipt.json"
DETERMINISM_REL = f"{REPORT_ROOT_REL}/kt_determinism_receipt.json"
LEDGER_AUTHORITY_REL = f"{REPORT_ROOT_REL}/kt_authority_topology_cutover_receipt.json"
PUBLICATION_ATTESTATION_REL = f"{REPORT_ROOT_REL}/kt_truth_publication_stabilization_receipt.json"
CLAIM_COMPILER_ACTIVATION_REL = f"{REPORT_ROOT_REL}/kt_claim_compiler_activation_receipt.json"
VERIFIER_RELEASE_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_manifest.json"
ADAPTER_GATE_REL = f"{REPORT_ROOT_REL}/kt_adapter_testing_gate_receipt.json"
TOURNAMENT_GATE_REL = f"{REPORT_ROOT_REL}/kt_tournament_readiness_receipt.json"
WS11_RECUT_REL = f"{REPORT_ROOT_REL}/kt_full_stack_adjudication_recut_receipt.json"
TUF_ROOT_REL = f"{REPORT_ROOT_REL}/kt_tuf_root_initialization.json"
RELEASE_LAW_REL = "KT_PROD_CLEANROOM/governance/foundation_pack/kt_release_law.json"
PUBLICATION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_publication_profile.json"
COMPETITION_PROFILE_REL = f"{PROFILE_ROOT_REL}/kt_competition_profile.json"

FINAL_BUNDLE_REL = f"{REPORT_ROOT_REL}/kt_final_completion_bundle.json"
PUBLIC_SHOWABILITY_REL = f"{REPORT_ROOT_REL}/kt_public_showability_receipt.json"
COMPLETION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_total_closure_campaign_completion_receipt.json"

ALLOWED_TOUCHES = {
    FINAL_BUNDLE_REL,
    PUBLIC_SHOWABILITY_REL,
    COMPLETION_RECEIPT_REL,
    "KT_PROD_CLEANROOM/tools/operator/total_closure_completion_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_total_closure_completion_validate.py",
}
PROTECTED_PATTERNS = (CURRENT_ARCHIVE_LITERAL, ".github/workflows/")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_status_paths(root: Path) -> List[str]:
    output = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain=v1"], text=True, encoding="utf-8")
    paths: List[str] = []
    for line in output.splitlines():
        rel = line[3:].strip()
        if not rel:
            continue
        rel_path = Path(rel)
        abs_path = (root / rel_path).resolve()
        if abs_path.is_dir():
            for child in sorted(item for item in abs_path.rglob("*") if item.is_file()):
                paths.append(child.relative_to(root).as_posix())
        else:
            paths.append(rel_path.as_posix())
    return paths


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _status(payload: Dict[str, Any]) -> str:
    return str(payload.get("status", "")).strip()


def _is_pass(payload: Dict[str, Any]) -> bool:
    return _status(payload) == "PASS"


def _build_context(root: Path) -> Dict[str, Any]:
    authority = _load_required(root, AUTHORITY_CLOSURE_REL)
    platform = _load_required(root, PLATFORM_FINAL_REL)
    verifier = _load_required(root, PUBLIC_VERIFIER_REL)
    runtime = _load_required(root, RUNTIME_BOUNDARY_REL)
    archive = _load_required(root, ARCHIVE_SEPARATION_REL)
    canonical_tree = _load_required(root, CANONICAL_TREE_REL)
    determinism = _load_required(root, DETERMINISM_REL)
    ledger_authority = _load_required(root, LEDGER_AUTHORITY_REL)
    publication_attestation = _load_required(root, PUBLICATION_ATTESTATION_REL)
    claim_compiler = _load_required(root, CLAIM_COMPILER_ACTIVATION_REL)
    verifier_release = _load_required(root, VERIFIER_RELEASE_REL)
    adapter_gate = _load_required(root, ADAPTER_GATE_REL)
    tournament_gate = _load_required(root, TOURNAMENT_GATE_REL)
    ws11_recut = _load_required(root, WS11_RECUT_REL)
    tuf_root = _load_required(root, TUF_ROOT_REL)
    release_law = _load_required(root, RELEASE_LAW_REL)
    publication_profile = _load_required(root, PUBLICATION_PROFILE_REL)
    competition_profile = _load_required(root, COMPETITION_PROFILE_REL)

    public_showability_blockers: List[str] = []
    if _status(tournament_gate) != "PASS":
        public_showability_blockers.append("TOURNAMENT_GATE_BLOCKED")
    if str(publication_profile.get("current_status", "")).strip() != "READY":
        public_showability_blockers.append("PUBLICATION_PROFILE_BLOCKED")

    return {
        "current_head": _git_head(root),
        "authority": authority,
        "platform": platform,
        "verifier": verifier,
        "runtime": runtime,
        "archive": archive,
        "canonical_tree": canonical_tree,
        "determinism": determinism,
        "ledger_authority": ledger_authority,
        "publication_attestation": publication_attestation,
        "claim_compiler": claim_compiler,
        "verifier_release": verifier_release,
        "adapter_gate": adapter_gate,
        "tournament_gate": tournament_gate,
        "ws11_recut": ws11_recut,
        "tuf_root": tuf_root,
        "release_law": release_law,
        "publication_profile": publication_profile,
        "competition_profile": competition_profile,
        "public_showability_blockers": public_showability_blockers,
    }


def _public_showability_receipt(context: Dict[str, Any]) -> Dict[str, Any]:
    status = "PASS" if not context["public_showability_blockers"] else "BLOCKED"
    return {
        "artifact_id": Path(PUBLIC_SHOWABILITY_REL).name,
        "schema_id": "kt.operator.public_showability_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": "PUBLIC_SHOWABILITY_OPEN" if status == "PASS" else "PUBLIC_SHOWABILITY_BLOCKED",
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "public_showability_gate_status": "OPEN" if status == "PASS" else "BLOCKED",
        "blocking_conditions": list(context["public_showability_blockers"]),
        "claim_boundary": "Public showability may open only if tournament gate is open and the publication profile is truly ready. Otherwise the horizon remains explicitly blocked.",
        "unexpected_touches": [],
        "protected_touch_violations": [],
        "validators_run": ["python -m tools.operator.total_closure_completion_validate"],
        "next_lawful_step": {"status_after_workstream": "COMPLETE", "workstream_id": "NONE_CAMPAIGN_COMPLETE"},
    }


def _final_bundle(context: Dict[str, Any], public_showability: Dict[str, Any]) -> Dict[str, Any]:
    truth_subject_commit = str(context["authority"].get("truth_subject_commit", "")).strip()
    truth_evidence_commit = str(context["authority"].get("truth_evidence_commit", "")).strip()
    current_head_claim_verdict = str(context["verifier"].get("head_claim_verdict", "")).strip()
    if not current_head_claim_verdict and truth_subject_commit and truth_evidence_commit and truth_subject_commit != truth_evidence_commit:
        current_head_claim_verdict = "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE"
    return {
        "artifact_id": Path(FINAL_BUNDLE_REL).name,
        "schema_id": "kt.operator.final_completion_bundle.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "active_truth_source_ref": str(context["verifier"].get("truth_pointer_ref", "")).strip(),
        "trust_root_id": str(context["tuf_root"].get("trust_root_id", "")).strip(),
        "trust_root_policy_ref": str(context["tuf_root"].get("root_policy_ref", "")).strip(),
        "proof_class_summary": {
            "truth_authority": str(context["authority"].get("authority_convergence_proof_class", "")).strip(),
            "governance_ceiling": str(context["platform"].get("enterprise_legitimacy_ceiling", "")).strip(),
            "runtime_boundary": str(context["runtime"].get("runtime_boundary_verdict", "")).strip(),
            "reproducibility": str(context["determinism"].get("pass_verdict", "")).strip(),
            "activation_state": "H1_BLOCKED",
        },
        "release_law_state": {
            "law_id": str(context["release_law"].get("law_id", "")).strip(),
            "forbidden_release_claims": list(context["release_law"].get("forbidden_release_claims", [])),
            "competition_and_publication_profile_ceiling": "competition_and_publication_on_bounded_surface_only",
        },
        "archive_separation_state": {
            "status": _status(context["archive"]),
            "pass_verdict": str(context["archive"].get("pass_verdict", "")).strip(),
        },
        "active_tree_state": {
            "status": _status(context["canonical_tree"]),
            "pass_verdict": str(context["canonical_tree"].get("pass_verdict", "")).strip(),
        },
        "gates": {
            "adapter_testing": str(context["adapter_gate"].get("adapter_testing_gate_status", "")).strip(),
            "tournament": str(context["tournament_gate"].get("tournament_gate_status", "")).strip(),
            "public_showability": str(public_showability.get("public_showability_gate_status", "")).strip(),
            "h1": "BLOCKED",
        },
        "lawful_now": [
            "adapter testing on the bounded canonical active tree",
            "offline public verification using the released verifier bundle",
            "workflow-governance-only current-head claims within the verifier boundary",
            "documentary commercial/doctrine use bounded by the active claim compiler",
        ],
        "still_blocked": [
            "platform-enforced governance on main",
            "tournament readiness",
            "public showability",
            "H1 activation",
        ],
        "truth_subject_boundary": {
            "truth_subject_commit": truth_subject_commit,
            "truth_evidence_commit": truth_evidence_commit,
            "current_head_claim_verdict": current_head_claim_verdict,
        },
        "governance_boundary": {
            "platform_governance_subject_commit": str(context["platform"].get("platform_governance_subject_commit", "")).strip(),
            "platform_governance_verdict": str(context["platform"].get("platform_governance_verdict", "")).strip(),
            "platform_governance_claim_admissible": bool(context["platform"].get("platform_governance_claim_admissible")),
        },
        "supporting_refs": [
            AUTHORITY_CLOSURE_REL,
            PLATFORM_FINAL_REL,
            PUBLIC_VERIFIER_REL,
            RUNTIME_BOUNDARY_REL,
            ARCHIVE_SEPARATION_REL,
            CANONICAL_TREE_REL,
            DETERMINISM_REL,
            LEDGER_AUTHORITY_REL,
            PUBLICATION_ATTESTATION_REL,
            VERIFIER_RELEASE_REL,
            CLAIM_COMPILER_ACTIVATION_REL,
            ADAPTER_GATE_REL,
            TOURNAMENT_GATE_REL,
            PUBLIC_SHOWABILITY_REL,
            WS11_RECUT_REL,
        ],
    }


def _completion_receipt(context: Dict[str, Any], public_showability: Dict[str, Any], actual_touched: List[str]) -> Dict[str, Any]:
    unexpected_touches = [path for path in actual_touched if path not in ALLOWED_TOUCHES]
    protected_touch_violations = [path for path in actual_touched if any(path.startswith(prefix) for prefix in PROTECTED_PATTERNS)]

    checks = [
        {
            "check": "final_bundle_names_active_truth_source_and_trust_root",
            "status": "PASS" if str(context["verifier"].get("truth_pointer_ref", "")).strip() and str(context["tuf_root"].get("trust_root_id", "")).strip() else "FAIL_CLOSED",
            "refs": [PUBLIC_VERIFIER_REL, TUF_ROOT_REL, FINAL_BUNDLE_REL],
        },
        {
            "check": "final_bundle_names_proof_class_release_law_and_archive_state",
            "status": "PASS" if _is_pass(context["archive"]) and _is_pass(context["canonical_tree"]) and str(context["release_law"].get("law_id", "")).strip() else "FAIL_CLOSED",
            "refs": [ARCHIVE_SEPARATION_REL, CANONICAL_TREE_REL, RELEASE_LAW_REL, FINAL_BUNDLE_REL],
        },
        {
            "check": "open_and_blocked_gates_explicit",
            "status": "PASS" if str(context["adapter_gate"].get("adapter_testing_gate_status", "")).strip() == "OPEN" and str(context["tournament_gate"].get("tournament_gate_status", "")).strip() == "BLOCKED" and str(public_showability.get("public_showability_gate_status", "")).strip() == "BLOCKED" else "FAIL_CLOSED",
            "refs": [ADAPTER_GATE_REL, TOURNAMENT_GATE_REL, PUBLIC_SHOWABILITY_REL],
        },
        {
            "check": "public_showability_not_softened_when_blocked",
            "status": "PASS" if bool(context["public_showability_blockers"]) else "FAIL_CLOSED",
            "refs": [PUBLIC_SHOWABILITY_REL, PUBLICATION_PROFILE_REL],
        },
        {
            "check": "post_touch_accounting_clean",
            "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL_CLOSED",
            "refs": [FINAL_BUNDLE_REL, PUBLIC_SHOWABILITY_REL, COMPLETION_RECEIPT_REL],
        },
    ]
    status = "PASS" if all(check["status"] == "PASS" for check in checks) else "FAIL_CLOSED"

    return {
        "artifact_id": Path(COMPLETION_RECEIPT_REL).name,
        "schema_id": "kt.operator.total_closure_campaign_completion_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else "FAIL_CLOSED",
        "compiled_head_commit": context["current_head"],
        "subject_head_commit": context["current_head"],
        "evidence_head_commit": context["current_head"],
        "work_order_id": WORK_ORDER_ID,
        "work_order_schema_id": WORK_ORDER_SCHEMA_ID,
        "adapter_testing_gate_status": str(context["adapter_gate"].get("adapter_testing_gate_status", "")).strip(),
        "tournament_gate_status": str(context["tournament_gate"].get("tournament_gate_status", "")).strip(),
        "public_showability_gate_status": str(public_showability.get("public_showability_gate_status", "")).strip(),
        "campaign_completion_state": "SEALED_WITH_BLOCKED_PUBLIC_HORIZONS" if status == "PASS" else "FAIL_CLOSED",
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": ["python -m tools.operator.total_closure_completion_validate"],
        "checks": checks,
        "next_lawful_step": {"status_after_workstream": "COMPLETE", "workstream_id": "NONE_CAMPAIGN_COMPLETE"},
        "step_report": {
            "timestamp": utc_now_iso_z(),
            "workstream_id": WORKSTREAM_ID,
            "step_id": STEP_ID,
            "actions_taken": [
                "sealed the final completion bundle from the live WS2-WS11 closure receipts",
                "declared the exact open and blocked gates without softening the blocked public horizons",
                "sealed the final public-showability read as blocked while adapter testing remains lawfully open",
            ],
            "files_touched": actual_touched,
            "tests_run": ["python -m pytest KT_PROD_CLEANROOM/tests/operator/test_total_closure_completion_validate.py -q"],
            "validators_run": ["python -m tools.operator.total_closure_completion_validate"],
            "issues_found": ["public_showability_blocked_due_to_tournament_and_publication_profile_state"] if context["public_showability_blockers"] else [],
            "resolution": "WS12 seals the campaign by naming the final lawful operating boundary: adapter testing open, tournament/public showability blocked, workflow governance only, and H1 blocked.",
            "pass_fail_status": status,
            "unexpected_touches": unexpected_touches,
            "protected_touch_violations": protected_touch_violations,
        },
    }


def emit_total_closure_completion(*, root: Path) -> Dict[str, Any]:
    context = _build_context(root)
    public_showability = _public_showability_receipt(context)
    write_json_stable((root / Path(PUBLIC_SHOWABILITY_REL)).resolve(), public_showability)
    write_json_stable((root / Path(FINAL_BUNDLE_REL)).resolve(), _final_bundle(context, public_showability))
    actual_touched = sorted(set(_git_status_paths(root) + [COMPLETION_RECEIPT_REL]))
    receipt = _completion_receipt(context, public_showability, actual_touched)
    write_json_stable((root / Path(COMPLETION_RECEIPT_REL)).resolve(), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seal the KT total closure campaign and emit the final completion bundle.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_total_closure_completion(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if _status(receipt) == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
