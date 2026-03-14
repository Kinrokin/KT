from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.runtime_boundary_integrity import build_runtime_boundary_report
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_COMPILER_RECEIPT_REL = f"{DEFAULT_REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json"
DEFAULT_PROGRAM_CATALOG_REL = f"{DEFAULT_REPORT_ROOT_REL}/commercial_program_catalog.json"
DEFAULT_DOCUMENTARY_LABELS_REL = f"{DEFAULT_REPORT_ROOT_REL}/documentary_authority_labels.json"

COMMERCIAL_DOC_PATHS = (
    "KT_PROD_CLEANROOM/docs/commercial/KT_CERTIFICATION_PACK.md",
    "KT_PROD_CLEANROOM/docs/commercial/KT_OPERATOR_FACTORY_SKU_CATALOG.md",
)

COMMON_REQUIRED_MARKERS = (
    "Documentary-only commercial surface.",
    "KT_PROD_CLEANROOM/reports/commercial_claim_compiler_receipt.json",
    "kt_truth_ledger:ledger/current/current_pointer.json",
)

DOC_SPECIFIC_MARKERS = {
    "KT_PROD_CLEANROOM/docs/commercial/KT_CERTIFICATION_PACK.md": (
        "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    ),
    "KT_PROD_CLEANROOM/docs/commercial/KT_OPERATOR_FACTORY_SKU_CATALOG.md": (
        "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
    ),
}


def _report_ref(report_root_rel: str, name: str) -> str:
    return str((Path(report_root_rel) / name).as_posix())


def _program_catalog_payload(*, root: Path, compiler_receipt: Dict[str, Any], report_root_rel: str) -> Dict[str, Any]:
    catalog = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "program_catalog.json")
    programs = catalog.get("programs") if isinstance(catalog.get("programs"), list) else []
    return {
        "schema_id": "kt.commercial_program_catalog.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE" if compiler_receipt["status"] == "PASS" else "HOLD",
        "documentary_only": True,
        "active_truth_source_ref": compiler_receipt["active_truth_source_ref"],
        "documentary_mirror_ref": compiler_receipt["documentary_mirror_ref"],
        "claim_compiler_receipt_ref": _report_ref(report_root_rel, "commercial_claim_compiler_receipt.json"),
        "public_verifier_manifest_ref": _report_ref(report_root_rel, "public_verifier_manifest.json"),
        "runtime_boundary_receipt_ref": _report_ref(report_root_rel, "runtime_boundary_integrity_receipt.json"),
        "truth_head_claim_verdict": compiler_receipt["truth_head_claim_verdict"],
        "platform_governance_head_claim_verdict": compiler_receipt["platform_governance_head_claim_verdict"],
        "runtime_boundary_head_claim_verdict": compiler_receipt["runtime_boundary_head_claim_verdict"],
        "allowed_current_claims": list(compiler_receipt["allowed_current_claims"]),
        "forbidden_current_claims": list(compiler_receipt["forbidden_current_claims"]),
        "program_count": len(programs),
        "programs": [
            {
                "program_id": str(row.get("program_id", "")).strip(),
                "implementation_path": str(row.get("implementation_path", "")).strip(),
                "commercial_surface": "operator" if "operator" in str(row.get("implementation_path", "")) else "delivery_or_ci",
            }
            for row in programs
            if isinstance(row, dict)
        ],
    }


def _documentary_labels_payload(*, report_root_rel: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.documentary_authority_labels.v2",
        "generated_utc": utc_now_iso_z(),
        "status": "ACTIVE",
        "labels": [
            {"glob": "KT_PROD_CLEANROOM/docs/operator/*.md", "label": "DOCUMENTARY_ONLY_UNLESS_CITED_BY_BOARD"},
            {
                "glob": "KT_PROD_CLEANROOM/docs/commercial/*.md",
                "label": "DOCUMENTARY_ONLY_COMMERCIAL_CLAIMS_BIND_TO_CLAIM_COMPILER",
            },
            {"glob": "docs/audit/**", "label": "AUDIT_DOCUMENTARY_ONLY"},
            {"glob": "KT_PROD_CLEANROOM/06_ARCHIVE_VAULT/**", "label": "HISTORICAL_ONLY"},
        ],
        "claim_compiler_receipt_ref": _report_ref(report_root_rel, "commercial_claim_compiler_receipt.json"),
    }


def _document_check(*, root: Path, relpath: str) -> Dict[str, Any]:
    path = root / relpath
    text = path.read_text(encoding="utf-8")
    required_markers = [*COMMON_REQUIRED_MARKERS, *DOC_SPECIFIC_MARKERS.get(relpath, ())]
    missing = [marker for marker in required_markers if marker not in text]
    return {
        "path": relpath,
        "status": "PASS" if not missing else "FAIL",
        "required_markers": required_markers,
        "missing_markers": missing,
    }


def _truth_allowed_claim(report: Dict[str, Any]) -> str:
    verdict = str(report.get("head_claim_verdict", "")).strip()
    current_head = str(report.get("current_head_commit", "")).strip()
    subject = str(report.get("truth_subject_commit", "")).strip()
    if verdict == "HEAD_IS_TRANSPARENCY_VERIFIED_SUBJECT":
        return f"Current HEAD {current_head} is the transparency-verified subject commit."
    if verdict == "HEAD_CONTAINS_TRANSPARENCY_VERIFIED_SUBJECT_EVIDENCE":
        return f"Current HEAD {current_head} contains transparency-verified evidence for subject commit {subject}."
    return "No current-head transparency claim is admissible."


def _governance_allowed_claim(report: Dict[str, Any]) -> str:
    verdict = str(report.get("platform_governance_head_claim_verdict", "")).strip()
    current_head = str(report.get("current_head_commit", "")).strip()
    subject = str(report.get("platform_governance_subject_commit", "")).strip()
    if verdict == "HEAD_HAS_PLATFORM_ENFORCEMENT_PROOF":
        return f"Current HEAD {current_head} has fresh platform-enforcement governance proof."
    if verdict == "HEAD_CONTAINS_PLATFORM_ENFORCEMENT_EVIDENCE_FOR_SUBJECT":
        return f"Current HEAD {current_head} contains platform-enforcement evidence for subject commit {subject}."
    if verdict == "HEAD_HAS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE":
        return f"Current HEAD {current_head} has fresh workflow-governance-only evidence and no platform-enforcement proof."
    if verdict == "HEAD_CONTAINS_WORKFLOW_GOVERNANCE_ONLY_EVIDENCE_FOR_SUBJECT":
        return f"Current HEAD {current_head} contains workflow-governance-only evidence for subject commit {subject}."
    return "No current-head governance claim is admissible."


def _runtime_boundary_allowed_claim(report: Dict[str, Any]) -> str:
    verdict = str(report.get("runtime_boundary_head_claim_verdict", "")).strip()
    current_head = str(report.get("current_head_commit", "")).strip()
    subject = str(report.get("runtime_boundary_subject_commit", "")).strip()
    if verdict == "HEAD_HAS_RUNTIME_BOUNDARY_PROOF":
        return f"Current HEAD {current_head} has fresh canonical runtime-boundary proof."
    if verdict == "HEAD_CONTAINS_RUNTIME_BOUNDARY_EVIDENCE_FOR_SUBJECT":
        return f"Current HEAD {current_head} contains runtime-boundary evidence for subject commit {subject}."
    return "No current-head runtime-boundary claim is admissible."


def build_claim_compiler_receipt(*, root: Path, report_root_rel: str = DEFAULT_REPORT_ROOT_REL) -> Dict[str, Any]:
    verifier_report = build_public_verifier_report(root=root, report_root_rel=report_root_rel)
    runtime_boundary_report = build_runtime_boundary_report(root=root, report_root_rel=report_root_rel)
    settled_truth = load_json(root / Path(_report_ref(report_root_rel, "settled_truth_source_receipt.json")))

    document_checks = [_document_check(root=root, relpath=relpath) for relpath in COMMERCIAL_DOC_PATHS]
    doc_failures = [row["path"] for row in document_checks if row["status"] != "PASS"]

    active_truth_source_ref = str(settled_truth.get("authoritative_current_pointer_ref", "")).strip()
    documentary_mirror_ref = "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json"

    allowed_current_claims = [
        _truth_allowed_claim(verifier_report),
        _governance_allowed_claim(verifier_report),
        _runtime_boundary_allowed_claim(runtime_boundary_report),
        f"Active truth source is {active_truth_source_ref}; {documentary_mirror_ref} is a documentary compatibility mirror only.",
    ]

    forbidden_current_claims = [
        "Do not claim current HEAD itself is the transparency-verified subject when head_equals_subject is false.",
        "Do not claim platform-enforced governance on main while branch_protection_status is not PASS.",
        "Do not claim current HEAD itself has fresh runtime-boundary proof when runtime_boundary_head_equals_subject is false.",
        f"Do not claim {documentary_mirror_ref} is the active truth source.",
        "Do not claim src/tools is canonical runtime.",
        "Do not claim H1 is allowed.",
    ]

    missing_inputs = []
    if not active_truth_source_ref:
        missing_inputs.append("authoritative_current_pointer_ref")
    if str(verifier_report.get("current_head_commit", "")).strip() == "":
        missing_inputs.append("current_head_commit")
    if str(runtime_boundary_report.get("runtime_boundary_subject_commit", "")).strip() == "":
        missing_inputs.append("runtime_boundary_subject_commit")

    status = "PASS" if not doc_failures and not missing_inputs else "FAIL"

    return {
        "schema_id": "kt.operator.commercial_claim_compiler_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "current_head_commit": verifier_report["current_head_commit"],
        "active_truth_source_ref": active_truth_source_ref,
        "documentary_mirror_ref": documentary_mirror_ref,
        "truth_subject_commit": verifier_report["truth_subject_commit"],
        "truth_evidence_commit": verifier_report["evidence_commit"],
        "truth_head_claim_verdict": verifier_report["head_claim_verdict"],
        "truth_head_claim_boundary": verifier_report["head_claim_boundary"],
        "platform_governance_subject_commit": verifier_report["platform_governance_subject_commit"],
        "platform_governance_head_claim_verdict": verifier_report["platform_governance_head_claim_verdict"],
        "platform_governance_head_claim_boundary": verifier_report["platform_governance_head_claim_boundary"],
        "runtime_boundary_subject_commit": runtime_boundary_report["runtime_boundary_subject_commit"],
        "runtime_boundary_evidence_commit": runtime_boundary_report["runtime_boundary_evidence_commit"],
        "runtime_boundary_head_claim_verdict": runtime_boundary_report["runtime_boundary_head_claim_verdict"],
        "runtime_boundary_head_claim_boundary": runtime_boundary_report["runtime_boundary_head_claim_boundary"],
        "commercial_doc_checks": document_checks,
        "allowed_current_claims": allowed_current_claims,
        "forbidden_current_claims": forbidden_current_claims,
        "input_refs": [
            _report_ref(report_root_rel, "public_verifier_manifest.json"),
            _report_ref(report_root_rel, "runtime_boundary_integrity_receipt.json"),
            _report_ref(report_root_rel, "settled_truth_source_receipt.json"),
        ],
        "missing_inputs": missing_inputs,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile commercial claim boundaries from verifier, runtime-boundary, and settled-truth receipts.")
    parser.add_argument("--report-root", default=DEFAULT_REPORT_ROOT_REL)
    parser.add_argument("--output", default="")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    report_root_rel = str(args.report_root)
    compiler_receipt = build_claim_compiler_receipt(root=root, report_root_rel=report_root_rel)
    report_root = Path(report_root_rel)
    if not report_root.is_absolute():
        report_root = (root / report_root).resolve()

    write_json_stable(report_root / "commercial_claim_compiler_receipt.json", compiler_receipt)
    write_json_stable(report_root / "documentary_authority_labels.json", _documentary_labels_payload(report_root_rel=report_root_rel))
    write_json_stable(
        report_root / "commercial_program_catalog.json",
        _program_catalog_payload(root=root, compiler_receipt=compiler_receipt, report_root_rel=report_root_rel),
    )
    print(json.dumps(compiler_receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if compiler_receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
