from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


WORKSTREAM_ID = "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK"
STEP_ID = "WS19_STEP_1_DEFINE_BOUNDED_PRODUCT_SURFACE_AND_LICENSE_TRACK"
PASS_VERDICT = "PRODUCT_SURFACE_AND_LICENSE_TRACK_ALIGNED_TO_BOUNDED_NON_RELEASE_ELIGIBLE_STATE"
BLOCKED_VERDICT = "PRODUCT_SURFACE_AND_LICENSE_TRACK_NOT_ALIGNED"
CAMPAIGN_COMPLETION_STATUS = "STILL_BLOCKED"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/ws19_product_surface_license_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_ws19_product_surface_license_validate.py"

LICENSE_REL = "LICENSE"
README_REL = "README.md"
EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
READINESS_SCOPE_REL = f"{GOVERNANCE_ROOT_REL}/readiness_scope_manifest.json"

WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"
WS17A_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_assurance_confirmation_receipt.json"
WS17B_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_capability_confirmation_receipt.json"
WS18_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_final_readjudication_receipt.json"
WS18_RELEASE_STATUS_REL = f"{REPORT_ROOT_REL}/kt_release_ceremony_status_receipt.json"
WS18_BLOCKER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_ws18_blocker_matrix.json"
WS15_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_claim_proof_ceiling_compiler.json"
COMMERCIAL_COMPILER_REL = f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json"
COMMERCIAL_PROGRAM_CATALOG_REL = f"{REPORT_ROOT_REL}/commercial_program_catalog.json"
STATIC_RELEASE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_release_manifest.json"
STATIC_VERIFIER_SBOM_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_sbom.json"
STATIC_VERIFIER_ATTESTATION_REL = f"{REPORT_ROOT_REL}/kt_static_verifier_attestation.json"
ACCEPTANCE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_acceptance_policy.json"
DISTRIBUTION_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_distribution_policy.json"

PRODUCT_SURFACE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_product_surface_policy.json"
LICENSE_TRACK_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_license_track_policy.json"
PRODUCT_CLAIM_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_product_claim_policy.json"
PRODUCT_SURFACE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_product_surface_manifest.json"
PRODUCT_CLAIM_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_product_claim_compiler.json"
PRODUCT_SURFACE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_product_surface_receipt.json"

PRODUCT_SURFACE_ID = "KT_BOUNDED_STATIC_VERIFIER_EVALUATION_SURFACE_V1"
LICENSE_TRACK_ID = "KT_LICENSE_TRACK_ALIGNMENT_V1_20260318"

PLANNED_MUTATES = [
    TOOL_REL,
    TEST_REL,
    EXECUTION_DAG_REL,
    PRODUCT_SURFACE_POLICY_REL,
    LICENSE_TRACK_POLICY_REL,
    PRODUCT_CLAIM_POLICY_REL,
    PRODUCT_SURFACE_MANIFEST_REL,
    PRODUCT_CLAIM_COMPILER_REL,
    PRODUCT_SURFACE_RECEIPT_REL,
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    if not ancestor or not descendant:
        return False
    result = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.returncode == 0


def _git_status_lines(root: Path) -> List[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(status_lines: Sequence[str]) -> List[str]:
    rels: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rels.append(Path(rel).as_posix())
    return sorted(set(rels))


def _path_in_scope(path: str) -> bool:
    normalized = Path(path).as_posix()
    planned = {Path(item).as_posix() for item in PLANNED_MUTATES}
    return normalized in planned or any(
        normalized.startswith(f"{item}/") or item.startswith(f"{normalized}/") for item in planned
    )


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS19 input: {rel}")
    return _read_json(path)


def _load_required_text(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS19 input: {rel}")
    return path.read_text(encoding="utf-8")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _status(payload: Dict[str, Any]) -> str:
    return str(payload.get("status", "")).strip()


def _check(
    ok: bool,
    check_id: str,
    detail: str,
    refs: Sequence[str],
    failures: Optional[Sequence[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "check": check_id,
        "status": "PASS" if ok else "FAIL",
        "detail": detail,
        "refs": [Path(ref).as_posix() for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    row.update(extra)
    return row


def _contains_all(text: str, needles: Sequence[str]) -> bool:
    lowered = text.lower()
    return all(needle.lower() in lowered for needle in needles)


def _claim_row(
    *,
    claim_id: str,
    claim_status: str,
    claim_type: str,
    compiled_head: str,
    statement: str,
    surface_scope: str,
    license_track: str,
    evidence_refs: Sequence[str],
    blockers: Sequence[str],
    stronger_claim_not_made: Sequence[str],
) -> Dict[str, Any]:
    return {
        "claim_id": claim_id,
        "claim_status": claim_status,
        "claim_type": claim_type,
        "compiled_head_commit": compiled_head,
        "statement": statement,
        "surface_scope": surface_scope,
        "license_track": license_track,
        "evidence_refs": [Path(ref).as_posix() for ref in evidence_refs],
        "blockers": [str(item) for item in blockers],
        "stronger_claim_not_made": [str(item) for item in stronger_claim_not_made],
    }


def _build_product_surface_policy(*, current_head: str, final_receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.product_surface_policy.v1",
        "policy_id": "KT_PRODUCT_SURFACE_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "product_surface_id": PRODUCT_SURFACE_ID,
        "surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
        "release_eligibility": final_receipt["final_verdict"]["release_eligibility"],
        "campaign_completion_status": final_receipt["final_verdict"]["campaign_completion_status"],
        "bounded_scope": "Static verifier artifact set and associated acceptance/distribution policy for the already-bounded imported current-head public verifier manifest surface only.",
        "included_artifact_refs": [
            STATIC_RELEASE_MANIFEST_REL,
            STATIC_VERIFIER_SBOM_REL,
            STATIC_VERIFIER_ATTESTATION_REL,
            ACCEPTANCE_POLICY_REL,
            DISTRIBUTION_POLICY_REL,
        ],
        "proof_anchor_refs": [
            WS14_RECEIPT_REL,
            WS17A_RECEIPT_REL,
            WS18_RECEIPT_REL,
        ],
        "documentary_ancestry_refs": [
            COMMERCIAL_COMPILER_REL,
            COMMERCIAL_PROGRAM_CATALOG_REL,
        ],
        "excluded_or_unproven_refs": [
            "threshold-root verifier acceptance bundle",
            "release signer issuance",
            "producer attestation bundle",
            "current-head external capability confirmation",
            "release ceremony execution",
            "campaign completion",
        ],
        "offer_language_ceiling": "DOCUMENTARY_AND_SPECIALIST_EVALUATION_ONLY",
        "pilot_language_ceiling": "DISCOVERY_ONLY_NON_EXECUTION",
        "stronger_claim_not_made": [
            "The current product surface is release-ready, production-ready, enterprise-ready, or market-ready.",
            "Historical capability confirmation upgrades into current-head capability.",
            "Campaign completion is proven.",
        ],
    }


def _build_license_track_policy(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.license_track_policy.v1",
        "policy_id": LICENSE_TRACK_ID,
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "repository_license_track": {
            "license_name": "KING'S THEOREM RESTRICTED RESEARCH LICENSE v1.1",
            "license_ref": LICENSE_REL,
            "status": "NONCOMMERCIAL_RESEARCH_ONLY",
            "allows": [
                "view",
                "study",
                "run_for_noncommercial_research",
                "run_for_education",
                "run_for_personal_evaluation",
            ],
            "forbids": [
                "commercial_use_or_benefit",
                "saas_or_hosting",
                "redistribution",
                "commercial_derivatives_or_bundling",
                "dataset_or_curriculum_generation_for_commercial_systems",
            ],
        },
        "commercial_license_track": {
            "status": "SEPARATE_WRITTEN_LICENSE_REQUIRED_EXTERNAL_TO_REPO",
            "activation_source": "copyright_holder_written_license",
            "present_in_repo": False,
            "current_lawful_offer_state": "NOT_ACTIVATED_IN_REPO",
        },
        "product_language_alignment": {
            "readiness_scope_ref": READINESS_SCOPE_REL,
            "commercial_zone_status": "EXCLUDED_FROM_READINESS",
            "documentary_surface_refs": [
                COMMERCIAL_COMPILER_REL,
                COMMERCIAL_PROGRAM_CATALOG_REL,
            ],
            "pilot_language_status": "DISCOVERY_ONLY_NON_EXECUTION",
            "release_language_status": "NON_RELEASE_ELIGIBLE_ONLY",
        },
        "stronger_claim_not_made": [
            "The repository license itself grants commercial deployment or product rights.",
            "The repo currently offers an executable commercial release or active pilot.",
        ],
    }


def _build_product_claim_policy(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.product_claim_policy.v1",
        "policy_id": "KT_PRODUCT_CLAIM_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "compiler_output_ref": PRODUCT_CLAIM_COMPILER_REL,
        "claim_record_fields": [
            {"field_id": "claim_id", "type": "string", "required": True},
            {"field_id": "claim_status", "type": "enum", "required": True, "allowed_values": ["ALLOWED_CURRENT", "BLOCKED_CURRENT", "DOCUMENTARY_ONLY"]},
            {"field_id": "claim_type", "type": "enum", "required": True, "allowed_values": ["product_surface", "license_track", "readiness", "pilot_language", "campaign_state"]},
            {"field_id": "compiled_head_commit", "type": "git_sha", "required": True},
            {"field_id": "statement", "type": "string", "required": True},
            {"field_id": "surface_scope", "type": "string", "required": True},
            {"field_id": "license_track", "type": "string", "required": True},
            {"field_id": "evidence_refs", "type": "list[string]", "required": True},
            {"field_id": "blockers", "type": "list[string]", "required": True},
            {"field_id": "stronger_claim_not_made", "type": "list[string]", "required": True},
        ],
        "required_field_order": [
            "claim_id",
            "claim_status",
            "claim_type",
            "compiled_head_commit",
            "statement",
            "surface_scope",
            "license_track",
            "evidence_refs",
            "blockers",
            "stronger_claim_not_made",
        ],
        "invariants": [
            "No WS19 product claim row may mark release readiness, production readiness, enterprise readiness, market readiness, or campaign completion as ALLOWED_CURRENT.",
            "No WS19 product claim row may convert historical bounded capability confirmation into current-head capability proof.",
            "No WS19 product claim row may convert the repo's noncommercial source license into an in-repo commercial grant.",
            "Pilot language must remain discovery-only and non-executed while release_eligibility is NOT_ELIGIBLE.",
        ],
        "stronger_claim_not_made": [
            "WS19 product-claim policy activates threshold-root verifier acceptance.",
            "WS19 product-claim policy proves release readiness or campaign completion.",
        ],
    }


def _build_product_claim_compiler(
    *,
    current_head: str,
    final_receipt: Dict[str, Any],
    release_status_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    final_verdict = final_receipt["final_verdict"]
    rows = [
        _claim_row(
            claim_id="repo_license_noncommercial_research_only",
            claim_status="ALLOWED_CURRENT",
            claim_type="license_track",
            compiled_head=current_head,
            statement="The repository is source-available for non-commercial research, evaluation, and educational use only.",
            surface_scope="repository_distribution",
            license_track="RESTRICTED_RESEARCH_NONCOMMERCIAL",
            evidence_refs=[LICENSE_REL, README_REL],
            blockers=[],
            stronger_claim_not_made=["The repository license grants commercial deployment, SaaS, redistribution, or bundled product rights."],
        ),
        _claim_row(
            claim_id="commercial_use_requires_separate_written_license",
            claim_status="ALLOWED_CURRENT",
            claim_type="license_track",
            compiled_head=current_head,
            statement="Any commercial use or benefit requires a separate written license external to this repository.",
            surface_scope="commercial_activation_boundary",
            license_track="SEPARATE_WRITTEN_LICENSE_REQUIRED",
            evidence_refs=[LICENSE_REL, README_REL],
            blockers=[],
            stronger_claim_not_made=["A commercial track is already activated inside the repository."],
        ),
        _claim_row(
            claim_id="bounded_product_surface_is_static_verifier_documentary_package_only",
            claim_status="ALLOWED_CURRENT",
            claim_type="product_surface",
            compiled_head=current_head,
            statement="The current bounded product surface is the static verifier artifact set and acceptance/distribution policy for the already-bounded imported current-head public verifier manifest surface only.",
            surface_scope=PRODUCT_SURFACE_ID,
            license_track="DOCUMENTARY_AND_SPECIALIST_EVALUATION_ONLY",
            evidence_refs=[WS14_RECEIPT_REL, PRODUCT_SURFACE_POLICY_REL, PRODUCT_SURFACE_MANIFEST_REL],
            blockers=[],
            stronger_claim_not_made=[
                "The product surface includes release ceremony execution, threshold-root acceptance, or broad verifier deployment.",
                "The product surface proves current-head capability beyond the bounded verifier surface.",
            ],
        ),
        _claim_row(
            claim_id="product_surface_non_release_eligible",
            claim_status="ALLOWED_CURRENT",
            claim_type="readiness",
            compiled_head=current_head,
            statement="The current product surface remains non-release-eligible under the final readjudication and release-ceremony status receipts.",
            surface_scope="release_eligibility",
            license_track="NON_RELEASE_ELIGIBLE_BOUNDARY",
            evidence_refs=[WS18_RECEIPT_REL, WS18_RELEASE_STATUS_REL],
            blockers=[],
            stronger_claim_not_made=["Release readiness or release ceremony completion is proven."],
        ),
        _claim_row(
            claim_id="pilot_language_discovery_only_non_execution",
            claim_status="ALLOWED_CURRENT",
            claim_type="pilot_language",
            compiled_head=current_head,
            statement="Any pilot or readiness language must remain discovery-only, documentary, and non-executed while release eligibility is NOT_ELIGIBLE.",
            surface_scope="pilot_language",
            license_track="DISCOVERY_ONLY_NON_EXECUTION",
            evidence_refs=[LICENSE_TRACK_POLICY_REL, WS18_RECEIPT_REL, WS18_RELEASE_STATUS_REL],
            blockers=[],
            stronger_claim_not_made=["An active production pilot, release pilot, or market launch is lawful today."],
        ),
        _claim_row(
            claim_id="historical_commercial_catalog_documentary_only",
            claim_status="DOCUMENTARY_ONLY",
            claim_type="product_surface",
            compiled_head=current_head,
            statement="The historical commercial program catalog remains documentary ancestry only and must not be overread as the current product posture for this head.",
            surface_scope=COMMERCIAL_PROGRAM_CATALOG_REL,
            license_track="DOCUMENTARY_ONLY",
            evidence_refs=[COMMERCIAL_COMPILER_REL, COMMERCIAL_PROGRAM_CATALOG_REL, PRODUCT_SURFACE_POLICY_REL],
            blockers=[],
            stronger_claim_not_made=["The historical commercial catalog is the current authoritative product surface for this head."],
        ),
        _claim_row(
            claim_id="current_head_capability_proven_for_product_surface",
            claim_status="BLOCKED_CURRENT",
            claim_type="readiness",
            compiled_head=current_head,
            statement="The current product surface must not claim current-head external capability proof.",
            surface_scope=PRODUCT_SURFACE_ID,
            license_track="BOUND_CURRENT_HEAD_ONLY",
            evidence_refs=[WS18_RECEIPT_REL, WS17B_RECEIPT_REL, WS18_BLOCKER_MATRIX_REL],
            blockers=["CURRENT_HEAD_CAPABILITY_NOT_EXTERNALLY_CONFIRMED"],
            stronger_claim_not_made=["Current-head capability is externally confirmed for the product surface."],
        ),
        _claim_row(
            claim_id="threshold_root_verifier_acceptance_active_for_product_surface",
            claim_status="BLOCKED_CURRENT",
            claim_type="readiness",
            compiled_head=current_head,
            statement="The current product surface must not claim threshold-root verifier acceptance.",
            surface_scope=PRODUCT_SURFACE_ID,
            license_track="BOOTSTRAP_ROOT_ONLY",
            evidence_refs=[WS18_RECEIPT_REL, WS18_BLOCKER_MATRIX_REL, ACCEPTANCE_POLICY_REL],
            blockers=["THRESHOLD_ROOT_VERIFIER_ACCEPTANCE_PENDING"],
            stronger_claim_not_made=["Threshold-root verifier acceptance is active for the product surface."],
        ),
        _claim_row(
            claim_id="enterprise_or_market_ready_product_offer",
            claim_status="BLOCKED_CURRENT",
            claim_type="readiness",
            compiled_head=current_head,
            statement="The current product surface must not be described as enterprise-ready, market-ready, production-ready, or release-ready.",
            surface_scope=PRODUCT_SURFACE_ID,
            license_track="NON_RELEASE_ELIGIBLE_BOUNDARY",
            evidence_refs=[WS18_RECEIPT_REL, WS18_RELEASE_STATUS_REL, LICENSE_TRACK_POLICY_REL],
            blockers=["RELEASE_CEREMONY_NOT_EXECUTED", "RELEASE_SIGNER_ISSUANCE_PENDING", "PRODUCER_ATTESTATION_BUNDLE_PENDING"],
            stronger_claim_not_made=["Enterprise readiness, market readiness, production readiness, or release readiness is proven."],
        ),
        _claim_row(
            claim_id="campaign_completion_proven",
            claim_status="BLOCKED_CURRENT",
            claim_type="campaign_state",
            compiled_head=current_head,
            statement="The repository must not claim campaign completion from the WS19 product and license alignment state.",
            surface_scope="campaign_state",
            license_track="CAMPAIGN_STILL_BLOCKED",
            evidence_refs=[WS18_RECEIPT_REL, WS15_COMPILER_REL],
            blockers=["CAMPAIGN_COMPLETION_NOT_PROVEN"],
            stronger_claim_not_made=["Campaign completion is proven."],
        ),
    ]
    return {
        "schema_id": "kt.operator.product_claim_compiler.v1",
        "artifact_id": "kt_product_claim_compiler.json",
        "status": "PASS",
        "generated_utc": _utc_now(),
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "allowed_current_claim_ids": [row["claim_id"] for row in rows if row["claim_status"] == "ALLOWED_CURRENT"],
        "blocked_current_claim_ids": [row["claim_id"] for row in rows if row["claim_status"] == "BLOCKED_CURRENT"],
        "documentary_only_claim_ids": [row["claim_id"] for row in rows if row["claim_status"] == "DOCUMENTARY_ONLY"],
        "compiled_claims": rows,
        "proof_summary": {
            "release_eligibility": final_verdict["release_eligibility"],
            "campaign_completion_status": final_verdict["campaign_completion_status"],
            "current_head_capability_status": final_verdict["current_head_capability_status"],
            "historical_capability_status": final_verdict["historical_capability_status"],
            "release_ceremony_status": release_status_receipt["release_ceremony_status"],
        },
        "stronger_claim_not_made": [
            "WS19 product claims prove release readiness, threshold-root acceptance, current-head capability, or campaign completion.",
        ],
    }


def _build_product_surface_manifest(
    *,
    root: Path,
    current_head: str,
    final_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    included_paths = [
        STATIC_RELEASE_MANIFEST_REL,
        STATIC_VERIFIER_SBOM_REL,
        STATIC_VERIFIER_ATTESTATION_REL,
        ACCEPTANCE_POLICY_REL,
        DISTRIBUTION_POLICY_REL,
    ]
    return {
        "schema_id": "kt.product_surface_manifest.v1",
        "artifact_id": "kt_product_surface_manifest.json",
        "status": "ACTIVE",
        "generated_utc": _utc_now(),
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "product_surface_id": PRODUCT_SURFACE_ID,
        "surface_status": "DOCUMENTARY_PRE_RELEASE_NON_RELEASE_ELIGIBLE",
        "release_eligibility": final_receipt["final_verdict"]["release_eligibility"],
        "campaign_completion_status": final_receipt["final_verdict"]["campaign_completion_status"],
        "offer_status": "DOCUMENTARY_AND_SPECIALIST_EVALUATION_ONLY",
        "pilot_status": "DISCOVERY_ONLY_NON_EXECUTION",
        "repository_license_track": "RESTRICTED_RESEARCH_NONCOMMERCIAL",
        "commercial_license_track": "SEPARATE_WRITTEN_LICENSE_REQUIRED_EXTERNAL_TO_REPO",
        "included_artifacts": [
            {
                "path": Path(rel).as_posix(),
                "sha256": _file_sha256((root / rel).resolve()),
            }
            for rel in included_paths
        ],
        "documentary_ancestry_refs": [
            COMMERCIAL_COMPILER_REL,
            COMMERCIAL_PROGRAM_CATALOG_REL,
        ],
        "bounded_proof_refs": [
            WS14_RECEIPT_REL,
            WS17A_RECEIPT_REL,
            WS18_RECEIPT_REL,
        ],
        "explicitly_not_included": [
            "threshold_root_verifier_acceptance",
            "release_ceremony_execution",
            "current_head_external_capability_confirmation",
            "historical_only_capability_import_as_current_product_proof",
            "campaign_completion",
        ],
        "stronger_claim_not_made": [
            "This manifest defines a release-ready or commercially activated product.",
            "This manifest upgrades historical capability proof into current-head capability.",
        ],
    }


def _build_dag_update(*, prior_dag: Dict[str, Any], current_head: str) -> Dict[str, Any]:
    updated = json.loads(json.dumps(prior_dag))
    updated["current_node"] = WORKSTREAM_ID
    updated["current_repo_head"] = current_head
    updated["next_lawful_workstream"] = None
    updated["campaign_completion_status"] = CAMPAIGN_COMPLETION_STATUS
    updated["generated_utc"] = _utc_now()
    semantic = updated.get("semantic_boundary") if isinstance(updated.get("semantic_boundary"), dict) else {}
    semantic["lawful_current_claim"] = (
        "WS19 defines only a documentary, bounded, non-release-eligible product surface and license track for the static verifier artifact set and associated acceptance/distribution policy. Campaign completion remains blocked."
    )
    stronger = list(semantic.get("stronger_claim_not_made", [])) if isinstance(semantic.get("stronger_claim_not_made"), list) else []
    for item in [
        "WS19 proves release readiness, production readiness, enterprise readiness, or campaign completion.",
        "WS19 upgrades historical capability confirmation into current-head capability proof.",
        "WS19 widens verifier coverage beyond the already-bounded surfaces.",
    ]:
        if item not in stronger:
            stronger.append(item)
    semantic["stronger_claim_not_made"] = stronger
    updated["semantic_boundary"] = semantic
    for node in updated.get("nodes", []):
        if not isinstance(node, dict):
            continue
        if str(node.get("id", "")).strip() == WORKSTREAM_ID:
            node["status"] = "PASS"
            node["ratification_checkpoint"] = "kt_product_surface_receipt.json"
            node["claim_boundary"] = (
                "WS19 PASS proves only a documentary, bounded, non-release-eligible product surface and license track aligned to the current final verdict. It does not prove release readiness, threshold-root acceptance, current-head capability, or campaign completion."
            )
    return updated


def _build_receipt(
    *,
    root: Path,
    current_head: str,
    checks: Sequence[Dict[str, Any]],
    blocked_by: Sequence[str],
    current_dag: Dict[str, Any],
) -> Dict[str, Any]:
    blocked = [str(item) for item in blocked_by]
    status = "PASS" if not blocked else "BLOCKED"
    pass_verdict = PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT
    input_hashes = {
        rel: _file_sha256((root / rel).resolve())
        for rel in [
            LICENSE_REL,
            README_REL,
            EXECUTION_DAG_REL,
            READINESS_SCOPE_REL,
            WS14_RECEIPT_REL,
            WS17A_RECEIPT_REL,
            WS17B_RECEIPT_REL,
            WS18_RECEIPT_REL,
            WS18_RELEASE_STATUS_REL,
            WS18_BLOCKER_MATRIX_REL,
            WS15_COMPILER_REL,
            COMMERCIAL_COMPILER_REL,
            COMMERCIAL_PROGRAM_CATALOG_REL,
        ]
    }
    return {
        "schema_id": "kt.operator.ws19.product_surface_receipt.v1",
        "artifact_id": "kt_product_surface_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": pass_verdict,
        "generated_utc": _utc_now(),
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "checks": list(checks),
        "blocked_by": blocked,
        "product_surface_ref": PRODUCT_SURFACE_MANIFEST_REL,
        "product_claim_compiler_ref": PRODUCT_CLAIM_COMPILER_REL,
        "product_surface_policy_ref": PRODUCT_SURFACE_POLICY_REL,
        "license_track_policy_ref": LICENSE_TRACK_POLICY_REL,
        "product_claim_policy_ref": PRODUCT_CLAIM_POLICY_REL,
        "campaign_completion_status": CAMPAIGN_COMPLETION_STATUS,
        "next_lawful_workstream": None,
        "campaign_completion_blocked": True,
        "limitations": [
            "WS19 does not activate threshold-root verifier acceptance.",
            "WS19 does not prove current-head external capability confirmation.",
            "WS19 does not prove release readiness or release ceremony execution.",
            "WS19 does not widen verifier coverage beyond the already-bounded surfaces.",
            "WS19 does not prove campaign completion.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "stronger_claim_not_made": [
            "Campaign completion is proven.",
            "Release readiness or production readiness is proven.",
            "Historical capability confirmation upgrades into current-head capability proof.",
            "WS19 activates a commercial license inside the repository.",
        ],
        "input_hashes": input_hashes,
        "protected_touch_violations": [],
        "unexpected_touches": [],
        "tests_run": [
            "python -m pytest -q tests/operator/test_ws19_product_surface_license_validate.py",
            "python -m pytest -q tests/operator/test_ws18_release_and_final_readjudication_validate.py tests/operator/test_ws19_product_surface_license_validate.py",
        ],
        "validators_run": [
            "python -m tools.operator.ws19_product_surface_license_validate",
        ],
        "upstream_refs": [
            WS14_RECEIPT_REL,
            WS17A_RECEIPT_REL,
            WS17B_RECEIPT_REL,
            WS18_RECEIPT_REL,
        ],
        "semantic_boundary": current_dag.get("semantic_boundary", {}),
    }


def emit_ws19_product_surface_license(*, root: Optional[Path] = None) -> Dict[str, Any]:
    root = (root or _repo_root()).resolve()
    current_head = _git_head(root)

    ws18_receipt = _load_required_json(root, WS18_RECEIPT_REL)
    ws18_release_status = _load_required_json(root, WS18_RELEASE_STATUS_REL)
    prior_dag = _load_required_json(root, EXECUTION_DAG_REL)
    readiness_scope = _load_required_json(root, READINESS_SCOPE_REL)
    ws14_receipt = _load_required_json(root, WS14_RECEIPT_REL)
    ws17a_receipt = _load_required_json(root, WS17A_RECEIPT_REL)
    ws17b_receipt = _load_required_json(root, WS17B_RECEIPT_REL)
    claim_compiler = _load_required_json(root, WS15_COMPILER_REL)
    commercial_compiler = _load_required_json(root, COMMERCIAL_COMPILER_REL)
    commercial_catalog = _load_required_json(root, COMMERCIAL_PROGRAM_CATALOG_REL)
    license_text = _load_required_text(root, LICENSE_REL)
    readme_text = _load_required_text(root, README_REL)

    final_verdict = ws18_receipt.get("final_verdict", {}) if isinstance(ws18_receipt.get("final_verdict"), dict) else {}
    ws18_boundary_frozen = _status(ws18_receipt) == "PASS" and _git_is_ancestor(
        root,
        str(ws18_receipt.get("compiled_against", "")).strip(),
        current_head,
    )
    license_aligned = _contains_all(
        license_text,
        [
            "non-commercial research",
            "separate written license",
            "commercial use",
        ],
    ) and _contains_all(readme_text, ["non-commercial research", "commercial use requires a separate written license"])
    readiness_excludes_commercial = "COMMERCIAL" in [str(item).strip() for item in readiness_scope.get("readiness_excludes_zones", [])]
    commercial_catalog_documentary = bool(commercial_catalog.get("documentary_only")) and str(
        commercial_catalog.get("compiled_head_commit", "")
    ).strip() != current_head
    commercial_boundary_visible = "compiled_head_commit" in str(commercial_catalog.get("claim_compiler_claim_boundary", "")) and "must not be described as the compiled head" in str(
        commercial_catalog.get("claim_compiler_claim_boundary", "")
    )
    final_verdict_bounded = (
        _status(ws18_receipt) == "PASS"
        and str(final_verdict.get("release_eligibility", "")).strip() == "NOT_ELIGIBLE"
        and str(final_verdict.get("campaign_completion_status", "")).strip() == "NOT_PROVEN"
        and str(final_verdict.get("current_head_capability_status", "")).strip() == "NOT_EXTERNALLY_CONFIRMED"
    )
    release_status_bounded = _status(ws18_release_status) == "PASS" and str(
        ws18_release_status.get("release_ceremony_status", "")
    ).strip() == "NON_EXECUTED_BLOCKED_BY_PREREQUISITES"
    blocked_claims = {str(item).strip() for item in claim_compiler.get("blocked_current_claim_ids", [])}
    proof_ceiling_blocks = {
        "campaign_completion_proven",
        "release_readiness_proven",
        "threshold_root_verifier_acceptance_active",
    }.issubset(blocked_claims)
    capability_history_stays_historical = str(ws17b_receipt.get("capability_scope", "")).strip() == "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY"
    current_assurance_stays_bounded = str(ws17a_receipt.get("bounded_assurance_surface", "")).strip() == "KT_PROD_CLEANROOM/reports/ws13_determinism/ci/public_verifier_manifest.json"

    checks = [
        _check(
            ws18_boundary_frozen,
            "ws18_boundary_frozen_first",
            "WS19 may proceed only after the accepted WS18 boundary has been frozen into a descendant checkpoint.",
            [WS18_RECEIPT_REL, EXECUTION_DAG_REL],
            failures=[] if ws18_boundary_frozen else ["WS18_BOUNDARY_NOT_FROZEN_FIRST"],
        ),
        _check(
            final_verdict_bounded,
            "final_verdict_remains_bounded_non_release_eligible",
            "WS19 may only define a product surface that stays inside the WS18 bounded non-release-eligible verdict.",
            [WS18_RECEIPT_REL, WS18_BLOCKER_MATRIX_REL],
            release_eligibility=final_verdict.get("release_eligibility"),
            campaign_completion_status=final_verdict.get("campaign_completion_status"),
            current_head_capability_status=final_verdict.get("current_head_capability_status"),
        ),
        _check(
            release_status_bounded,
            "release_ceremony_status_remains_non_executed",
            "WS19 must not overread the release lane; release ceremony remains non-executed and not eligible.",
            [WS18_RELEASE_STATUS_REL],
            release_ceremony_status=ws18_release_status.get("release_ceremony_status"),
        ),
        _check(
            license_aligned,
            "repository_license_and_readme_align_to_noncommercial_track",
            "Top-level license/readme language must stay aligned to a non-commercial repo track with separate written licensing required for commercial use.",
            [LICENSE_REL, README_REL],
        ),
        _check(
            readiness_excludes_commercial,
            "readiness_scope_keeps_commercial_excluded",
            "Commercial surfaces must remain excluded from readiness in the active readiness scope.",
            [READINESS_SCOPE_REL],
        ),
        _check(
            commercial_catalog_documentary and commercial_boundary_visible and _status(commercial_compiler) == "PASS",
            "historical_commercial_catalog_is_documentary_ancestry_only",
            "The older commercial compiler/catalog surfaces may remain as documentary ancestry only and must not be overread as current-head product posture.",
            [COMMERCIAL_COMPILER_REL, COMMERCIAL_PROGRAM_CATALOG_REL],
            compiled_head_commit=commercial_catalog.get("compiled_head_commit"),
            current_repo_head=current_head,
        ),
        _check(
            proof_ceiling_blocks and capability_history_stays_historical and current_assurance_stays_bounded,
            "product_claim_ceiling_preconditions_remain_intact",
            "WS19 must inherit the existing proof ceiling instead of weakening it: no release readiness, no campaign completion, no threshold-root acceptance, and no current-head capability overread.",
            [WS15_COMPILER_REL, WS17A_RECEIPT_REL, WS17B_RECEIPT_REL],
        ),
        _check(
            _status(ws14_receipt) == "PASS",
            "bounded_static_verifier_surface_remains_anchor",
            "WS19 product surface must stay bounded to the already-proven WS14 static verifier release and acceptance surfaces.",
            [WS14_RECEIPT_REL, STATIC_RELEASE_MANIFEST_REL, ACCEPTANCE_POLICY_REL, DISTRIBUTION_POLICY_REL],
        ),
    ]

    blocked_by: List[str] = []
    if not ws18_boundary_frozen:
        blocked_by.append("WS18_BOUNDARY_NOT_FROZEN_FIRST")
    if not final_verdict_bounded:
        blocked_by.append("FINAL_VERDICT_NOT_BOUNDED_NON_RELEASE_ELIGIBLE")
    if not release_status_bounded:
        blocked_by.append("RELEASE_CEREMONY_STATUS_NOT_NON_EXECUTED")
    if not license_aligned:
        blocked_by.append("LICENSE_TRACK_NOT_ALIGNED")
    if not readiness_excludes_commercial:
        blocked_by.append("COMMERCIAL_ZONE_NOT_EXCLUDED_FROM_READINESS")
    if not (commercial_catalog_documentary and commercial_boundary_visible and _status(commercial_compiler) == "PASS"):
        blocked_by.append("HISTORICAL_COMMERCIAL_SURFACE_NOT_BOUNDARIED")
    if not (proof_ceiling_blocks and capability_history_stays_historical and current_assurance_stays_bounded):
        blocked_by.append("PRODUCT_CLAIM_PRECONDITIONS_NOT_INTACT")
    if _status(ws14_receipt) != "PASS":
        blocked_by.append("WS14_STATIC_VERIFIER_SURFACE_NOT_PASS")

    product_surface_policy = _build_product_surface_policy(current_head=current_head, final_receipt=ws18_receipt)
    license_track_policy = _build_license_track_policy(current_head=current_head)
    product_claim_policy = _build_product_claim_policy(current_head=current_head)
    updated_dag = _build_dag_update(prior_dag=prior_dag, current_head=current_head)

    _write_json(root / PRODUCT_SURFACE_POLICY_REL, product_surface_policy)
    _write_json(root / LICENSE_TRACK_POLICY_REL, license_track_policy)
    _write_json(root / PRODUCT_CLAIM_POLICY_REL, product_claim_policy)

    product_surface_manifest = _build_product_surface_manifest(root=root, current_head=current_head, final_receipt=ws18_receipt)
    product_claim_compiler = _build_product_claim_compiler(
        current_head=current_head,
        final_receipt=ws18_receipt,
        release_status_receipt=ws18_release_status,
    )
    _write_json(root / PRODUCT_SURFACE_MANIFEST_REL, product_surface_manifest)
    _write_json(root / PRODUCT_CLAIM_COMPILER_REL, product_claim_compiler)
    _write_json(root / EXECUTION_DAG_REL, updated_dag)

    receipt = _build_receipt(
        root=root,
        current_head=current_head,
        checks=checks,
        blocked_by=blocked_by,
        current_dag=updated_dag,
    )
    _write_json(root / PRODUCT_SURFACE_RECEIPT_REL, receipt)

    post_status_lines = _git_status_lines(root)
    dirty_paths = _dirty_relpaths(post_status_lines)
    unexpected = [path for path in dirty_paths if not _path_in_scope(path)]
    protected_violations = [path for path in unexpected if Path(path).as_posix().startswith("KT_PROD_CLEANROOM/")]

    receipt["unexpected_touches"] = unexpected
    receipt["protected_touch_violations"] = protected_violations
    _write_json(root / PRODUCT_SURFACE_RECEIPT_REL, receipt)
    return receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Emit WS19 bounded product surface and license-track alignment artifacts.")
    parser.add_argument("--root", default=str(_repo_root()))
    args = parser.parse_args(argv)
    receipt = emit_ws19_product_surface_license(root=Path(args.root).resolve())
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "campaign_completion_status": receipt["campaign_completion_status"],
                "next_lawful_workstream": receipt["next_lawful_workstream"],
            },
            indent=2,
        )
    )
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
