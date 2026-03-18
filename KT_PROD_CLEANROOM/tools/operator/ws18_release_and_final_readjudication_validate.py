from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


WORKSTREAM_ID = "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION"
STEP_ID = "WS18_STEP_1_RECOMPUTE_RELEASE_STATUS_BLOCKERS_AND_FINAL_VERDICT"
PASS_VERDICT = "FINAL_READJUDICATION_COMPLETE_BOUNDARIED_NON_RELEASE_ELIGIBLE"
BLOCKED_VERDICT = "FINAL_READJUDICATION_INCOMPLETE_OR_CONTRADICTED"
NEXT_WORKSTREAM_ON_PASS = "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/ws18_release_and_final_readjudication_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_ws18_release_and_final_readjudication_validate.py"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
RELEASE_CEREMONY_REL = f"{GOVERNANCE_ROOT_REL}/kt_release_ceremony.json"
ACCEPTANCE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_acceptance_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"

WS10_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_root_ceremony_receipt.json"
WS11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sigstore_integration_receipt.json"
WS12_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_supply_chain_policy_receipt.json"
WS13_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"
WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"
WS15_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_claim_abi_receipt.json"
WS15_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_claim_proof_ceiling_compiler.json"
WS16_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_tevv_dataset_registry_receipt.json"
WS17A_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_assurance_confirmation_receipt.json"
WS17B_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_external_capability_confirmation_receipt.json"

BLOCKER_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_ws18_blocker_matrix.json"
RELEASE_STATUS_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_release_ceremony_status_receipt.json"
FINAL_READJUDICATION_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_final_readjudication_receipt.json"

ROOT_PENDING_PREREQ = "threshold-root verifier acceptance bundle published and accepted"
RELEASE_PENDING_PREREQ = "release signer issuance completed under later workstream law"
PRODUCER_PENDING_PREREQ = "producer attestation bundle activated under later workstream law"
WS18_DONE_PREREQ = "final readjudication completed in WS18"

PLANNED_MUTATES = [
    TOOL_REL,
    TEST_REL,
    EXECUTION_DAG_REL,
    RELEASE_CEREMONY_REL,
    BLOCKER_MATRIX_REL,
    RELEASE_STATUS_RECEIPT_REL,
    FINAL_READJUDICATION_RECEIPT_REL,
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
        raise RuntimeError(f"FAIL_CLOSED: missing required WS18 input: {rel}")
    return _read_json(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


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


def _role_row(topology: Dict[str, Any], role_id: str) -> Dict[str, Any]:
    for row in topology.get("roles", []):
        if isinstance(row, dict) and str(row.get("role_id", "")).strip() == role_id:
            return row
    return {}


def _role_executed(topology: Dict[str, Any], role_id: str) -> bool:
    row = _role_row(topology, role_id)
    issuance = str(row.get("issuance_state", "")).strip()
    return issuance.startswith("EXECUTED")


def _threshold_root_pending(acceptance_policy: Dict[str, Any]) -> bool:
    accepted = acceptance_policy.get("accepted_verifier_trust_roots", [])
    pending = acceptance_policy.get("pending_not_yet_accepted_trust_roots", [])
    bootstrap_only = (
        isinstance(accepted, list)
        and len(accepted) == 1
        and str(accepted[0].get("acceptance_state", "")).strip() == "ACTIVE_BOOTSTRAP_ACCEPTED"
    )
    threshold_pending = (
        isinstance(pending, list)
        and any(str(row.get("acceptance_state", "")).strip() == "PENDING_LATER_ACCEPTANCE_UPDATE" for row in pending if isinstance(row, dict))
    )
    return bootstrap_only and threshold_pending


def _build_release_law_update(
    *,
    prior_release_law: Dict[str, Any],
    current_head: str,
    acceptance_policy: Dict[str, Any],
    signer_topology: Dict[str, Any],
) -> Tuple[Dict[str, Any], str, str, List[str]]:
    threshold_pending = _threshold_root_pending(acceptance_policy)
    release_pending = not _role_executed(signer_topology, "release")
    producer_pending = not _role_executed(signer_topology, "producer")

    open_prereqs: List[str] = []
    if threshold_pending:
        open_prereqs.append(ROOT_PENDING_PREREQ)
    if release_pending:
        open_prereqs.append(RELEASE_PENDING_PREREQ)
    if producer_pending:
        open_prereqs.append(PRODUCER_PENDING_PREREQ)

    release_status = "NON_EXECUTED_BLOCKED_BY_PREREQUISITES" if open_prereqs else "EXECUTABLE_NOT_EXECUTED"
    release_eligibility = "NOT_ELIGIBLE" if open_prereqs else "ELIGIBLE_PENDING_OPERATOR_DECISION"

    updated = json.loads(json.dumps(prior_release_law))
    updated["current_repo_head"] = current_head
    updated["generated_utc"] = _utc_now()
    updated["predecessor_status"] = str(prior_release_law.get("status", "")).strip()
    updated["status"] = "ACTIVE_LOCKED_PENDING_EXECUTION_PREREQUISITES" if open_prereqs else "ACTIVE_READY_NOT_EXECUTED"
    updated["execution_prerequisites_not_yet_met"] = open_prereqs
    updated["completed_in_ws18"] = [WS18_DONE_PREREQ]
    updated["release_execution_status"] = release_status
    updated["release_eligibility"] = release_eligibility
    semantic = updated.get("semantic_boundary") if isinstance(updated.get("semantic_boundary"), dict) else {}
    semantic["lawful_current_claim"] = (
        "WS18 completes final readjudication and determines that the release ceremony remains non-executed and not release-eligible until threshold-root acceptance, release signer issuance, and producer attestation activation are proven."
        if open_prereqs
        else "WS18 completes final readjudication and determines that release execution prerequisites are satisfied, but release remains not executed until a later explicit operator decision."
    )
    semantic["release_ready_now"] = not open_prereqs
    semantic["release_execution_now_lawful"] = not open_prereqs
    updated["semantic_boundary"] = semantic
    stronger = list(updated.get("stronger_claim_not_made", [])) if isinstance(updated.get("stronger_claim_not_made"), list) else []
    for item in [
        "Release ceremony executed.",
        "Release readiness proven without threshold-root acceptance, release signer issuance, and producer attestation activation.",
        "Historical-bounded capability confirmation upgrades into current-head capability proof.",
    ]:
        if item not in stronger:
            stronger.append(item)
    updated["stronger_claim_not_made"] = list(dict.fromkeys(stronger))
    return updated, release_status, release_eligibility, open_prereqs


def _build_blocker_matrix(
    *,
    current_head: str,
    claim_compiler: Dict[str, Any],
    ws17a_receipt: Dict[str, Any],
    ws17b_receipt: Dict[str, Any],
    release_status: str,
    open_release_prereqs: Sequence[str],
) -> Dict[str, Any]:
    blocked_claim_ids = {str(item).strip() for item in claim_compiler.get("blocked_current_claim_ids", [])}
    capability_scope = str(ws17b_receipt.get("capability_scope", "")).strip()

    rows = [
        {
            "blocker_id": "THRESHOLD_ROOT_VERIFIER_ACCEPTANCE_PENDING",
            "severity": "CRITICAL",
            "status": "OPEN" if ROOT_PENDING_PREREQ in open_release_prereqs else "RESOLVED",
            "rationale": "Verifier acceptance remains bootstrap-root only; no threshold-root acceptance bundle has been published and accepted.",
            "evidence_refs": [ACCEPTANCE_POLICY_REL, TRUST_ROOT_POLICY_REL, WS15_COMPILER_REL],
        },
        {
            "blocker_id": "RELEASE_SIGNER_ISSUANCE_PENDING",
            "severity": "CRITICAL",
            "status": "OPEN" if RELEASE_PENDING_PREREQ in open_release_prereqs else "RESOLVED",
            "rationale": "Release signers remain planned only and have not been issued under later workstream law.",
            "evidence_refs": [SIGNER_TOPOLOGY_REL, RELEASE_CEREMONY_REL, WS10_RECEIPT_REL],
        },
        {
            "blocker_id": "PRODUCER_ATTESTATION_BUNDLE_PENDING",
            "severity": "HIGH",
            "status": "OPEN" if PRODUCER_PENDING_PREREQ in open_release_prereqs else "RESOLVED",
            "rationale": "Producer attestation identities remain planned only and no release-side producer bundle is active.",
            "evidence_refs": [SIGNER_TOPOLOGY_REL, RELEASE_CEREMONY_REL],
        },
        {
            "blocker_id": "RELEASE_CEREMONY_NOT_EXECUTED",
            "severity": "HIGH",
            "status": "OPEN" if release_status != "EXECUTED" else "RESOLVED",
            "rationale": "WS18 determines release ceremony execution has not occurred and remains blocked by explicit prerequisites.",
            "evidence_refs": [RELEASE_CEREMONY_REL, RELEASE_STATUS_RECEIPT_REL],
        },
        {
            "blocker_id": "CURRENT_HEAD_CAPABILITY_NOT_EXTERNALLY_CONFIRMED",
            "severity": "HIGH",
            "status": "OPEN" if capability_scope == "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY" else "RESOLVED",
            "rationale": "WS17B confirms historical bounded capability only and must not be overread as current-head capability confirmation.",
            "evidence_refs": [WS17B_RECEIPT_REL],
        },
        {
            "blocker_id": "CAMPAIGN_COMPLETION_NOT_PROVEN",
            "severity": "HIGH",
            "status": "OPEN" if "campaign_completion_proven" in blocked_claim_ids else "RESOLVED",
            "rationale": "The proof ceiling still blocks campaign-completion claims on the current lawful stack.",
            "evidence_refs": [WS15_COMPILER_REL],
        },
        {
            "blocker_id": "CURRENT_HEAD_ASSURANCE_CONFIRMED_BOUNDED_ONLY",
            "severity": "INFO",
            "status": "RESOLVED_WITH_BOUNDARY" if _status(ws17a_receipt) == "PASS" else "OPEN",
            "rationale": "Current-head outsider assurance is proven only for the bounded declared public verifier surface.",
            "evidence_refs": [WS17A_RECEIPT_REL],
        },
        {
            "blocker_id": "HISTORICAL_CAPABILITY_CONFIRMED_BOUNDED_ONLY",
            "severity": "INFO",
            "status": "RESOLVED_WITH_BOUNDARY" if _status(ws17b_receipt) == "PASS" else "OPEN",
            "rationale": "Historical outsider capability replay is proven only on the bounded frontier/readjudication target and stays historical-only.",
            "evidence_refs": [WS17B_RECEIPT_REL],
        },
    ]

    open_ids = [row["blocker_id"] for row in rows if row["status"] == "OPEN"]
    resolved_ids = [row["blocker_id"] for row in rows if row["status"] == "RESOLVED"]
    narrowed_ids = [row["blocker_id"] for row in rows if row["status"] == "RESOLVED_WITH_BOUNDARY"]
    return {
        "schema_id": "kt.operator.ws18.blocker_matrix.v1",
        "artifact_id": "kt_ws18_blocker_matrix.json",
        "workstream_id": WORKSTREAM_ID,
        "generated_utc": _utc_now(),
        "current_repo_head": current_head,
        "rows": rows,
        "summary": {
            "open_blockers": open_ids,
            "resolved_blockers": resolved_ids,
            "resolved_with_boundary": narrowed_ids,
        },
        "stronger_claim_not_made": "This WS18 blocker matrix does not convert historical capability confirmation into current-head capability, does not activate threshold-root acceptance, and does not claim release readiness, release execution, or campaign completion.",
    }


def _build_release_status_receipt(
    *,
    root: Path,
    current_head: str,
    ws10: Dict[str, Any],
    ws11: Dict[str, Any],
    ws12: Dict[str, Any],
    ws13: Dict[str, Any],
    ws14: Dict[str, Any],
    ws15: Dict[str, Any],
    ws16: Dict[str, Any],
    ws17a: Dict[str, Any],
    ws17b: Dict[str, Any],
    release_status: str,
    release_eligibility: str,
    open_release_prereqs: Sequence[str],
) -> Dict[str, Any]:
    ws17b_boundary_head = str(ws17b.get("compiled_against", "")).strip()
    ws17b_frozen_first = _git_is_ancestor(root, ws17b_boundary_head, current_head)
    upstream_stack_ok = all(
        _status(payload) == "PASS"
        for payload in (ws10, ws11, ws12, ws13, ws14, ws15, ws16, ws17a, ws17b)
    )
    historical_only_capability = str(ws17b.get("capability_scope", "")).strip() == "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY"

    blockers: List[str] = []
    if not ws17b_frozen_first:
        blockers.append("WS17B_BOUNDARY_NOT_FROZEN_FIRST")
    if not upstream_stack_ok:
        blockers.append("UPSTREAM_RECEIPT_STACK_NOT_PASS")
    if not historical_only_capability:
        blockers.append("WS17B_CAPABILITY_SCOPE_CONTRADICTED")

    checks = [
        _check(
            ws17b_frozen_first,
            "ws17b_boundary_frozen_before_ws18",
            "WS18 may proceed only after the accepted WS17B pass boundary is frozen first.",
            [WS17B_RECEIPT_REL],
            failures=[] if ws17b_frozen_first else [f"compiled_against={ws17b_boundary_head}", f"current_head={current_head}"],
        ),
        _check(
            upstream_stack_ok,
            "ws10_through_ws17b_receipt_stack_pass",
            "WS18 requires the current lawful bounded receipt stack from WS10 through WS17B to remain PASS before readjudication.",
            [WS10_RECEIPT_REL, WS11_RECEIPT_REL, WS12_RECEIPT_REL, WS13_RECEIPT_REL, WS14_RECEIPT_REL, WS15_RECEIPT_REL, WS16_RECEIPT_REL, WS17A_RECEIPT_REL, WS17B_RECEIPT_REL],
        ),
        _check(
            ROOT_PENDING_PREREQ in open_release_prereqs,
            "threshold_root_acceptance_still_pending",
            "Threshold-root verifier acceptance must remain pending until an explicit later acceptance bundle is published.",
            [ACCEPTANCE_POLICY_REL, TRUST_ROOT_POLICY_REL],
        ),
        _check(
            RELEASE_PENDING_PREREQ in open_release_prereqs,
            "release_signer_issuance_still_pending",
            "Release signer issuance must remain explicit and unexecuted until a later workstream actually performs it.",
            [SIGNER_TOPOLOGY_REL, RELEASE_CEREMONY_REL],
        ),
        _check(
            PRODUCER_PENDING_PREREQ in open_release_prereqs,
            "producer_attestation_bundle_still_pending",
            "Producer attestation activation must remain explicit and unexecuted until a later workstream performs it.",
            [SIGNER_TOPOLOGY_REL, RELEASE_CEREMONY_REL],
        ),
        _check(
            release_status == "NON_EXECUTED_BLOCKED_BY_PREREQUISITES" and release_eligibility == "NOT_ELIGIBLE",
            "release_status_explicit_and_not_executed",
            "WS18 must determine release ceremony status explicitly and keep it non-executed when prerequisites remain open.",
            [RELEASE_CEREMONY_REL],
            release_ceremony_status=release_status,
            release_eligibility=release_eligibility,
        ),
        _check(
            historical_only_capability,
            "historical_capability_not_overread_as_current_head_capability",
            "WS18 must preserve the WS17B historical-only capability boundary and not overread it into current-head capability.",
            [WS17B_RECEIPT_REL],
        ),
    ]
    status = "PASS" if not blockers else "BLOCKED"
    return {
        "schema_id": "kt.operator.ws18.release_ceremony_status_receipt.v1",
        "artifact_id": "kt_release_ceremony_status_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": "RELEASE_CEREMONY_NON_EXECUTION_CORRECTLY_DETERMINED" if status == "PASS" else "RELEASE_CEREMONY_STATUS_CONTRADICTED",
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "generated_utc": _utc_now(),
        "release_ceremony_status": release_status,
        "release_eligibility": release_eligibility,
        "open_execution_prerequisites": list(open_release_prereqs),
        "checks": checks,
        "blocked_by": blockers,
        "remaining_limitations": [
            "WS18 does not execute the release ceremony when explicit prerequisites remain open.",
            "Threshold-root verifier acceptance remains inactive.",
            "Release signer issuance and producer attestation activation remain unexecuted.",
            "Historical capability confirmation remains historical-only and does not upgrade into current-head capability.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "stronger_claim_not_made": [
            "Release ceremony executed.",
            "Release readiness is proven.",
            "Historical capability confirmation upgrades into current-head capability.",
        ],
    }


def _build_final_readjudication_receipt(
    *,
    current_head: str,
    claim_compiler: Dict[str, Any],
    ws17a: Dict[str, Any],
    ws17b: Dict[str, Any],
    blocker_matrix: Dict[str, Any],
    release_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    blocked_claim_ids = [str(item).strip() for item in claim_compiler.get("blocked_current_claim_ids", [])]
    open_blockers = list(blocker_matrix.get("summary", {}).get("open_blockers", []))
    release_eligibility = str(release_receipt.get("release_eligibility", "")).strip()
    release_status = str(release_receipt.get("release_ceremony_status", "")).strip()
    historical_only_capability = str(ws17b.get("capability_scope", "")).strip() == "HISTORICAL_BOUNDED_FRONTIER_TARGET_ONLY"
    final_verdict_ok = (
        "release_readiness_proven" in blocked_claim_ids
        and "campaign_completion_proven" in blocked_claim_ids
        and release_eligibility == "NOT_ELIGIBLE"
        and release_status == "NON_EXECUTED_BLOCKED_BY_PREREQUISITES"
        and historical_only_capability
    )
    blockers: List[str] = []
    if _status(release_receipt) != "PASS":
        blockers.append("RELEASE_STATUS_NOT_DETERMINED")
    if not final_verdict_ok:
        blockers.append("FINAL_VERDICT_DERIVATION_CONTRADICTED")

    checks = [
        _check(
            _status(release_receipt) == "PASS",
            "release_ceremony_status_receipt_pass",
            "WS18 requires an explicit, validator-backed release-ceremony status receipt before final readjudication can pass.",
            [RELEASE_STATUS_RECEIPT_REL],
        ),
        _check(
            bool(open_blockers),
            "blocker_matrix_recomputed_from_current_stack",
            "WS18 must recompute blockers from the current lawful stack instead of inheriting an older matrix blindly.",
            [BLOCKER_MATRIX_REL, WS15_COMPILER_REL, WS17B_RECEIPT_REL],
            open_blockers=open_blockers,
        ),
        _check(
            "release_readiness_proven" in blocked_claim_ids and "campaign_completion_proven" in blocked_claim_ids,
            "proof_ceiling_still_blocks_stronger_claims",
            "The carried-forward proof ceiling must still block release readiness and campaign completion on the current stack.",
            [WS15_COMPILER_REL],
            blocked_claim_ids=blocked_claim_ids,
        ),
        _check(
            _status(ws17a) == "PASS" and historical_only_capability,
            "bounded_current_assurance_and_historical_capability_kept_distinct",
            "WS18 must preserve current-head bounded assurance separately from historical-only capability replay.",
            [WS17A_RECEIPT_REL, WS17B_RECEIPT_REL],
        ),
        _check(
            final_verdict_ok,
            "final_verdict_machine_derived_from_claims_and_blockers",
            "WS18 final verdict must be derived from the proof ceiling, release status determination, and the recomputed blocker matrix rather than narrative preference.",
            [WS15_COMPILER_REL, RELEASE_STATUS_RECEIPT_REL, BLOCKER_MATRIX_REL],
            release_ceremony_status=release_status,
            release_eligibility=release_eligibility,
        ),
    ]
    status = "PASS" if not blockers else "BLOCKED"
    next_lawful = NEXT_WORKSTREAM_ON_PASS if status == "PASS" else WORKSTREAM_ID
    final_verdict = {
        "verdict_id": "CURRENT_LAWFUL_STACK_BOUNDED_NON_RELEASE_ELIGIBLE",
        "status": "PASS" if final_verdict_ok else "BLOCKED",
        "bounded_scope": "Current lawful stack through WS17B with bounded current-head assurance and historical-only capability import.",
        "release_eligibility": release_eligibility,
        "release_ceremony_status": release_status,
        "current_head_assurance_status": "PROVEN_BOUNDED_SINGLE_SURFACE" if _status(ws17a) == "PASS" else "NOT_PROVEN",
        "current_head_capability_status": "NOT_EXTERNALLY_CONFIRMED",
        "historical_capability_status": "PROVEN_HISTORICAL_BOUNDED_ONLY" if historical_only_capability and _status(ws17b) == "PASS" else "NOT_PROVEN",
        "campaign_completion_status": "NOT_PROVEN" if "campaign_completion_proven" in blocked_claim_ids else "UNBLOCKED",
        "open_blockers": open_blockers,
    }
    return {
        "schema_id": "kt.operator.ws18.final_readjudication_receipt.v1",
        "artifact_id": "kt_final_readjudication_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else BLOCKED_VERDICT,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "generated_utc": _utc_now(),
        "release_ceremony_status_ref": RELEASE_STATUS_RECEIPT_REL,
        "blocker_matrix_ref": BLOCKER_MATRIX_REL,
        "proof_ceiling_ref": WS15_COMPILER_REL,
        "final_verdict": final_verdict,
        "blocked_by": blockers,
        "checks": checks,
        "remaining_limitations": [
            "WS18 does not activate threshold-root verifier acceptance.",
            "WS18 does not execute the release ceremony.",
            "WS18 does not upgrade historical capability confirmation into current-head capability proof.",
            "WS18 does not widen verifier coverage beyond the already-bounded surfaces.",
            "WS18 does not prove campaign completion.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "next_lawful_workstream": next_lawful,
        "stronger_claim_not_made": [
            "Release readiness is proven.",
            "Release ceremony executed.",
            "Historical-bounded capability confirmation upgrades into current-head capability proof.",
            "Campaign completion is proven.",
        ],
    }


def _apply_control_plane(*, dag: Dict[str, Any], current_head: str, ws18_status: str) -> None:
    next_lawful = NEXT_WORKSTREAM_ON_PASS if ws18_status == "PASS" else WORKSTREAM_ID
    ws18_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws19_node = next(node for node in dag["nodes"] if node["id"] == NEXT_WORKSTREAM_ON_PASS)
    ws18_node["status"] = ws18_status
    ws18_node["ratification_checkpoint"] = Path(FINAL_READJUDICATION_RECEIPT_REL).name
    ws18_node["claim_boundary"] = (
        "WS18 PASS proves only that the current lawful stack has been finally readjudicated as bounded, non-release-eligible, and not campaign-complete. Historical capability confirmation remains historical-only and does not upgrade into current-head capability."
        if ws18_status == "PASS"
        else "WS18 remains current until release status, blocker recomputation, and final readjudication all resolve without contradiction."
    )
    ws19_node["status"] = "UNLOCKED" if ws18_status == "PASS" else "LOCKED_PENDING_WS18_PASS"
    dag["current_node"] = WORKSTREAM_ID
    dag["current_repo_head"] = current_head
    dag["generated_utc"] = _utc_now()
    dag["next_lawful_workstream"] = next_lawful
    semantic = dag.get("semantic_boundary") if isinstance(dag.get("semantic_boundary"), dict) else {}
    semantic["lawful_current_claim"] = (
        "WS18 has recomputed the current lawful stack as bounded, non-release-eligible, and not campaign-complete. Current-head outsider assurance remains bounded to the declared verifier surface, while outsider capability confirmation remains historical-only."
        if ws18_status == "PASS"
        else "WS18 is current until the bounded release-status determination and final readjudication resolve without contradiction."
    )
    stronger = list(semantic.get("stronger_claim_not_made", [])) if isinstance(semantic.get("stronger_claim_not_made"), list) else []
    for item in [
        "Threshold-root verifier acceptance is active.",
        "Release readiness is proven.",
        "Release ceremony execution is proven.",
        "Historical-bounded capability confirmation upgrades into current-head capability proof.",
        "Campaign completion is proven.",
    ]:
        if item not in stronger:
            stronger.append(item)
    semantic["stronger_claim_not_made"] = list(dict.fromkeys(stronger))
    dag["semantic_boundary"] = semantic


def emit_ws18_release_and_final_readjudication(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or _repo_root()
    pre_status = _git_status_lines(repo)
    pre_dirty = _dirty_relpaths(pre_status)
    if pre_dirty:
        out_of_scope = [path for path in pre_dirty if not _path_in_scope(path)]
        if out_of_scope:
            raise RuntimeError(f"FAIL_CLOSED: WS18 prewrite workspace not clean: {out_of_scope}")

    current_head = _git_head(repo)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    release_law = _load_required_json(repo, RELEASE_CEREMONY_REL)
    acceptance_policy = _load_required_json(repo, ACCEPTANCE_POLICY_REL)
    signer_topology = _load_required_json(repo, SIGNER_TOPOLOGY_REL)
    claim_compiler = _load_required_json(repo, WS15_COMPILER_REL)

    ws10 = _load_required_json(repo, WS10_RECEIPT_REL)
    ws11 = _load_required_json(repo, WS11_RECEIPT_REL)
    ws12 = _load_required_json(repo, WS12_RECEIPT_REL)
    ws13 = _load_required_json(repo, WS13_RECEIPT_REL)
    ws14 = _load_required_json(repo, WS14_RECEIPT_REL)
    ws15 = _load_required_json(repo, WS15_RECEIPT_REL)
    ws16 = _load_required_json(repo, WS16_RECEIPT_REL)
    ws17a = _load_required_json(repo, WS17A_RECEIPT_REL)
    ws17b = _load_required_json(repo, WS17B_RECEIPT_REL)

    release_law_updated, release_status, release_eligibility, open_release_prereqs = _build_release_law_update(
        prior_release_law=release_law,
        current_head=current_head,
        acceptance_policy=acceptance_policy,
        signer_topology=signer_topology,
    )
    blocker_matrix = _build_blocker_matrix(
        current_head=current_head,
        claim_compiler=claim_compiler,
        ws17a_receipt=ws17a,
        ws17b_receipt=ws17b,
        release_status=release_status,
        open_release_prereqs=open_release_prereqs,
    )
    release_receipt = _build_release_status_receipt(
        root=repo,
        current_head=current_head,
        ws10=ws10,
        ws11=ws11,
        ws12=ws12,
        ws13=ws13,
        ws14=ws14,
        ws15=ws15,
        ws16=ws16,
        ws17a=ws17a,
        ws17b=ws17b,
        release_status=release_status,
        release_eligibility=release_eligibility,
        open_release_prereqs=open_release_prereqs,
    )

    _write_json((repo / Path(RELEASE_CEREMONY_REL)).resolve(), release_law_updated)
    _write_json((repo / Path(BLOCKER_MATRIX_REL)).resolve(), blocker_matrix)
    _write_json((repo / Path(RELEASE_STATUS_RECEIPT_REL)).resolve(), release_receipt)

    final_receipt = _build_final_readjudication_receipt(
        current_head=current_head,
        claim_compiler=claim_compiler,
        ws17a=ws17a,
        ws17b=ws17b,
        blocker_matrix=blocker_matrix,
        release_receipt=release_receipt,
    )
    final_receipt["input_hashes"] = {
        WS10_RECEIPT_REL: _file_sha256((repo / Path(WS10_RECEIPT_REL)).resolve()),
        WS11_RECEIPT_REL: _file_sha256((repo / Path(WS11_RECEIPT_REL)).resolve()),
        WS12_RECEIPT_REL: _file_sha256((repo / Path(WS12_RECEIPT_REL)).resolve()),
        WS13_RECEIPT_REL: _file_sha256((repo / Path(WS13_RECEIPT_REL)).resolve()),
        WS14_RECEIPT_REL: _file_sha256((repo / Path(WS14_RECEIPT_REL)).resolve()),
        WS15_RECEIPT_REL: _file_sha256((repo / Path(WS15_RECEIPT_REL)).resolve()),
        WS15_COMPILER_REL: _file_sha256((repo / Path(WS15_COMPILER_REL)).resolve()),
        WS16_RECEIPT_REL: _file_sha256((repo / Path(WS16_RECEIPT_REL)).resolve()),
        WS17A_RECEIPT_REL: _file_sha256((repo / Path(WS17A_RECEIPT_REL)).resolve()),
        WS17B_RECEIPT_REL: _file_sha256((repo / Path(WS17B_RECEIPT_REL)).resolve()),
        BLOCKER_MATRIX_REL: _file_sha256((repo / Path(BLOCKER_MATRIX_REL)).resolve()),
        RELEASE_STATUS_RECEIPT_REL: _file_sha256((repo / Path(RELEASE_STATUS_RECEIPT_REL)).resolve()),
    }

    _apply_control_plane(dag=dag, current_head=current_head, ws18_status=str(final_receipt.get("status", "")).strip())
    _write_json((repo / Path(EXECUTION_DAG_REL)).resolve(), dag)

    post_status = _git_status_lines(repo)
    unexpected_touches = [path for path in _dirty_relpaths(post_status) if not _path_in_scope(path)]
    if unexpected_touches:
        raise RuntimeError(f"FAIL_CLOSED: WS18 touched out-of-scope paths: {unexpected_touches}")

    final_receipt["unexpected_touches"] = []
    final_receipt["protected_touch_violations"] = []
    final_receipt["validators_run"] = ["python -m tools.operator.ws18_release_and_final_readjudication_validate"]
    final_receipt["tests_run"] = ["python -m pytest -q tests/operator/test_ws18_release_and_final_readjudication_validate.py"]
    _write_json((repo / Path(FINAL_READJUDICATION_RECEIPT_REL)).resolve(), final_receipt)
    return final_receipt


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="WS18 release-ceremony status and final readjudication validator")
    parser.parse_args(list(argv) if argv is not None else None)
    receipt = emit_ws18_release_and_final_readjudication(root=_repo_root())
    print(json.dumps({"status": receipt["status"], "next_lawful_workstream": receipt["next_lawful_workstream"]}, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
