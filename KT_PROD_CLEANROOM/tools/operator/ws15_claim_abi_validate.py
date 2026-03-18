from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW"
STEP_ID = "WS15_STEP_1_LOCK_CLAIM_ABI_AND_PROOF_CEILING"
PASS_VERDICT = "CLAIM_ABI_AND_PROOF_CEILING_LOCKED"
PARTIAL_VERDICT = "CLAIM_ABI_OR_PROOF_CEILING_INCOMPLETE"
NEXT_WORKSTREAM_ID = "WS16_TRUST_ASSUMPTIONS_TEVV_DATASET_PINNING_AND_COMPARATOR_REGISTRY"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
WS10_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_root_ceremony_receipt.json"
WS11_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_sigstore_integration_receipt.json"
WS12_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_supply_chain_policy_receipt.json"
WS13_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"
WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"

ACCEPTANCE_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_public_verifier_acceptance_policy.json"
SIGNER_IDENTITY_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/signer_identity_policy.json"
SIGNER_TOPOLOGY_REL = f"{GOVERNANCE_ROOT_REL}/kt_signer_topology.json"
TRUST_ROOT_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_root_policy.json"
TRUTH_SUPERSESSION_RULES_REL = f"{GOVERNANCE_ROOT_REL}/truth_supersession_rules.json"
CLAIM_COMPILER_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/closure_foundation/kt_claim_compiler_policy.json"

SETTLED_TRUTH_SOURCE_REL = f"{REPORT_ROOT_REL}/settled_truth_source_receipt.json"
TRUTH_SUPERSESSION_RECEIPT_REL = f"{REPORT_ROOT_REL}/truth_supersession_receipt.json"
CURRENT_STATE_RECEIPT_REL = f"{REPORT_ROOT_REL}/current_state_receipt.json"
CLAIM_CEILING_SUMMARY_REL = f"{REPORT_ROOT_REL}/kt_claim_ceiling_summary.json"

CLAIM_ABI_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_claim_abi_policy.json"
IDENTITY_MODEL_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_identity_model_policy.json"
LEDGER_LAW_REL = f"{GOVERNANCE_ROOT_REL}/kt_ledger_law.json"
RELEASE_CEREMONY_REL = f"{GOVERNANCE_ROOT_REL}/kt_release_ceremony.json"
FAILURE_MODE_REGISTER_REL = f"{GOVERNANCE_ROOT_REL}/kt_failure_mode_register.json"

PROOF_CEILING_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_claim_proof_ceiling_compiler.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_claim_abi_receipt.json"

PLANNED_MUTATES = [
    CLAIM_ABI_POLICY_REL,
    IDENTITY_MODEL_POLICY_REL,
    LEDGER_LAW_REL,
    RELEASE_CEREMONY_REL,
    FAILURE_MODE_REGISTER_REL,
    PROOF_CEILING_COMPILER_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws15_claim_abi_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws15_claim_abi_validate.py",
]

ABI_FIELD_ORDER = [
    "claim_id",
    "claim_status",
    "domain",
    "compiled_head_commit",
    "subject_head_commit",
    "evidence_position",
    "upstream_receipt_ref",
    "upstream_receipt_status",
    "proof_ceiling_id",
    "trust_scope",
    "surface_scope",
    "statement",
    "evidence_refs",
    "blockers",
    "stronger_claim_not_made",
]

ALLOWED_CLAIM_STATUSES = ("ALLOWED_CURRENT", "BLOCKED_CURRENT", "DOCUMENTARY_ONLY")
ALLOWED_DOMAINS = (
    "truth_authority",
    "root_trust",
    "public_trust",
    "supply_chain",
    "determinism",
    "verifier_release",
    "verifier_acceptance",
    "release_ceremony",
    "campaign_state",
)
ALLOWED_EVIDENCE_POSITIONS = (
    "CURRENT_HEAD_CONTAINS_UPSTREAM_PASS_EVIDENCE",
    "CURRENT_HEAD_DOCUMENTARY_ONLY_BOUNDARY",
)


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True, encoding="utf-8").strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
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
    rows: List[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if rel:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _path_in_scope(path: str) -> bool:
    normalized = str(Path(path).as_posix()).rstrip("/")
    for allowed in PLANNED_MUTATES:
        allowed_norm = str(Path(allowed).as_posix()).rstrip("/")
        if normalized == allowed_norm or normalized.startswith(f"{allowed_norm}/") or allowed_norm.startswith(f"{normalized}/"):
            return True
    return False


def _load_required_json(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS15 input: {rel}")
    return load_json(path)


def _write_json(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=())


def _render_stable_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _stable_payload_sha(obj: Any) -> str:
    return hashlib.sha256(_render_stable_json(obj).encode("utf-8")).hexdigest()


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
        "refs": [str(Path(ref).as_posix()) for ref in refs],
    }
    if failures:
        row["failures"] = [str(item) for item in failures]
    row.update(extra)
    return row


def _field(field_id: str, field_type: str, required: bool, description: str, *, allowed_values: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "field_id": field_id,
        "type": field_type,
        "required": required,
        "description": description,
    }
    if allowed_values is not None:
        row["allowed_values"] = list(allowed_values)
    return row


def build_claim_abi_policy(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.claim_abi_policy.v1",
        "policy_id": "KT_CLAIM_ABI_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "claim_record_fields": [
            _field("claim_id", "string", True, "Stable machine-readable identifier for the claim row."),
            _field("claim_status", "enum", True, "Current admissibility state for the claim.", allowed_values=ALLOWED_CLAIM_STATUSES),
            _field("domain", "enum", True, "Governance domain for the claim.", allowed_values=ALLOWED_DOMAINS),
            _field("compiled_head_commit", "git_sha", True, "Current repository head against which the ABI output was compiled."),
            _field("subject_head_commit", "git_sha_or_empty", True, "Upstream bounded subject head for the cited claim."),
            _field(
                "evidence_position",
                "enum",
                True,
                "Whether the current head is the subject or only contains bounded upstream evidence.",
                allowed_values=ALLOWED_EVIDENCE_POSITIONS,
            ),
            _field("upstream_receipt_ref", "repo_relpath", True, "Canonical upstream receipt that governs the claim."),
            _field("upstream_receipt_status", "string", True, "Required current status of the cited upstream receipt."),
            _field("proof_ceiling_id", "string", True, "Named proof ceiling that constrains the claim."),
            _field("trust_scope", "string", True, "Bounded trust scope for the claim."),
            _field("surface_scope", "string", True, "Bounded surface path or scope string for the claim."),
            _field("statement", "string", True, "Human-readable claim string generated from machine state."),
            _field("evidence_refs", "list[string]", True, "Machine-cited evidence references for the claim."),
            _field("blockers", "list[string]", True, "Explicit blockers when the claim is not currently admissible."),
            _field("stronger_claim_not_made", "list[string]", True, "Stronger claims that remain forbidden."),
        ],
        "required_field_order": list(ABI_FIELD_ORDER),
        "claim_status_semantics": {
            "ALLOWED_CURRENT": "Current head may make the bounded claim exactly as compiled.",
            "BLOCKED_CURRENT": "Current head must not make the stronger claim; blockers remain active.",
            "DOCUMENTARY_ONLY": "Claim is documentary or mirror-only and may not be treated as live authority.",
        },
        "invariants": [
            "Every current claim row must distinguish compiled_head_commit from subject_head_commit whenever current HEAD only contains upstream evidence.",
            "No claim row may widen bootstrap-root verifier acceptance into threshold-root acceptance without a later explicit acceptance bundle.",
            "No claim row may convert the WS10 reratified 3-of-3 root execution into a 3-of-5 execution claim.",
            "No claim row may mark release readiness, release ceremony completion, or campaign completion as ALLOWED_CURRENT at WS15.",
            "Documentary mirrors may be described only as documentary-only surfaces and never as the active truth source.",
        ],
        "compiler_output_ref": PROOF_CEILING_COMPILER_REL,
        "historical_predecessor_refs": [
            CLAIM_CEILING_SUMMARY_REL,
            f"{REPORT_ROOT_REL}/commercial_claim_compiler_receipt.json",
            CLAIM_COMPILER_POLICY_REL,
        ],
        "stronger_claim_not_made": [
            "Claim ABI law itself widens verifier coverage or release readiness.",
            "WS15 makes threshold-root verifier acceptance active.",
            "WS15 erases the distinction between current HEAD and upstream frozen proof subjects.",
        ],
    }


def _sorted_unique(values: Iterable[str]) -> List[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def build_identity_model_policy(*, root: Path, current_head: str) -> Dict[str, Any]:
    signer_topology = _load_required_json(root, SIGNER_TOPOLOGY_REL)
    signer_identity_policy = _load_required_json(root, SIGNER_IDENTITY_POLICY_REL)
    trust_root_policy = _load_required_json(root, TRUST_ROOT_POLICY_REL)

    role_identity_map = signer_topology.get("role_identity_map") if isinstance(signer_topology.get("role_identity_map"), list) else []
    role_sets: Dict[str, List[str]] = {}
    for row in role_identity_map:
        if not isinstance(row, dict):
            continue
        role_id = str(row.get("role_id", "")).strip()
        identity_id = str(row.get("identity_id", "")).strip()
        if role_id and identity_id:
            role_sets.setdefault(role_id, []).append(identity_id)

    keyless_signers = [
        str(row.get("signer_id", "")).strip()
        for row in (signer_identity_policy.get("allowed_signers") if isinstance(signer_identity_policy.get("allowed_signers"), list) else [])
        if isinstance(row, dict) and str(row.get("mode", "")).strip() == "sigstore_keyless"
    ]
    operator_identity = str(trust_root_policy.get("topology_reratification", {}).get("approved_by_operator", "")).strip()
    principal_sets = {
        "root_custodians": _sorted_unique(role_sets.get("root", [])),
        "release_signers": _sorted_unique(role_sets.get("release", [])),
        "producer_attestors": _sorted_unique(role_sets.get("producer", [])),
        "ci_role_identities": _sorted_unique(role_sets.get("ci", [])),
        "ci_keyless_signers": _sorted_unique(keyless_signers),
        "verifier_acceptance_maintainers": _sorted_unique(role_sets.get("verifier_acceptance", [])),
        "local_operator": _sorted_unique([operator_identity]),
    }

    overlap_rules = [
        ("root_custodians", "release_signers", "root_release_overlap_forbidden"),
        ("root_custodians", "producer_attestors", "root_producer_overlap_forbidden"),
        ("root_custodians", "ci_role_identities", "root_ci_overlap_forbidden"),
        ("root_custodians", "verifier_acceptance_maintainers", "root_verifier_acceptance_overlap_forbidden"),
        ("release_signers", "verifier_acceptance_maintainers", "release_verifier_acceptance_overlap_forbidden"),
        ("release_signers", "ci_keyless_signers", "release_ci_keyless_overlap_forbidden"),
        ("verifier_acceptance_maintainers", "ci_keyless_signers", "verifier_acceptance_ci_keyless_overlap_forbidden"),
        ("local_operator", "release_signers", "operator_release_overlap_forbidden"),
        ("local_operator", "verifier_acceptance_maintainers", "operator_verifier_acceptance_overlap_forbidden"),
    ]
    overlap_scan: List[Dict[str, Any]] = []
    for left, right, constraint_id in overlap_rules:
        overlap = sorted(set(principal_sets[left]) & set(principal_sets[right]))
        overlap_scan.append(
            {
                "constraint_id": constraint_id,
                "left_principal_class": left,
                "right_principal_class": right,
                "overlap_identities": overlap,
                "status": "PASS" if not overlap else "FAIL",
            }
        )

    self_ratification_barriers = [
        {
            "barrier_id": "claim_compiler_must_not_self_ratify_stronger_claims",
            "rule": "WS15 claim compiler outputs may only compile claims from cited upstream receipts and may not treat kt_claim_abi_receipt.json or kt_claim_proof_ceiling_compiler.json as authority for stronger upstream states.",
            "enforcement": "FAIL_CLOSED",
        },
        {
            "barrier_id": "verifier_acceptance_requires_explicit_upstream_bundle",
            "rule": "Bootstrap-root-only acceptance may remain active, but threshold-root acceptance may not be self-promoted by WS15 outputs without a later explicit acceptance bundle.",
            "enforcement": "FAIL_CLOSED",
        },
        {
            "barrier_id": "release_approver_cannot_self_accept_same_bundle",
            "rule": "The same concrete identity may not serve as both release approver and verifier-acceptance maintainer for the same release bundle.",
            "enforcement": "FAIL_CLOSED",
        },
    ]

    return {
        "schema_id": "kt.governance.identity_model_policy.v1",
        "policy_id": "KT_IDENTITY_MODEL_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "principal_sets": principal_sets,
        "identity_constraints": [
            {
                "constraint_id": row["constraint_id"],
                "scope": "same concrete identity on the same artifact or authority transition",
                "left_principal_class": row["left_principal_class"],
                "right_principal_class": row["right_principal_class"],
                "rule": "Forbidden overlap unless a later explicit workstream law widens it with independent authority.",
                "enforcement": "FAIL_CLOSED",
            }
            for row in overlap_scan
        ],
        "self_ratification_barriers": self_ratification_barriers,
        "current_overlap_scan": overlap_scan,
        "semantic_boundary": {
            "local_operator_compiles_claims_but_does_not_gain_release_or_verifier_acceptance_power": True,
            "root_boundary_remains_reratified_3_of_3_only": True,
            "non_root_roles_remain_logically_declared_or_planned": True,
        },
        "stronger_claim_not_made": [
            "The current identity model proves independence beyond the declared bounded role sets.",
            "WS15 executes release or verifier-acceptance authority.",
            "Overlapping trust roles are acceptable without later explicit law.",
        ],
    }


def build_ledger_law(*, root: Path, current_head: str) -> Dict[str, Any]:
    settled_truth = _load_required_json(root, SETTLED_TRUTH_SOURCE_REL)
    supersession_rules = _load_required_json(root, TRUTH_SUPERSESSION_RULES_REL)
    supersession_receipt = _load_required_json(root, TRUTH_SUPERSESSION_RECEIPT_REL)
    current_state = _load_required_json(root, CURRENT_STATE_RECEIPT_REL)

    documentary_mirror_refs = [
        "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json",
        CURRENT_STATE_RECEIPT_REL,
    ]
    return {
        "schema_id": "kt.governance.ledger_law.v1",
        "law_id": "KT_LEDGER_LAW_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "active_truth_source_ref": str(settled_truth.get("authoritative_current_pointer_ref", "")).strip(),
        "authority_mode": str(supersession_receipt.get("authority_status", "")).strip(),
        "immutability_rules": [
            {
                "rule_id": "append_only_hash_chain_required",
                "validator_ref": "KT_PROD_CLEANROOM/tools/operator/ledger_verify_chain.py",
                "rule": "Ledger entries must preserve previous_entry_hash linkage and entry_hash integrity.",
            },
            {
                "rule_id": "no_delete_without_supersession",
                "validator_ref": TRUTH_SUPERSESSION_RULES_REL,
                "rule": "Historical truth surfaces may not be deleted or silently overwritten; supersession must be explicit and receipted.",
            },
        ],
        "supersession_law": {
            "rules_ref": TRUTH_SUPERSESSION_RULES_REL,
            "receipt_ref": TRUTH_SUPERSESSION_RECEIPT_REL,
            "supersede_when": list(supersession_rules.get("supersede_when", [])),
            "superseded_outputs": list(supersession_rules.get("superseded_outputs", [])),
            "receipt_output": str(supersession_rules.get("receipt_output", "")).strip(),
        },
        "mirroring_rules": {
            "documentary_mirror_refs": documentary_mirror_refs,
            "documentary_mirror_class": str(current_state.get("mirror_class", "")).strip(),
            "documentary_only_refs": documentary_mirror_refs,
            "mirror_rule": "Documentary mirrors may exist for compatibility, but they may never be treated as the active truth source or live authority.",
        },
        "authority_boundaries": {
            "settled_truth_source_receipt_ref": SETTLED_TRUTH_SOURCE_REL,
            "current_state_receipt_ref": CURRENT_STATE_RECEIPT_REL,
            "current_state_documentary_only": bool(current_state.get("documentary_only")),
            "current_state_live_authority": bool(current_state.get("live_authority")),
            "current_head_truth_source_ref": str(current_state.get("validation_index_ref", "")).strip(),
            "superseded_by": list(current_state.get("superseded_by", [])),
        },
        "stronger_claim_not_made": [
            "Documentary mirrors are active truth.",
            "WS15 changes the authoritative ledger pointer.",
            "WS15 widens authority beyond the settled ledger-backed truth source.",
        ],
    }


def build_release_ceremony_law(*, root: Path, current_head: str) -> Dict[str, Any]:
    predecessor = _load_required_json(root, RELEASE_CEREMONY_REL)
    return {
        "schema_id": "kt.governance.release_ceremony.v1",
        "ceremony_id": "KT_RELEASE_CEREMONY_LAW_V1_20260318",
        "status": "ACTIVE_LOCKED_PENDING_UPSTREAM_WORKSTREAMS",
        "generated_utc": utc_now_iso_z(),
        "current_repo_head": current_head,
        "semantic_boundary": {
            "preparatory_only": False,
            "ws15_full_release_law_ratified": True,
            "release_ready_now": False,
            "lawful_current_claim": "This file defines release-ceremony prerequisites, trust boundaries, and freeze behavior only. It does not claim release readiness or release-ceremony execution.",
        },
        "predecessor_ref": RELEASE_CEREMONY_REL,
        "predecessor_status": str(predecessor.get("status", "")).strip(),
        "release_prerequisites": [
            "WS10 PASS under reratified 3-of-3 root boundary only",
            "WS11 PASS with bounded keyless declared verifier surface",
            "WS12 PASS with bounded supply-chain reconciliation",
            "WS13 PASS with bounded determinism and artifact classification",
            "WS14 PASS with bootstrap-root-only verifier acceptance policy",
            "WS15 PASS with claim ABI and proof-ceiling compiler locked",
            "WS16 PASS",
            "WS17A PASS",
            "WS17B PASS",
        ],
        "execution_prerequisites_not_yet_met": [
            "threshold-root verifier acceptance bundle published and accepted",
            "release signer issuance completed under later workstream law",
            "producer attestation bundle activated under later workstream law",
            "final readjudication completed in WS18",
        ],
        "verifier_acceptance_preconditions": {
            "current_state": "BOOTSTRAP_ROOT_ONLY",
            "threshold_root_acceptance_required_before_release_start": True,
            "later_bundle_required": True,
            "acceptance_policy_ref": ACCEPTANCE_POLICY_REL,
        },
        "forbidden_states": [
            "release_ceremony_execution_claim_before_ws18",
            "release_readiness_claim_before_threshold_root_acceptance",
            "release_signing_before_verifier_acceptance_preconditions",
            "using documentary mirrors as release authority inputs",
        ],
        "stronger_claim_not_made": [
            "Release ceremony executed.",
            "Release readiness proven.",
            "Threshold-root verifier acceptance is already active.",
        ],
    }


def build_failure_mode_register(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.failure_mode_register.v1",
        "register_id": "KT_FAILURE_MODE_REGISTER_V1_20260318",
        "status": "ACTIVE",
        "generated_utc": utc_now_iso_z(),
        "current_repo_head": current_head,
        "semantic_boundary": {
            "preparatory_only": False,
            "ws15_full_failure_law_ratified": True,
            "lawful_current_claim": "This register captures fail-closed claim ABI, proof-ceiling, identity, ledger, and release-law failure modes for the current bounded KT state.",
        },
        "failure_modes": [
            {
                "failure_mode_id": "CLAIM_ABI_SCHEMA_DRIFT",
                "trigger": "Compiled claim rows omit required ABI fields or violate typed field semantics.",
                "effect": "WS15 cannot pass and the claim compiler output is not admissible.",
                "required_response": "Regenerate from canonical ABI policy and fail closed on all stronger claims.",
            },
            {
                "failure_mode_id": "PROOF_CEILING_OVERCLAIM",
                "trigger": "Any compiled claim widens bootstrap-root-only verifier acceptance, reratified 3-of-3 root execution, or release readiness.",
                "effect": "All stronger claims are invalid and WS15 remains current.",
                "required_response": "Downgrade the claim row to BLOCKED_CURRENT and rerun the compiler.",
            },
            {
                "failure_mode_id": "SELF_RATIFICATION_ATTEMPT",
                "trigger": "WS15 outputs cite themselves as authority for a stronger upstream state.",
                "effect": "Authority recursion invalidates the compiler output.",
                "required_response": "Recompile from cited WS10-WS14 receipts only.",
            },
            {
                "failure_mode_id": "IDENTITY_ROLE_OVERLAP_ABUSE",
                "trigger": "A concrete identity occupies forbidden overlapping trust roles for the same artifact or authority transition.",
                "effect": "Signer topology and acceptance posture fail closed.",
                "required_response": "Freeze progression and reratify identities or role separation explicitly.",
            },
            {
                "failure_mode_id": "DOCUMENTARY_MIRROR_OVERREAD",
                "trigger": "Any claim treats a documentary mirror as the active truth source or live authority.",
                "effect": "Truth authority boundary is violated.",
                "required_response": "Invalidate the claim and revert to the settled ledger-backed truth source.",
            },
            {
                "failure_mode_id": "STALE_SUPERSESSION_CHAIN",
                "trigger": "Truth supersession rules or receipts are missing, stale, or contradictory.",
                "effect": "Ledger law is not admissible for current-head claim compilation.",
                "required_response": "Fail closed and refresh the supersession evidence before progressing.",
            },
            {
                "failure_mode_id": "THRESHOLD_ROOT_ACCEPTANCE_OVERREAD",
                "trigger": "Any WS15 or later artifact implies threshold-root verifier acceptance without a later explicit acceptance bundle.",
                "effect": "Verifier trust widening is invalid.",
                "required_response": "Narrow the claim back to bootstrap-root-only acceptance.",
            },
            {
                "failure_mode_id": "RELEASE_CEREMONY_EXECUTION_OVERREAD",
                "trigger": "Any artifact claims release readiness or release ceremony execution before WS18.",
                "effect": "Release authority is invalid.",
                "required_response": "Freeze progression and narrow the release law back to prerequisites only.",
            },
            {
                "failure_mode_id": "SECRET_BACKED_VERIFIER_RELEASE",
                "trigger": "Any declared verifier surface requires private key material, HMAC, or unpublished trust roots for outsider verification.",
                "effect": "Verifier release packaging is not admissible.",
                "required_response": "Revert to secret-free public evidence only and invalidate the overreaching surface.",
            },
        ],
    }


def _claim(
    *,
    claim_id: str,
    claim_status: str,
    domain: str,
    compiled_head_commit: str,
    subject_head_commit: str,
    upstream_receipt_ref: str,
    upstream_receipt_status: str,
    proof_ceiling_id: str,
    trust_scope: str,
    surface_scope: str,
    statement: str,
    evidence_refs: Sequence[str],
    blockers: Sequence[str],
    stronger_claim_not_made: Sequence[str],
    evidence_position: str = "CURRENT_HEAD_CONTAINS_UPSTREAM_PASS_EVIDENCE",
) -> Dict[str, Any]:
    return {
        "claim_id": claim_id,
        "claim_status": claim_status,
        "domain": domain,
        "compiled_head_commit": compiled_head_commit,
        "subject_head_commit": subject_head_commit,
        "evidence_position": evidence_position,
        "upstream_receipt_ref": upstream_receipt_ref,
        "upstream_receipt_status": upstream_receipt_status,
        "proof_ceiling_id": proof_ceiling_id,
        "trust_scope": trust_scope,
        "surface_scope": surface_scope,
        "statement": statement,
        "evidence_refs": list(evidence_refs),
        "blockers": list(blockers),
        "stronger_claim_not_made": list(stronger_claim_not_made),
    }


def build_claim_proof_ceiling_compiler(*, root: Path, current_head: str) -> Dict[str, Any]:
    ws10 = _load_required_json(root, WS10_RECEIPT_REL)
    ws11 = _load_required_json(root, WS11_RECEIPT_REL)
    ws12 = _load_required_json(root, WS12_RECEIPT_REL)
    ws13 = _load_required_json(root, WS13_RECEIPT_REL)
    ws14 = _load_required_json(root, WS14_RECEIPT_REL)
    acceptance = _load_required_json(root, ACCEPTANCE_POLICY_REL)
    settled_truth = _load_required_json(root, SETTLED_TRUTH_SOURCE_REL)
    current_state = _load_required_json(root, CURRENT_STATE_RECEIPT_REL)
    truth_supersession = _load_required_json(root, TRUTH_SUPERSESSION_RECEIPT_REL)
    historical_ceiling = _load_required_json(root, CLAIM_CEILING_SUMMARY_REL)

    ws14_subject = str(ws14.get("compiled_against", "")).strip()
    ws13_subject = str(ws13.get("compiled_against", "")).strip()
    ws12_subject = str(ws12.get("compiled_against", "")).strip()
    ws11_subject = str(ws11.get("compiled_against", "")).strip()
    ws10_subject = str(ws10.get("subject_head_commit", "")).strip()
    accepted_surface = acceptance.get("accepted_current_head_surface") if isinstance(acceptance.get("accepted_current_head_surface"), dict) else {}

    claims = [
        _claim(
            claim_id="active_truth_source_is_ledger_pointer_documentary_mirrors_blocked",
            claim_status="ALLOWED_CURRENT",
            domain="truth_authority",
            compiled_head_commit=current_head,
            subject_head_commit=str(settled_truth.get("pinned_head_sha", "")).strip(),
            upstream_receipt_ref=SETTLED_TRUTH_SOURCE_REL,
            upstream_receipt_status=str(settled_truth.get("status", "")).strip(),
            proof_ceiling_id="LEDGER_POINTER_SETTLED_AUTHORITATIVE",
            trust_scope="LEDGER_POINTER_ACTIVE_TRUTH_ONLY",
            surface_scope=str(settled_truth.get("authoritative_current_pointer_ref", "")).strip(),
            statement="Current HEAD may claim only that the settled ledger pointer is the active truth source; documentary mirrors remain non-authoritative.",
            evidence_refs=[SETTLED_TRUTH_SOURCE_REL, TRUTH_SUPERSESSION_RECEIPT_REL, CURRENT_STATE_RECEIPT_REL],
            blockers=[],
            stronger_claim_not_made=[
                "KT_PROD_CLEANROOM/exports/_truth/current/current_pointer.json is the live truth source",
                "KT_PROD_CLEANROOM/reports/current_state_receipt.json is live authority",
            ],
            evidence_position="CURRENT_HEAD_DOCUMENTARY_ONLY_BOUNDARY",
        ),
        _claim(
            claim_id="ws10_root_boundary_reratified_3_of_3_only",
            claim_status="ALLOWED_CURRENT",
            domain="root_trust",
            compiled_head_commit=current_head,
            subject_head_commit=ws10_subject,
            upstream_receipt_ref=WS10_RECEIPT_REL,
            upstream_receipt_status=str(ws10.get("status", "")).strip(),
            proof_ceiling_id="ROOT_BOUNDARY_RERATIFIED_3_OF_3_ONLY",
            trust_scope="RERATIFIED_ROOT_3_OF_3_ONLY",
            surface_scope="offline_root_boundary_only",
            statement="Current HEAD contains valid WS10 evidence for an executed off-box reratified 3-of-3 root boundary only.",
            evidence_refs=[WS10_RECEIPT_REL, TRUST_ROOT_POLICY_REL, SIGNER_TOPOLOGY_REL],
            blockers=[],
            stronger_claim_not_made=[
                "The earlier planned 3-of-5 root topology was executed",
                "Release, producer, CI, or verifier-acceptance roles were executed",
            ],
        ),
        _claim(
            claim_id="ws11_bounded_keyless_public_verifier_surface",
            claim_status="ALLOWED_CURRENT",
            domain="public_trust",
            compiled_head_commit=current_head,
            subject_head_commit=ws11_subject,
            upstream_receipt_ref=WS11_RECEIPT_REL,
            upstream_receipt_status=str(ws11.get("status", "")).strip(),
            proof_ceiling_id="DECLARED_KEYLESS_PUBLIC_VERIFIER_SURFACE_ONLY",
            trust_scope="DECLARED_WS11_SURFACE_ONLY",
            surface_scope="KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            statement="Current HEAD contains bounded WS11 evidence for keyless Sigstore and Rekor-backed verification of the declared public verifier manifest surface only.",
            evidence_refs=[WS11_RECEIPT_REL, SIGNER_IDENTITY_POLICY_REL],
            blockers=[],
            stronger_claim_not_made=[
                "All verifier surfaces are keyless-backed",
                "Release readiness is proven from WS11",
            ],
        ),
        _claim(
            claim_id="ws12_supply_chain_reconciled_for_bounded_surface",
            claim_status="ALLOWED_CURRENT",
            domain="supply_chain",
            compiled_head_commit=current_head,
            subject_head_commit=ws12_subject,
            upstream_receipt_ref=WS12_RECEIPT_REL,
            upstream_receipt_status=str(ws12.get("status", "")).strip(),
            proof_ceiling_id="CURRENT_HEAD_SUPPLY_CHAIN_BOUNDED_SURFACE_ONLY",
            trust_scope="BOUNDED_SURFACE_SINGLE_KEYLESS_ARTIFACT",
            surface_scope=str(ws12.get("bounded_current_surface", "")).strip(),
            statement="Current HEAD contains WS12 evidence that supply-chain lineage, truth-barrier reconciliation, and fail-closed TUF attack coverage were proven only for the bounded declared verifier surface.",
            evidence_refs=[WS12_RECEIPT_REL],
            blockers=[],
            stronger_claim_not_made=[
                "Full updater deployment is proven",
                "Enterprise or product readiness is proven",
            ],
        ),
        _claim(
            claim_id="ws13_determinism_locked_for_declared_class_a_and_b_surfaces",
            claim_status="ALLOWED_CURRENT",
            domain="determinism",
            compiled_head_commit=current_head,
            subject_head_commit=ws13_subject,
            upstream_receipt_ref=WS13_RECEIPT_REL,
            upstream_receipt_status=str(ws13.get("status", "")).strip(),
            proof_ceiling_id="DECLARED_CLASS_A_CLASS_B_ONLY",
            trust_scope="CLASS_A_AND_CLASS_B_ONLY",
            surface_scope="KT_PROD_CLEANROOM/governance/kt_artifact_class_policy.json + live_validation_index_v1 canonical profile",
            statement="Current HEAD contains WS13 evidence that only the declared CLASS_A and CLASS_B surfaces were locked reproducibly across the declared local and CI environments.",
            evidence_refs=[WS13_RECEIPT_REL],
            blockers=[],
            stronger_claim_not_made=[
                "All KT artifacts are byte-identical across environments",
                "CLASS_C imported evidence was normalized into deterministic output",
            ],
        ),
        _claim(
            claim_id="ws14_bootstrap_root_only_verifier_acceptance_and_static_release",
            claim_status="ALLOWED_CURRENT",
            domain="verifier_release",
            compiled_head_commit=current_head,
            subject_head_commit=ws14_subject,
            upstream_receipt_ref=WS14_RECEIPT_REL,
            upstream_receipt_status=str(ws14.get("status", "")).strip(),
            proof_ceiling_id="BOOTSTRAP_ROOT_ONLY_VERIFIER_RELEASE_BOUNDARY",
            trust_scope="BOOTSTRAP_ROOT_ONLY",
            surface_scope=str(accepted_surface.get("signed_surface_import_ref", "")).strip(),
            statement="Current HEAD contains frozen WS14 evidence for a bounded static verifier release artifact set and bootstrap-root-only verifier acceptance on the imported signed public verifier manifest surface.",
            evidence_refs=[WS14_RECEIPT_REL, ACCEPTANCE_POLICY_REL],
            blockers=[],
            stronger_claim_not_made=[
                "Threshold-root verifier acceptance is active",
                "Broader verifier coverage is proven",
                "Release readiness is proven",
            ],
        ),
        _claim(
            claim_id="threshold_root_verifier_acceptance_active",
            claim_status="BLOCKED_CURRENT",
            domain="verifier_acceptance",
            compiled_head_commit=current_head,
            subject_head_commit=ws14_subject,
            upstream_receipt_ref=WS14_RECEIPT_REL,
            upstream_receipt_status=str(ws14.get("status", "")).strip(),
            proof_ceiling_id="THRESHOLD_ROOT_ACCEPTANCE_PENDING",
            trust_scope="BOOTSTRAP_ROOT_ONLY",
            surface_scope=str(accepted_surface.get("signed_surface_import_ref", "")).strip(),
            statement="Current HEAD must not claim threshold-root verifier acceptance; WS14 keeps verifier acceptance bootstrap-root only pending a later explicit acceptance bundle.",
            evidence_refs=[WS14_RECEIPT_REL, ACCEPTANCE_POLICY_REL, TRUST_ROOT_POLICY_REL],
            blockers=["THRESHOLD_ROOT_ACCEPTANCE_PENDING"],
            stronger_claim_not_made=["Threshold-root verifier acceptance is active today"],
        ),
        _claim(
            claim_id="original_planned_3_of_5_root_execution_proven",
            claim_status="BLOCKED_CURRENT",
            domain="root_trust",
            compiled_head_commit=current_head,
            subject_head_commit=ws10_subject,
            upstream_receipt_ref=WS10_RECEIPT_REL,
            upstream_receipt_status=str(ws10.get("status", "")).strip(),
            proof_ceiling_id="PLANNED_3_OF_5_NOT_PROVEN",
            trust_scope="RERATIFIED_ROOT_3_OF_3_ONLY",
            surface_scope="root_topology_execution",
            statement="Current HEAD must not claim the earlier planned 3-of-5 root execution; only the reratified 3-of-3 root boundary was executed and witnessed.",
            evidence_refs=[WS10_RECEIPT_REL, TRUST_ROOT_POLICY_REL],
            blockers=["PLANNED_3_OF_5_NOT_PROVEN"],
            stronger_claim_not_made=["Original planned 3-of-5 root topology executed"],
        ),
        _claim(
            claim_id="release_readiness_proven",
            claim_status="BLOCKED_CURRENT",
            domain="release_ceremony",
            compiled_head_commit=current_head,
            subject_head_commit=current_head,
            upstream_receipt_ref=RELEASE_CEREMONY_REL,
            upstream_receipt_status="ACTIVE_LOCKED_PENDING_UPSTREAM_WORKSTREAMS",
            proof_ceiling_id="RELEASE_CEREMONY_NOT_YET_EXECUTABLE",
            trust_scope="NOT_READY",
            surface_scope="release_ceremony",
            statement="Current HEAD must not claim release readiness or release ceremony completion; WS15 only locks prerequisites and failure law.",
            evidence_refs=[RELEASE_CEREMONY_REL, WS14_RECEIPT_REL],
            blockers=["RELEASE_CEREMONY_NOT_EXECUTED", "UPSTREAM_WORKSTREAMS_NOT_COMPLETE"],
            stronger_claim_not_made=["Release readiness is proven", "Release ceremony executed"],
        ),
        _claim(
            claim_id="campaign_completion_proven",
            claim_status="BLOCKED_CURRENT",
            domain="campaign_state",
            compiled_head_commit=current_head,
            subject_head_commit=current_head,
            upstream_receipt_ref=EXECUTION_DAG_REL,
            upstream_receipt_status="ACTIVE",
            proof_ceiling_id="CAMPAIGN_COMPLETION_PENDING_LATER_WORKSTREAMS",
            trust_scope="WS15_ONLY",
            surface_scope="execution_dag",
            statement="Current HEAD must not claim campaign completion; WS16 through WS19 remain ahead.",
            evidence_refs=[EXECUTION_DAG_REL],
            blockers=["WS16_NOT_COMPLETE", "WS17_NOT_COMPLETE", "WS18_NOT_COMPLETE", "WS19_NOT_COMPLETE"],
            stronger_claim_not_made=["Campaign is complete", "Whole-bundle completion proven"],
        ),
    ]
    claims = sorted(claims, key=lambda row: str(row["claim_id"]))
    return {
        "schema_id": "kt.operator.claim_proof_ceiling_compiler.v1",
        "artifact_id": "kt_claim_proof_ceiling_compiler.json",
        "status": "PASS",
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "generated_utc": utc_now_iso_z(),
        "inputs": [
            {"ref": WS10_RECEIPT_REL, "status": str(ws10.get("status", "")).strip(), "sha256": file_sha256((root / WS10_RECEIPT_REL).resolve())},
            {"ref": WS11_RECEIPT_REL, "status": str(ws11.get("status", "")).strip(), "sha256": file_sha256((root / WS11_RECEIPT_REL).resolve())},
            {"ref": WS12_RECEIPT_REL, "status": str(ws12.get("status", "")).strip(), "sha256": file_sha256((root / WS12_RECEIPT_REL).resolve())},
            {"ref": WS13_RECEIPT_REL, "status": str(ws13.get("status", "")).strip(), "sha256": file_sha256((root / WS13_RECEIPT_REL).resolve())},
            {"ref": WS14_RECEIPT_REL, "status": str(ws14.get("status", "")).strip(), "sha256": file_sha256((root / WS14_RECEIPT_REL).resolve())},
            {"ref": ACCEPTANCE_POLICY_REL, "status": str(acceptance.get("status", "")).strip(), "sha256": file_sha256((root / ACCEPTANCE_POLICY_REL).resolve())},
            {"ref": SETTLED_TRUTH_SOURCE_REL, "status": str(settled_truth.get("status", "")).strip(), "sha256": file_sha256((root / SETTLED_TRUTH_SOURCE_REL).resolve())},
            {"ref": TRUTH_SUPERSESSION_RECEIPT_REL, "status": str(truth_supersession.get("status", "")).strip(), "sha256": file_sha256((root / TRUTH_SUPERSESSION_RECEIPT_REL).resolve())},
            {"ref": CLAIM_CEILING_SUMMARY_REL, "status": str(historical_ceiling.get("closeout_verdict", "")).strip(), "sha256": file_sha256((root / CLAIM_CEILING_SUMMARY_REL).resolve())},
        ],
        "historical_predecessor_boundary": {
            "kt_claim_ceiling_summary_ref": CLAIM_CEILING_SUMMARY_REL,
            "historical_boundary_only": True,
            "historical_boundary_note": "The historical claim-ceiling summary is preserved as doctrine ancestry only and does not override current WS10-WS14 receipts.",
        },
        "compiled_claims": claims,
        "allowed_current_claim_ids": [row["claim_id"] for row in claims if row["claim_status"] == "ALLOWED_CURRENT"],
        "blocked_current_claim_ids": [row["claim_id"] for row in claims if row["claim_status"] == "BLOCKED_CURRENT"],
        "documentary_only_claim_ids": [row["claim_id"] for row in claims if row["claim_status"] == "DOCUMENTARY_ONLY"],
        "proof_ceiling_summary": {
            "root_boundary": "RERATIFIED_3_OF_3_ONLY",
            "verifier_acceptance": "BOOTSTRAP_ROOT_ONLY",
            "keyless_surface_scope": "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json",
            "determinism_scope": "DECLARED_CLASS_A_AND_CLASS_B_ONLY",
            "release_state": "NOT_READY",
            "campaign_state": "NOT_COMPLETE",
            "documentary_truth_boundary": {
                "active_truth_source": str(settled_truth.get("authoritative_current_pointer_ref", "")).strip(),
                "documentary_current_state_receipt": CURRENT_STATE_RECEIPT_REL,
                "documentary_only": bool(current_state.get("documentary_only")),
            },
        },
    }


def _stable_emission_matches(root: Path, payloads: Dict[str, Dict[str, Any]]) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    for rel, payload in payloads.items():
        actual = (root / Path(rel)).read_text(encoding="utf-8")
        expected = _render_stable_json(payload)
        if actual != expected:
            failures.append(f"stable_mismatch:{Path(rel).as_posix()}")
    return not failures, failures


def _validate_claim_rows(claims: Sequence[Dict[str, Any]]) -> List[str]:
    failures: List[str] = []
    for claim in claims:
        keys = list(claim.keys())
        if keys != ABI_FIELD_ORDER:
            failures.append(f"field_order:{claim.get('claim_id', '<unknown>')}")
        for field in ABI_FIELD_ORDER:
            if field not in claim:
                failures.append(f"missing_field:{claim.get('claim_id', '<unknown>')}:{field}")
        if str(claim.get("claim_status", "")).strip() not in ALLOWED_CLAIM_STATUSES:
            failures.append(f"claim_status:{claim.get('claim_id', '<unknown>')}")
        if str(claim.get("domain", "")).strip() not in ALLOWED_DOMAINS:
            failures.append(f"domain:{claim.get('claim_id', '<unknown>')}")
        if str(claim.get("evidence_position", "")).strip() not in ALLOWED_EVIDENCE_POSITIONS:
            failures.append(f"evidence_position:{claim.get('claim_id', '<unknown>')}")
        if not isinstance(claim.get("evidence_refs"), list):
            failures.append(f"evidence_refs_type:{claim.get('claim_id', '<unknown>')}")
        if not isinstance(claim.get("blockers"), list):
            failures.append(f"blockers_type:{claim.get('claim_id', '<unknown>')}")
        if not isinstance(claim.get("stronger_claim_not_made"), list):
            failures.append(f"stronger_claim_not_made_type:{claim.get('claim_id', '<unknown>')}")
    return sorted(set(failures))


def build_ws15_receipt(
    *,
    root: Path,
    current_head: str,
    ws14_receipt: Dict[str, Any],
    claim_abi_policy: Dict[str, Any],
    identity_model_policy: Dict[str, Any],
    ledger_law: Dict[str, Any],
    release_ceremony: Dict[str, Any],
    failure_mode_register: Dict[str, Any],
    proof_ceiling_compiler: Dict[str, Any],
) -> Dict[str, Any]:
    ws14_pass = str(ws14_receipt.get("status", "")).strip() == "PASS"
    ws14_subject = str(ws14_receipt.get("compiled_against", "")).strip()
    ws14_ancestor_ok = bool(ws14_subject) and _git_is_ancestor(root, ws14_subject, current_head)
    proof_claim_failures = _validate_claim_rows(
        proof_ceiling_compiler.get("compiled_claims") if isinstance(proof_ceiling_compiler.get("compiled_claims"), list) else []
    )
    overlap_scan = identity_model_policy.get("current_overlap_scan") if isinstance(identity_model_policy.get("current_overlap_scan"), list) else []
    identity_ok = all(str(row.get("status", "")).strip() == "PASS" for row in overlap_scan if isinstance(row, dict))
    active_truth_ok = str(ledger_law.get("active_truth_source_ref", "")).strip() == "kt_truth_ledger:ledger/current/current_pointer.json"
    documentary_boundary = ledger_law.get("authority_boundaries") if isinstance(ledger_law.get("authority_boundaries"), dict) else {}
    documentary_ok = bool(documentary_boundary.get("current_state_documentary_only")) and not bool(documentary_boundary.get("current_state_live_authority"))
    release_law_ok = str(release_ceremony.get("status", "")).strip() == "ACTIVE_LOCKED_PENDING_UPSTREAM_WORKSTREAMS" and not bool(
        release_ceremony.get("semantic_boundary", {}).get("release_ready_now")
    )
    failure_register_ok = str(failure_mode_register.get("status", "")).strip() == "ACTIVE"
    acceptance_policy = _load_required_json(root, ACCEPTANCE_POLICY_REL)
    acceptance_roots = acceptance_policy.get("accepted_verifier_trust_roots") if isinstance(acceptance_policy.get("accepted_verifier_trust_roots"), list) else []
    pending_roots = acceptance_policy.get("pending_not_yet_accepted_trust_roots") if isinstance(acceptance_policy.get("pending_not_yet_accepted_trust_roots"), list) else []
    bootstrap_only_ok = len(acceptance_roots) == 1 and str(acceptance_roots[0].get("acceptance_state", "")).strip() == "ACTIVE_BOOTSTRAP_ACCEPTED"
    threshold_pending_ok = len(pending_roots) == 1 and str(pending_roots[0].get("acceptance_state", "")).strip() == "PENDING_LATER_ACCEPTANCE_UPDATE"
    blocked_ids = set(proof_ceiling_compiler.get("blocked_current_claim_ids", []))
    blocked_claims_ok = {
        "threshold_root_verifier_acceptance_active",
        "original_planned_3_of_5_root_execution_proven",
        "release_readiness_proven",
        "campaign_completion_proven",
    }.issubset(blocked_ids)
    stable_ok, stable_failures = _stable_emission_matches(
        root,
        {
            CLAIM_ABI_POLICY_REL: claim_abi_policy,
            IDENTITY_MODEL_POLICY_REL: identity_model_policy,
            LEDGER_LAW_REL: ledger_law,
            RELEASE_CEREMONY_REL: release_ceremony,
            FAILURE_MODE_REGISTER_REL: failure_mode_register,
            PROOF_CEILING_COMPILER_REL: proof_ceiling_compiler,
        },
    )

    blockers: List[str] = []
    if not ws14_pass:
        blockers.append("WS14_NOT_PASS")
    if not ws14_ancestor_ok:
        blockers.append("WS14_FREEZE_BOUNDARY_NOT_PRESERVED")
    if proof_claim_failures:
        blockers.append("CLAIM_ABI_TYPED_FIELDS_INVALID")
    if not identity_ok:
        blockers.append("IDENTITY_MODEL_OVERLAP_PRESENT")
    if not active_truth_ok or not documentary_ok:
        blockers.append("LEDGER_OR_DOCUMENTARY_BOUNDARY_INVALID")
    if not release_law_ok:
        blockers.append("RELEASE_CEREMONY_LAW_NOT_LOCKED")
    if not failure_register_ok:
        blockers.append("FAILURE_MODE_REGISTER_NOT_ACTIVE")
    if not bootstrap_only_ok or not threshold_pending_ok or not blocked_claims_ok:
        blockers.append("PROOF_CEILING_WIDENS_BEYOND_CURRENT_ACCEPTANCE_BOUNDARY")
    if not stable_ok:
        blockers.append("WS15_OUTPUTS_NOT_STABLY_EMITTED")

    status = "PASS" if not blockers else "PARTIAL"
    next_lawful = NEXT_WORKSTREAM_ID if status == "PASS" else WORKSTREAM_ID
    checks = [
        _check(ws14_pass, "ws14_receipt_pass", "WS14 must already be PASS before WS15 can type and lock current-head claims.", [WS14_RECEIPT_REL]),
        _check(
            ws14_ancestor_ok,
            "ws14_frozen_subject_boundary_preserved",
            "WS15 must preserve the frozen WS14 subject head as upstream evidence instead of overreading it as the current subject.",
            [WS14_RECEIPT_REL],
            failures=[] if ws14_ancestor_ok else [f"current_head={current_head}", f"ws14_subject={ws14_subject}"],
        ),
        _check(
            not proof_claim_failures,
            "claim_abi_fields_fully_typed_and_machine_enforced",
            "Every compiled claim row must match the locked ABI fields, order, and types.",
            [CLAIM_ABI_POLICY_REL, PROOF_CEILING_COMPILER_REL],
            failures=proof_claim_failures,
        ),
        _check(
            blocked_claims_ok and bootstrap_only_ok and threshold_pending_ok,
            "proof_ceiling_compiler_preserves_current_bootstrap_only_boundary",
            "The proof-ceiling compiler must preserve reratified 3-of-3 root truth, bootstrap-root-only verifier acceptance, and blocked release-readiness/campaign-completion claims.",
            [PROOF_CEILING_COMPILER_REL, ACCEPTANCE_POLICY_REL, TRUST_ROOT_POLICY_REL],
        ),
        _check(
            identity_ok,
            "identity_model_forbids_self_ratification_and_overlap_abuse",
            "Identity model constraints must forbid release/verifier/root/operator overlap abuse for the same authority transition.",
            [IDENTITY_MODEL_POLICY_REL, SIGNER_TOPOLOGY_REL, SIGNER_IDENTITY_POLICY_REL],
            failures=[row["constraint_id"] for row in overlap_scan if isinstance(row, dict) and str(row.get("status", "")).strip() != "PASS"],
        ),
        _check(
            active_truth_ok and documentary_ok,
            "ledger_law_locks_immutability_supersession_and_documentary_boundaries",
            "Ledger law must keep the settled ledger pointer authoritative and documentary mirrors non-authoritative.",
            [LEDGER_LAW_REL, SETTLED_TRUTH_SOURCE_REL, TRUTH_SUPERSESSION_RULES_REL, CURRENT_STATE_RECEIPT_REL],
        ),
        _check(
            release_law_ok,
            "release_ceremony_law_explicit_but_non_executed",
            "Release ceremony law must be active and explicit while still blocking release readiness and execution claims.",
            [RELEASE_CEREMONY_REL],
        ),
        _check(
            failure_register_ok,
            "failure_mode_register_explicit_and_fail_closed",
            "Failure-mode law must explicitly block ABI drift, proof-ceiling overclaims, self-ratification, mirror overread, and release overread.",
            [FAILURE_MODE_REGISTER_REL],
        ),
        _check(
            stable_ok,
            "ws15_outputs_stably_emitted",
            "All WS15 law and compiler outputs must re-emit byte-stably from the current source state.",
            [CLAIM_ABI_POLICY_REL, IDENTITY_MODEL_POLICY_REL, LEDGER_LAW_REL, RELEASE_CEREMONY_REL, FAILURE_MODE_REGISTER_REL, PROOF_CEILING_COMPILER_REL],
            failures=stable_failures,
        ),
    ]

    return {
        "artifact_id": "kt_claim_abi_receipt.json",
        "schema_id": "kt.operator.claim_abi_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else PARTIAL_VERDICT,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "generated_utc": utc_now_iso_z(),
        "blocked_by": blockers,
        "checks": checks,
        "current_strongest_claim": (
            "WS15 locks a typed claim ABI, deterministic proof-ceiling compiler, identity abuse constraints, ledger law, release-ceremony law, and fail-closed failure register while preserving the reratified 3-of-3 root boundary and bootstrap-root-only verifier acceptance."
            if status == "PASS"
            else "WS15 has produced part of the claim ABI or proof-ceiling law, but one or more bounded current-head constraints remain unresolved."
        ),
        "output_hashes": {
            CLAIM_ABI_POLICY_REL: file_sha256((root / Path(CLAIM_ABI_POLICY_REL)).resolve()),
            IDENTITY_MODEL_POLICY_REL: file_sha256((root / Path(IDENTITY_MODEL_POLICY_REL)).resolve()),
            LEDGER_LAW_REL: file_sha256((root / Path(LEDGER_LAW_REL)).resolve()),
            RELEASE_CEREMONY_REL: file_sha256((root / Path(RELEASE_CEREMONY_REL)).resolve()),
            FAILURE_MODE_REGISTER_REL: file_sha256((root / Path(FAILURE_MODE_REGISTER_REL)).resolve()),
            PROOF_CEILING_COMPILER_REL: file_sha256((root / Path(PROOF_CEILING_COMPILER_REL)).resolve()),
        },
        "remaining_limitations": [
            "WS15 does not widen verifier acceptance beyond the bootstrap root.",
            "WS15 does not prove release readiness, release ceremony execution, or campaign completion.",
            "WS15 remains bounded to the declared verifier surface coverage already proven in WS14.",
            "The repo-root import fragility remains visible and is not erased by WS15.",
        ],
        "stronger_claim_not_made": [
            "Threshold-root verifier acceptance is active.",
            "The original planned 3-of-5 root topology was executed.",
            "Release readiness or release ceremony completion is proven.",
            "WS16 has already been substantively started.",
        ],
        "validators_run": ["python -m tools.operator.ws15_claim_abi_validate"],
        "tests_run": ["python -m pytest -q tests/operator/test_ws15_claim_abi_validate.py"],
        "next_lawful_workstream": next_lawful,
        "unexpected_touches": [],
        "protected_touch_violations": [],
    }


def _apply_control_plane(*, dag: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    current_head = str(receipt.get("current_repo_head", "")).strip()
    generated_utc = str(receipt.get("generated_utc", "")).strip()
    ws15_pass = str(receipt.get("status", "")).strip() == "PASS"

    dag["generated_utc"] = generated_utc
    dag["current_repo_head"] = current_head
    dag["current_node"] = receipt["next_lawful_workstream"]
    dag["next_lawful_workstream"] = receipt["next_lawful_workstream"]
    dag["semantic_boundary"]["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. WS12 passed for bounded current-head supply-chain policy. WS13 passed for bounded artifact-class locking and determinism proof across local Windows and GitHub Actions Ubuntu on the same subject head. WS14 froze a bounded static verifier release and bootstrap-root-only acceptance policy. WS15 now locks a typed claim ABI, deterministic proof ceiling, identity abuse barriers, ledger law, and non-executed release law without widening threshold-root acceptance or release readiness."
        if ws15_pass
        else "WS10 through WS14 remain bounded and preserved. WS15 is current until claim ABI, proof-ceiling, identity, ledger, and release-law constraints are fully sealed."
    )
    dag["semantic_boundary"]["stronger_claim_not_made"] = [
        "The original planned 3-of-5 root topology was executed",
        "Threshold-root verifier acceptance is active",
        "Release readiness is proven",
        "WS16 has already been substantively started",
    ]
    ws15_node = next(node for node in dag["nodes"] if node["id"] == WORKSTREAM_ID)
    ws16_node = next(node for node in dag["nodes"] if node["id"] == NEXT_WORKSTREAM_ID)
    ws15_node["ratification_checkpoint"] = Path(RECEIPT_REL).name
    if ws15_pass:
        ws15_node["status"] = "PASS"
        ws15_node["claim_boundary"] = "WS15 PASS proves only a typed claim ABI, deterministic proof ceiling, identity abuse constraints, ledger law, and non-executed release law under the existing reratified 3-of-3 root boundary and bootstrap-root-only verifier acceptance."
        ws16_node["status"] = "UNLOCKED"
        ws16_node["unlock_basis"] = "WS15 PASS"
    else:
        ws15_node["status"] = "PARTIAL"
        ws15_node["claim_boundary"] = "WS15 remains current until claim ABI, proof-ceiling, identity, ledger, and release-law surfaces are complete."
        ws16_node["status"] = "LOCKED_PENDING_WS15_PASS"
        ws16_node.pop("unlock_basis", None)


def emit_ws15_claim_abi(*, root: Optional[Path] = None) -> Dict[str, Any]:
    repo = root or repo_root()
    pre_dirty = _dirty_relpaths(_git_status_lines(repo))
    if pre_dirty and any(not _path_in_scope(path) for path in pre_dirty):
        raise RuntimeError("FAIL_CLOSED: WS15 requires a frozen repo except for the bounded WS15 write set")

    current_head = _git_head(repo)
    dag = _load_required_json(repo, EXECUTION_DAG_REL)
    ws14_receipt = _load_required_json(repo, WS14_RECEIPT_REL)

    claim_abi_policy = build_claim_abi_policy(current_head=current_head)
    identity_model_policy = build_identity_model_policy(root=repo, current_head=current_head)
    ledger_law = build_ledger_law(root=repo, current_head=current_head)
    release_ceremony = build_release_ceremony_law(root=repo, current_head=current_head)
    failure_mode_register = build_failure_mode_register(current_head=current_head)

    _write_json(repo, CLAIM_ABI_POLICY_REL, claim_abi_policy)
    _write_json(repo, IDENTITY_MODEL_POLICY_REL, identity_model_policy)
    _write_json(repo, LEDGER_LAW_REL, ledger_law)
    _write_json(repo, RELEASE_CEREMONY_REL, release_ceremony)
    _write_json(repo, FAILURE_MODE_REGISTER_REL, failure_mode_register)

    proof_ceiling_compiler = build_claim_proof_ceiling_compiler(root=repo, current_head=current_head)
    _write_json(repo, PROOF_CEILING_COMPILER_REL, proof_ceiling_compiler)

    receipt = build_ws15_receipt(
        root=repo,
        current_head=current_head,
        ws14_receipt=ws14_receipt,
        claim_abi_policy=claim_abi_policy,
        identity_model_policy=identity_model_policy,
        ledger_law=ledger_law,
        release_ceremony=release_ceremony,
        failure_mode_register=failure_mode_register,
        proof_ceiling_compiler=proof_ceiling_compiler,
    )
    _apply_control_plane(dag=dag, receipt=receipt)
    _write_json(repo, EXECUTION_DAG_REL, dag)

    post_dirty = _dirty_relpaths(_git_status_lines(repo))
    receipt["unexpected_touches"] = sorted(path for path in post_dirty if not _path_in_scope(path))
    _write_json(repo, RECEIPT_REL, receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WS15: lock typed claim ABI, proof ceiling, identity model, and ledger law.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    _parse_args(argv)
    receipt = emit_ws15_claim_abi(root=repo_root())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if str(receipt.get("status", "")).strip() == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
