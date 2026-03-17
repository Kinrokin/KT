from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence


WORKSTREAM_ID = "WS10_AIR_GAPPED_ROOT_CEREMONY_AND_SIGNER_TOPOLOGY"
PRIMARY_EXPECTED_ARTIFACTS = [
    "KT_PROD_CLEANROOM/governance/kt_trust_root_policy.json",
    "KT_PROD_CLEANROOM/governance/kt_signer_topology.json",
    "KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json",
]
ALLOWED_TOUCHES = {
    "KT_PROD_CLEANROOM/tools/operator/root_ceremony_prepare.py",
    "KT_PROD_CLEANROOM/tests/operator/test_root_ceremony_prepare.py",
    "KT_PROD_CLEANROOM/governance/kt_trust_root_policy.json",
    "KT_PROD_CLEANROOM/governance/kt_signer_topology.json",
    "KT_PROD_CLEANROOM/governance/kt_execution_dag.json",
    "KT_PROD_CLEANROOM/governance/kt_release_ceremony.json",
    "KT_PROD_CLEANROOM/governance/kt_failure_mode_register.json",
    "KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json",
}
ROOT_SIGNER_IDS = [
    "KT_ROOT_SHARD_A",
    "KT_ROOT_SHARD_B",
    "KT_ROOT_SHARD_C",
    "KT_ROOT_SHARD_D",
    "KT_ROOT_SHARD_E",
]
RELEASE_SIGNER_IDS = [
    "KT_RELEASE_SIGNER_A",
    "KT_RELEASE_SIGNER_B",
    "KT_RELEASE_SIGNER_C",
]
PRODUCER_SIGNER_IDS = [
    "KT_PRODUCER_SIGNER_A",
    "KT_PRODUCER_SIGNER_B",
    "KT_PRODUCER_SIGNER_C",
]
CI_SIGNER_IDS = [
    "KT_CI_SIGNER_A",
    "KT_CI_SIGNER_B",
]
VERIFIER_SIGNER_IDS = [
    "KT_VERIFIER_ACCEPTANCE_A",
    "KT_VERIFIER_ACCEPTANCE_B",
]
OFFBOX_BLOCKERS = [
    "OFFBOX_AIR_GAPPED_CEREMONY_NOT_PERFORMED",
    "ROOT_KEY_MATERIAL_NOT_GENERATED_OFFLINE",
    "ROOT_SHARD_CUSTODY_NOT_WITNESSED",
    "SIGNER_QUORUM_NOT_WITNESSED",
    "OFFLINE_VERIFICATION_NOT_EXECUTED",
]
TRUST_ASSUMPTIONS_REMAINING = [
    "Connected development environment cannot stand in for an air-gapped ceremony.",
    "Signer identities are logical placeholders until off-box issuance and custody evidence exist.",
    "Verifier acceptance remains anchored to the closure-foundation bootstrap root until WS10 PASS and WS11 activation.",
    "No Sigstore/Rekor public transparency upgrade is claimed in WS10 preparation.",
]
FORBIDDEN_CLAIMS = [
    "Air-gapped root ceremony executed",
    "Offline root key material generated on this connected development host",
    "Root shard custody or signer presence proven",
    "WS11 Sigstore/Rekor activation completed",
    "External or hardware-backed verification completed",
]
OUT_OF_SCOPE_ATTACK_CLASSES = [
    "physical_hardware_tampering",
    "offbox_operator_collusion",
    "hardware_supply_chain_forensics",
    "sigstore_rekor_rollout",
    "external_assurance_confirmation",
]
WHAT_IS_NOT_PROVEN = [
    "Root generation or rotation on an air-gapped host",
    "Shard custody, signer presence, or quorum achievement",
    "Offline verification of generated root metadata",
    "Public-key trust activation beyond the closure-foundation bootstrap boundary",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_git(root: Path, args: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            text=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return completed.stdout.strip()


def _git_head(root: Path) -> str:
    return _run_git(root, ["rev-parse", "HEAD"]) or "UNKNOWN_HEAD"


def _git_status_paths(root: Path) -> List[str]:
    output = _run_git(root, ["status", "--short"])
    if not output:
        return []
    paths: List[str] = []
    for line in output.splitlines():
        raw = line[3:].strip()
        if " -> " in raw:
            raw = raw.split(" -> ", 1)[1].strip()
        paths.append(raw.replace("\\", "/"))
    return paths


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _relative(path: Path, root: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _planned_identity_map() -> List[Dict[str, Any]]:
    identities: List[Dict[str, Any]] = []
    for signer_id in ROOT_SIGNER_IDS:
        identities.append(
            {
                "identity_id": signer_id,
                "role_id": "root",
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                "custody_class": "offline_hardware_token",
                "storage_rule": "dual_control_secure_storage",
            }
        )
    for signer_id in RELEASE_SIGNER_IDS:
        identities.append(
            {
                "identity_id": signer_id,
                "role_id": "release",
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                "custody_class": "hardware_backed_signing_station",
                "storage_rule": "release_offline_when_idle",
            }
        )
    for signer_id in PRODUCER_SIGNER_IDS:
        identities.append(
            {
                "identity_id": signer_id,
                "role_id": "producer",
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                "custody_class": "attested_build_identity",
                "storage_rule": "ephemeral_bound_to_attested_runner",
            }
        )
    for signer_id in CI_SIGNER_IDS:
        identities.append(
            {
                "identity_id": signer_id,
                "role_id": "ci",
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                "custody_class": "attested_ci_oidc_identity",
                "storage_rule": "short_lived_token_only",
            }
        )
    for signer_id in VERIFIER_SIGNER_IDS:
        identities.append(
            {
                "identity_id": signer_id,
                "role_id": "verifier_acceptance",
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                "custody_class": "offline_verifier_maintainer",
                "storage_rule": "offline_acceptance_bundle",
            }
        )
    return identities


def _unexpected_touches(root: Path) -> List[str]:
    return sorted(path for path in _git_status_paths(root) if path not in ALLOWED_TOUCHES)


def _protected_touch_violations(root: Path) -> List[str]:
    violations: List[str] = []
    for path in _git_status_paths(root):
        if path in ALLOWED_TOUCHES:
            continue
        if path.startswith("KT_PROD_CLEANROOM/"):
            violations.append(path)
    return sorted(violations)


def _load_ws9_context(root: Path) -> Dict[str, Any]:
    kt_root = root / "KT_PROD_CLEANROOM"
    truth_source = _load_json(kt_root / "reports/kt_current_head_truth_source.json")
    ws9_receipt = _load_json(kt_root / "reports/kt_authority_and_published_head_closure_receipt.json")
    if ws9_receipt.get("status") != "PASS":
        raise RuntimeError("FAIL_CLOSED: WS9 receipt must be PASS before WS10 preparation.")
    foundation_policy = _load_json(kt_root / "governance/closure_foundation/kt_tuf_root_policy.json")
    signer_identity_policy = _load_json(kt_root / "governance/signer_identity_policy.json")
    supply_chain_layout = _load_json(kt_root / "governance/supply_chain_layout.json")
    return {
        "truth_source": truth_source,
        "ws9_receipt": ws9_receipt,
        "foundation_policy": foundation_policy,
        "signer_identity_policy": signer_identity_policy,
        "supply_chain_layout": supply_chain_layout,
    }


def build_trust_root_policy(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    context = _load_ws9_context(root)
    truth_source = context["truth_source"]
    foundation_policy = context["foundation_policy"]
    return {
        "schema_id": "kt.governance.trust_root_policy.v1",
        "policy_id": "KT_SOVEREIGN_TRUST_ROOT_POLICY_V1_20260317",
        "status": "PREPARED_NOT_EXECUTED",
        "generated_utc": generated_utc,
        "current_repo_head": _git_head(root),
        "ws9_truth_source_ref": "KT_PROD_CLEANROOM/reports/kt_current_head_truth_source.json",
        "predecessor_policy_ref": "KT_PROD_CLEANROOM/governance/closure_foundation/kt_tuf_root_policy.json",
        "semantic_boundary": {
            "air_gapped_ceremony_executed": False,
            "offline_root_material_present": False,
            "release_signer_material_present": False,
            "verifier_acceptance_upgraded": False,
            "lawful_current_claim": "Prepared policy only. No off-box air-gapped ceremony or offline key generation is claimed.",
        },
        "closure_boundary": {
            "preparatory_only": True,
            "requires_offbox_execution_for_pass": True,
            "next_required_step": WORKSTREAM_ID,
        },
        "inheritance": {
            "foundation_trust_root_id": foundation_policy["root_of_trust"]["trust_root_id"],
            "foundation_bootstrap_state": foundation_policy["root_of_trust"]["bootstrap_state"],
            "foundation_threshold": foundation_policy["root_of_trust"]["threshold"],
            "subject_head_commit": truth_source["truth_subject_commit"],
            "evidence_head_commit": truth_source["evidence_head_commit"],
        },
        "forbidden_states": [
            "connected_host_root_generation_labeled_air_gapped",
            "unsigned_root_metadata_acceptance",
            "quorum_claim_without_witnessed_offline_signers",
            "ws11_transparency_claim_before_activation",
        ],
        "invariants": [
            "Root material for WS10 PASS must be generated or rotated only on an off-box air-gapped host.",
            "Root quorum cannot be claimed without witnessed shard custody and offline verification evidence.",
            "Verifier acceptance must remain on the predecessor bootstrap root until a PASS receipt supersedes it.",
            "Signer topology may be planned on a connected host, but issuance state must remain PREPARED_NOT_EXECUTED.",
        ],
        "planned_root_topology": {
            "target_trust_root_id": "KT_SOVEREIGN_ROOT_TARGET_20260317",
            "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            "root_threshold": 3,
            "root_signer_count": 5,
            "planned_root_signers": [
                {
                    "identity_id": signer_id,
                    "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
                    "custody_class": "offline_hardware_token",
                    "witness_requirement": "dual_witness_required",
                }
                for signer_id in ROOT_SIGNER_IDS
            ],
        },
        "root_ceremony_procedure": {
            "execution_mode_required": "OFFBOX_AIR_GAPPED_ONLY",
            "steps": [
                {
                    "step_id": "prepare_materials",
                    "status": "PREPARED",
                    "description": "Stage blank hardware, printed checklist, sealed custody packets, and bootstrap trust references without generating any private material on a connected host.",
                },
                {
                    "step_id": "air_gapped_generate_or_rotate_root",
                    "status": "PENDING_OFFBOX_EXECUTION",
                    "description": "Generate or rotate root shards on the isolated host and record witness identities plus hardware serials.",
                },
                {
                    "step_id": "offline_verify_threshold_metadata",
                    "status": "PENDING_OFFBOX_EXECUTION",
                    "description": "Verify root metadata offline before any export of public material.",
                },
                {
                    "step_id": "record_custody_and_storage",
                    "status": "PENDING_OFFBOX_EXECUTION",
                    "description": "Seal shard custody packets, storage locations, and emergency rotation activation instructions.",
                },
            ],
            "evidence_required_for_pass": [
                "witnessed ceremony log signed offline",
                "hardware inventory and custody log",
                "root metadata verification transcript",
                "exported public trust bundle only",
            ],
        },
        "quorum_threshold_rules": [
            {
                "role_id": "root",
                "threshold": 3,
                "signer_count": 5,
                "claim_boundary": "No root quorum claim before witnessed off-box execution.",
            },
            {
                "role_id": "release",
                "threshold": 2,
                "signer_count": 3,
                "claim_boundary": "Release signing remains planned only until later workstreams activate issuance and verifier acceptance.",
            },
            {
                "role_id": "producer",
                "threshold": 2,
                "signer_count": 3,
                "claim_boundary": "Producer attestations remain future-state and cannot be implied by WS10 preparation.",
            },
            {
                "role_id": "ci",
                "threshold": 1,
                "signer_count": 2,
                "claim_boundary": "CI identity binding is planned but not activated.",
            },
            {
                "role_id": "verifier_acceptance",
                "threshold": 1,
                "signer_count": 2,
                "claim_boundary": "Verifier acceptance policy stays on predecessor root until a later acceptance update.",
            },
        ],
        "custody_and_storage_rules": {
            "root_shards": [
                "Store only on offline hardware tokens approved for the ceremony.",
                "Require dual-control secure storage with sealed custody evidence.",
                "Never copy private root material to connected development machines.",
            ],
            "release_and_verifier_material": [
                "Keep release and verifier acceptance material offline when idle.",
                "Permit only public references and logical identifiers in connected planning artifacts.",
            ],
        },
        "emergency_rotation_path": {
            "triggers": [
                "suspected_root_compromise",
                "custody_breach",
                "witness_dispute",
                "hardware_failure",
            ],
            "required_actions": [
                "freeze downstream workstreams",
                "convene new air-gapped ceremony",
                "revoke affected identities",
                "reissue root metadata and verifier acceptance bundle",
            ],
        },
        "verifier_acceptance_impact": {
            "current_acceptance_state": "BOOTSTRAP_ROOT_ONLY",
            "post_pass_target_state": "THRESHOLD_ROOT_ACCEPTANCE_PENDING_WS11_AND_WS14",
            "current_boundary": "No verifier acceptance widening is lawful from WS10 preparation alone.",
        },
    }


def build_signer_topology(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    return {
        "schema_id": "kt.governance.signer_topology.v1",
        "topology_id": "KT_SOVEREIGN_SIGNER_TOPOLOGY_V1_20260317",
        "status": "PREPARED_NOT_EXECUTED",
        "generated_utc": generated_utc,
        "current_repo_head": _git_head(root),
        "root_policy_ref": "KT_PROD_CLEANROOM/governance/kt_trust_root_policy.json",
        "signer_identity_policy_ref": "KT_PROD_CLEANROOM/governance/signer_identity_policy.json",
        "supply_chain_layout_ref": "KT_PROD_CLEANROOM/governance/supply_chain_layout.json",
        "semantic_boundary": {
            "identities_are_logical_only": True,
            "offline_issuance_complete": False,
            "quorum_witnessed": False,
            "lawful_current_claim": "Topology planned only. No signer presence, root material issuance, or quorum completion is claimed.",
        },
        "role_identity_map": _planned_identity_map(),
        "roles": [
            {
                "role_id": "root",
                "purpose": "Offline trust-root ratification and emergency recovery.",
                "threshold": 3,
                "signer_count": 5,
                "planned_identity_ids": ROOT_SIGNER_IDS,
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            },
            {
                "role_id": "release",
                "purpose": "Approve release bundles after verifier acceptance and ceremony prerequisites pass.",
                "threshold": 2,
                "signer_count": 3,
                "planned_identity_ids": RELEASE_SIGNER_IDS,
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            },
            {
                "role_id": "producer",
                "purpose": "Attest approved build or artifact production surfaces.",
                "threshold": 2,
                "signer_count": 3,
                "planned_identity_ids": PRODUCER_SIGNER_IDS,
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            },
            {
                "role_id": "ci",
                "purpose": "Bind automated pipeline identities under later Sigstore/TUF policy.",
                "threshold": 1,
                "signer_count": 2,
                "planned_identity_ids": CI_SIGNER_IDS,
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            },
            {
                "role_id": "verifier_acceptance",
                "purpose": "Approve verifier trust-root updates and revocations.",
                "threshold": 1,
                "signer_count": 2,
                "planned_identity_ids": VERIFIER_SIGNER_IDS,
                "issuance_state": "PLANNED_PENDING_OFFBOX_CEREMONY",
            },
        ],
        "quorum_rules": [
            {
                "role_id": "root",
                "quorum_statement": "3 of 5 offline root shards required for trust-root updates.",
            },
            {
                "role_id": "release",
                "quorum_statement": "2 of 3 release maintainers required for release approval.",
            },
            {
                "role_id": "producer",
                "quorum_statement": "2 of 3 producer identities required for artifact promotion.",
            },
            {
                "role_id": "ci",
                "quorum_statement": "1 of 2 attested CI identities required for automated publication support.",
            },
            {
                "role_id": "verifier_acceptance",
                "quorum_statement": "1 of 2 verifier maintainers required to publish an updated acceptance bundle.",
            },
        ],
        "custody_and_storage_rules": {
            "root": "Offline hardware tokens only, dual-control storage, witness-signed custody chain.",
            "release": "Hardware-backed signing stations; offline when idle; no shared credentials.",
            "producer": "Ephemeral identities bound to attested build systems only after later activation.",
            "ci": "Short-lived OIDC or equivalent attestable identities only after WS11.",
            "verifier_acceptance": "Offline acceptance bundles; no private verifier trust secrets on connected hosts.",
        },
        "emergency_rotation_path": {
            "freeze_condition": "Any root or release identity compromise freezes WS11+ immediately.",
            "recovery_sequence": [
                "freeze downstream workstreams",
                "invoke root ceremony again offline",
                "reissue trust metadata",
                "publish revocation and acceptance update",
            ],
        },
        "verifier_acceptance_impact": {
            "pre_ws10_pass": "Verifier continues to trust only the predecessor bootstrap root and current bounded receipts.",
            "post_ws10_pass": "Verifier may consume an updated threshold-backed root only after explicit acceptance-policy workstreams complete.",
        },
        "release_ceremony_dependency_update": {
            "release_ceremony_ref": "KT_PROD_CLEANROOM/governance/kt_release_ceremony.json",
            "new_blocking_dependency": "WS10 receipt must be PASS before any release ceremony can start.",
        },
        "failure_mode_register_ref": "KT_PROD_CLEANROOM/governance/kt_failure_mode_register.json",
        "execution_dag_ref": "KT_PROD_CLEANROOM/governance/kt_execution_dag.json",
    }


def build_execution_dag(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    return {
        "schema_id": "kt.governance.execution_dag.v1",
        "dag_id": "KT_SOVEREIGN_EXECUTION_DAG_V1_20260317",
        "status": "ACTIVE",
        "generated_utc": generated_utc,
        "current_repo_head": _git_head(root),
        "current_node": WORKSTREAM_ID,
        "no_progress_without_proof": True,
        "semantic_boundary": {
            "ws9_frozen_locally": True,
            "ws10_pass_required_before_ws11": True,
            "lawful_current_claim": "WS10 preparation is active; WS11+ remain locked pending a PASS root ceremony receipt.",
        },
        "nodes": [
            {
                "id": "WS9_AUTHORITY_AND_PUBLISHED_HEAD_CLOSURE",
                "depends_on": [],
                "ratification_checkpoint": "kt_authority_and_published_head_closure_receipt.json",
                "status": "LOCAL_CHECKPOINT_COMPLETE",
            },
            {
                "id": WORKSTREAM_ID,
                "depends_on": ["WS9_AUTHORITY_AND_PUBLISHED_HEAD_CLOSURE"],
                "ratification_checkpoint": "kt_root_ceremony_receipt.json",
                "status": "PREPARED_NOT_EXECUTED",
                "advance_requires": OFFBOX_BLOCKERS,
            },
            {
                "id": "WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION",
                "depends_on": [WORKSTREAM_ID],
                "ratification_checkpoint": "kt_sigstore_integration_receipt.json",
                "status": "LOCKED_PENDING_WS10_PASS",
            },
            {
                "id": "WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE",
                "depends_on": ["WS11_SIGSTORE_REKOR_AND_LOG_MONITOR_ACTIVATION"],
                "ratification_checkpoint": "kt_supply_chain_policy_receipt.json",
                "status": "LOCKED_PENDING_WS11_PASS",
            },
            {
                "id": "WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK",
                "depends_on": ["WS12_IN_TOTO_SLSA_AND_TUF_ATTACK_COVERAGE"],
                "ratification_checkpoint": "kt_determinism_envelope_receipt.json",
                "status": "LOCKED_PENDING_WS12_PASS",
            },
            {
                "id": "WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY",
                "depends_on": ["WS13_ARTIFACT_CLASS_AND_DETERMINISM_ENVELOPE_LOCK"],
                "ratification_checkpoint": "kt_public_verifier_release_receipt.json",
                "status": "LOCKED_PENDING_WS13_PASS",
            },
            {
                "id": "WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW",
                "depends_on": ["WS14_STATIC_VERIFIER_RELEASE_AND_ACCEPTANCE_POLICY"],
                "ratification_checkpoint": "claim_abi_receipt",
                "status": "LOCKED_PENDING_WS14_PASS",
            },
            {
                "id": "WS16_TRUST_ASSUMPTIONS_TEVV_DATASET_PINNING_AND_COMPARATOR_REGISTRY",
                "depends_on": ["WS15_CLAIM_ABI_PROOF_CEILING_IDENTITY_AND_LEDGER_LAW"],
                "ratification_checkpoint": "tevv_and_benchmark_receipt",
                "status": "LOCKED_PENDING_WS15_PASS",
            },
            {
                "id": "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE",
                "depends_on": ["WS16_TRUST_ASSUMPTIONS_TEVV_DATASET_PINNING_AND_COMPARATOR_REGISTRY"],
                "ratification_checkpoint": "external_assurance_receipt",
                "status": "LOCKED_PENDING_WS16_PASS",
            },
            {
                "id": "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY",
                "depends_on": ["WS16_TRUST_ASSUMPTIONS_TEVV_DATASET_PINNING_AND_COMPARATOR_REGISTRY"],
                "ratification_checkpoint": "external_capability_receipt",
                "status": "LOCKED_PENDING_WS16_PASS",
            },
            {
                "id": "WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION",
                "depends_on": ["WS17A_EXTERNAL_CONFIRMATION_ASSURANCE", "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY"],
                "ratification_checkpoint": "final_readjudication_receipt",
                "status": "LOCKED_PENDING_WS17_PASS",
            },
            {
                "id": "WS19_PRODUCT_SURFACE_AND_LICENSE_TRACK",
                "depends_on": ["WS18_RELEASE_CEREMONY_AND_FINAL_READJUDICATION"],
                "ratification_checkpoint": "product_surface_receipt",
                "status": "LOCKED_PENDING_WS18_PASS",
            },
        ],
    }


def build_release_ceremony(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    return {
        "schema_id": "kt.governance.release_ceremony.v0",
        "ceremony_id": "KT_RELEASE_CEREMONY_PREP_V0_20260317",
        "status": "PREPARED_NOT_EXECUTED",
        "generated_utc": generated_utc,
        "current_repo_head": _git_head(root),
        "semantic_boundary": {
            "preparatory_only": True,
            "ws15_full_release_law_ratified": False,
            "lawful_current_claim": "This file records WS10 dependency updates only; it is not a final release-ceremony law.",
        },
        "dependency_updates": {
            "new_ws10_dependency": "kt_root_ceremony_receipt.json status PASS",
            "release_prerequisites": [
                "WS10 PASS",
                "WS11 PASS",
                "WS12 PASS",
                "WS13 PASS",
                "WS14 PASS",
                "WS15 PASS",
                "WS16 PASS",
                "WS17A PASS",
                "WS17B PASS",
            ],
            "verifier_acceptance_prerequisites": [
                "threshold-backed root accepted",
                "revocation path documented",
                "verifier acceptance policy released",
            ],
        },
    }


def build_failure_mode_register(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    return {
        "schema_id": "kt.governance.failure_mode_register.v0",
        "register_id": "KT_FAILURE_MODE_REGISTER_PREP_V0_20260317",
        "status": "PREPARED_NOT_EXECUTED",
        "generated_utc": generated_utc,
        "current_repo_head": _git_head(root),
        "semantic_boundary": {
            "preparatory_only": True,
            "ws15_full_failure_law_ratified": False,
            "lawful_current_claim": "This register captures WS10 failure modes that must block progression until off-box ceremony evidence exists.",
        },
        "failure_modes": [
            {
                "failure_mode_id": "CONNECTED_ENV_ROOT_GENERATION_CLAIM",
                "trigger": "Any root material allegedly generated on a connected development host.",
                "effect": "Immediate invalidation of WS10 PASS claims.",
                "required_response": "Discard material, emit failure receipt, restart on approved off-box system.",
            },
            {
                "failure_mode_id": "CEREMONY_CLAIM_WITHOUT_EVIDENCE",
                "trigger": "Receipt or narrative claims ceremony execution without witnessable off-box evidence.",
                "effect": "Stop progression and mark receipt invalid.",
                "required_response": "Revert to PREPARED_NOT_EXECUTED and document the claim narrowing.",
            },
            {
                "failure_mode_id": "ROOT_SHARD_CUSTODY_GAP",
                "trigger": "Shard custody or storage cannot be independently enumerated.",
                "effect": "Root cannot be accepted for verifier trust.",
                "required_response": "Freeze downstream workstreams and rerun ceremony.",
            },
            {
                "failure_mode_id": "QUORUM_MISREPRESENTATION",
                "trigger": "Threshold claim made without recorded signer presence and witness confirmation.",
                "effect": "Signer topology acceptance fails closed.",
                "required_response": "Invalidate receipt and require fresh off-box execution.",
            },
            {
                "failure_mode_id": "PREMATURE_WS11_WIDENING",
                "trigger": "Any WS11/Sigstore/Rekor claim appears in WS10-prepared artifacts.",
                "effect": "Scope violation and claim contamination.",
                "required_response": "Block advancement and narrow claims back to WS10 preparation only.",
            },
        ],
    }


def build_root_ceremony_receipt(root: Path, *, generated_utc: str | None = None) -> Dict[str, Any]:
    generated_utc = generated_utc or _utcnow()
    context = _load_ws9_context(root)
    truth_source = context["truth_source"]
    unexpected_touches = _unexpected_touches(root)
    protected_touch_violations = _protected_touch_violations(root)
    created_files = sorted(
        path
        for path in ALLOWED_TOUCHES
        if path.endswith(".json") and not path.startswith("KT_PROD_CLEANROOM/tools/") and not path.startswith("KT_PROD_CLEANROOM/tests/")
    )
    return {
        "schema_id": "kt.operator.root_ceremony_receipt.v1",
        "workstream_id": WORKSTREAM_ID,
        "status": "PREPARED_NOT_EXECUTED",
        "pass_verdict": "CEREMONY_READY_PENDING_OFFBOX_EXECUTION",
        "subject_head_commit": truth_source["truth_subject_commit"],
        "evidence_head_commit": truth_source["evidence_head_commit"],
        "current_repo_head": _git_head(root),
        "compiled_against": _git_head(root),
        "generated_utc": generated_utc,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "validators_run": [
            "root_ceremony_prepare::ws9_receipt_precondition",
            "root_ceremony_prepare::allowed_touch_set_guard",
            "root_ceremony_prepare::prepared_only_claim_boundary",
        ],
        "tests_run": [
            "tests/operator/test_root_ceremony_prepare.py",
        ],
        "trust_assumptions_remaining": TRUST_ASSUMPTIONS_REMAINING,
        "upgrade_events": [
            "WS10_PREPARATION_ARTIFACTS_EMITTED",
        ],
        "downgrade_events": [],
        "signer_topology_snapshot": {
            "root_threshold": "3-of-5 planned pending off-box ceremony",
            "release_threshold": "2-of-3 planned pending off-box ceremony",
            "producer_threshold": "2-of-3 planned pending off-box ceremony",
            "ci_threshold": "1-of-2 planned pending off-box ceremony",
            "verifier_acceptance_threshold": "1-of-2 planned pending off-box ceremony",
        },
        "verification_predicate_versions": {
            "trust_root_policy": "kt.governance.trust_root_policy.v1",
            "signer_topology": "kt.governance.signer_topology.v1",
            "execution_dag": "kt.governance.execution_dag.v1",
            "release_ceremony": "kt.governance.release_ceremony.v0",
            "failure_mode_register": "kt.governance.failure_mode_register.v0",
        },
        "current_strongest_claim": "WS10 preparation is complete locally. Root ceremony law, topology, custody rules, and gating updates are prepared, but no off-box air-gapped execution is claimed.",
        "stronger_claim_not_made": WHAT_IS_NOT_PROVEN,
        "forbidden_claims": FORBIDDEN_CLAIMS,
        "out_of_scope_attack_classes": OUT_OF_SCOPE_ATTACK_CLASSES,
        "created_files": created_files,
        "deleted_files": [],
        "temporary_files_removed": [],
        "superseded_files_removed_or_demoted": [],
        "waste_control": {
            "files_touched": sorted(ALLOWED_TOUCHES),
            "expected_artifacts_for_this_workstream_only": PRIMARY_EXPECTED_ARTIFACTS,
            "receipt_family_for_this_workstream_only": [
                "KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json"
            ],
            "mutation_scope": "WS10_PREPARATION_ONLY",
        },
        "next_lawful_workstream": WORKSTREAM_ID,
        "blocked_by": OFFBOX_BLOCKERS,
        "blocker_evidence_refs": [
            "KT_PROD_CLEANROOM/governance/kt_trust_root_policy.json",
            "KT_PROD_CLEANROOM/governance/kt_signer_topology.json",
            "KT_PROD_CLEANROOM/governance/kt_execution_dag.json",
            "KT_PROD_CLEANROOM/governance/kt_release_ceremony.json",
            "KT_PROD_CLEANROOM/governance/kt_failure_mode_register.json",
            "KT_PROD_CLEANROOM/reports/kt_authority_and_published_head_closure_receipt.json",
        ],
        "what_is_not_proven": WHAT_IS_NOT_PROVEN,
        "ws10_extension": {
            "ceremony_status": "CEREMONY_READY_PENDING_OFFBOX_EXECUTION",
            "execution_evidence_present": False,
            "expected_primary_artifacts": PRIMARY_EXPECTED_ARTIFACTS,
            "prepared_supporting_artifacts": [
                "KT_PROD_CLEANROOM/governance/kt_execution_dag.json",
                "KT_PROD_CLEANROOM/governance/kt_release_ceremony.json",
                "KT_PROD_CLEANROOM/governance/kt_failure_mode_register.json",
            ],
        },
    }


def emit_ws10_preparation(root: Path) -> Dict[str, Dict[str, Any]]:
    generated_utc = _utcnow()
    kt_root = root / "KT_PROD_CLEANROOM"
    payloads = {
        _relative(kt_root / "governance/kt_trust_root_policy.json", root): build_trust_root_policy(root, generated_utc=generated_utc),
        _relative(kt_root / "governance/kt_signer_topology.json", root): build_signer_topology(root, generated_utc=generated_utc),
        _relative(kt_root / "governance/kt_execution_dag.json", root): build_execution_dag(root, generated_utc=generated_utc),
        _relative(kt_root / "governance/kt_release_ceremony.json", root): build_release_ceremony(root, generated_utc=generated_utc),
        _relative(kt_root / "governance/kt_failure_mode_register.json", root): build_failure_mode_register(root, generated_utc=generated_utc),
    }
    for relative_path, payload in payloads.items():
        _write_json(root / relative_path, payload)
    receipt = build_root_ceremony_receipt(root, generated_utc=generated_utc)
    receipt_rel = "KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json"
    _write_json(root / receipt_rel, receipt)
    payloads[receipt_rel] = receipt
    return payloads


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare bounded WS10 root-ceremony artifacts without claiming off-box execution.")
    parser.add_argument("--root", default=str(_repo_root()))
    args = parser.parse_args()
    emit_ws10_preparation(Path(args.root).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
