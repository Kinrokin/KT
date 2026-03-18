from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


WORKSTREAM_ID = "WS16_TRUST_ASSUMPTIONS_TEVV_DATASET_PINNING_AND_COMPARATOR_REGISTRY"
STEP_ID = "WS16_STEP_1_LOCK_TEVV_PACK_DATASET_PINS_AND_COMPARATORS"
PASS_VERDICT = "TRUST_ASSUMPTIONS_TEVV_DATASET_AND_COMPARATORS_LOCKED"
PARTIAL_VERDICT = "TRUST_ASSUMPTIONS_TEVV_OR_COMPARATOR_INCOMPLETE"
NEXT_WORKSTREAM_ID = "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE"

REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
GOVERNANCE_ROOT_REL = "KT_PROD_CLEANROOM/governance"

EXECUTION_DAG_REL = f"{GOVERNANCE_ROOT_REL}/kt_execution_dag.json"
WS13_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_determinism_envelope_receipt.json"
WS14_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_public_verifier_release_receipt.json"
WS15_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_claim_abi_receipt.json"
CLAIM_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_claim_proof_ceiling_compiler.json"
TRUTH_FRESHNESS_WINDOWS_REL = f"{GOVERNANCE_ROOT_REL}/truth_freshness_windows.json"
DETERMINISM_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_determinism_envelope_policy.json"
REPLAY_RECIPE_REL = f"{REPORT_ROOT_REL}/kt_independent_replay_recipe.md"

LOCAL_LIVE_INDEX_REL = f"{REPORT_ROOT_REL}/ws13_determinism/local/live_validation_index.local.json"
CI_LIVE_INDEX_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/live_validation_index.ci.json"
LOCAL_SUBJECT_SET_REL = f"{REPORT_ROOT_REL}/ws13_determinism/local/kt_determinism_subject_set.json"
CI_SUBJECT_SET_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/kt_determinism_subject_set.json"
CI_SIGNED_SURFACE_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/public_verifier_manifest.json"
CI_SIGSTORE_BUNDLE_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/public_verifier_manifest.sigstore.json"
CI_KEYLESS_RECEIPT_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/kt_ws11_keyless_execution_receipt.json"
CI_REMOTE_DIAGNOSTIC_REL = f"{REPORT_ROOT_REL}/ws13_determinism/ci/kt_truth_barrier_remote_diagnostic.json"

TRUST_ASSUMPTIONS_REL = f"{GOVERNANCE_ROOT_REL}/kt_trust_assumptions_register.json"
TRUTH_ASSUMPTIONS_REL = TRUST_ASSUMPTIONS_REL
TEVV_PACK_POLICY_REL = f"{GOVERNANCE_ROOT_REL}/kt_tevv_pack_policy.json"
DATASET_PIN_REGISTRY_REL = f"{GOVERNANCE_ROOT_REL}/kt_dataset_pin_registry.json"
COMPARATOR_REGISTRY_REL = f"{GOVERNANCE_ROOT_REL}/kt_comparator_registry.json"
BENCHMARK_VALIDITY_WINDOWS_REL = f"{GOVERNANCE_ROOT_REL}/kt_benchmark_validity_windows.json"

TEVV_PACK_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_tevv_pack_manifest.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_tevv_dataset_registry_receipt.json"

PLANNED_MUTATES = [
    TRUST_ASSUMPTIONS_REL,
    TEVV_PACK_POLICY_REL,
    DATASET_PIN_REGISTRY_REL,
    COMPARATOR_REGISTRY_REL,
    BENCHMARK_VALIDITY_WINDOWS_REL,
    TEVV_PACK_MANIFEST_REL,
    RECEIPT_REL,
    EXECUTION_DAG_REL,
    "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_ws16_tevv_dataset_comparator_validate.py",
]

TRUST_ASSUMPTION_FIELDS = [
    "assumption_id",
    "assumption_class",
    "bounded_scope",
    "dependency_kind",
    "statement",
    "evidence_refs",
    "validator_refs",
    "failure_if_false",
    "fail_closed_if_false",
    "stronger_claim_not_made",
]

REQUIRED_BLOCKED_CLAIMS = [
    "threshold_root_verifier_acceptance_active",
    "release_readiness_proven",
    "campaign_completion_proven",
]

REQUIRED_COMPARATOR_IDS = [
    "sha256_exact_file_match_v1",
    "live_validation_index_canonical_equivalence_v1",
    "subject_head_equality_v1",
    "sigstore_bundle_surface_binding_v1",
    "freshness_window_fail_closed_v1",
    "worst_case_pack_status_v1",
]


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
        raise RuntimeError(f"FAIL_CLOSED: missing required WS16 input: {rel}")
    return load_json(path)


def _read_text_required(root: Path, rel: str) -> str:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required WS16 input: {rel}")
    return path.read_text(encoding="utf-8")


def _write_json(root: Path, rel: str, payload: Dict[str, Any]) -> None:
    write_json_stable((root / Path(rel)).resolve(), payload, volatile_keys=())


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


def _parse_iso_z(value: str) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def _hours_old(value: str) -> float:
    return max(0.0, (datetime.now(timezone.utc) - _parse_iso_z(value)).total_seconds() / 3600.0)


def _path_sha_row(root: Path, rel: str) -> Dict[str, Any]:
    return {
        "path": rel,
        "sha256": file_sha256((root / Path(rel)).resolve()),
    }


def _subject_head_candidates(*objs: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    for obj in objs:
        for value in (
            obj.get("subject_head_commit"),
            obj.get("compiled_against"),
            obj.get("current_repo_head"),
            obj.get("worktree", {}).get("head_sha") if isinstance(obj.get("worktree"), dict) else None,
        ):
            text = str(value or "").strip()
            if text:
                candidates.append(text)
    return sorted(set(candidates))


def _dataset_row(*, dataset_id: str, dataset_class: str, rel: str, sha256: str, subject_head_commit: str, origin: str, comparator_ids: Sequence[str], replay_role: str) -> Dict[str, Any]:
    return {
        "dataset_id": dataset_id,
        "dataset_class": dataset_class,
        "path": rel,
        "sha256": sha256,
        "subject_head_commit": subject_head_commit,
        "origin": origin,
        "comparator_ids": list(comparator_ids),
        "replay_role": replay_role,
        "contains_private_material": False,
    }


def build_trust_assumptions_register(*, current_head: str, tevv_subject_head: str) -> Dict[str, Any]:
    assumptions = [
        {
            "assumption_id": "ASSUME_WS10_ROOT_BOUNDARY_RERATIFIED_3_OF_3_ONLY",
            "assumption_class": "ROOT_TRUST_BOUNDARY",
            "bounded_scope": "WS10 carry-forward root trust claim",
            "dependency_kind": "UPSTREAM_RECEIPT",
            "statement": "Current TEVV claims inherit only the reratified 3-of-3 root boundary and must not overread the earlier planned 3-of-5 topology as executed.",
            "evidence_refs": [
                "KT_PROD_CLEANROOM/reports/kt_root_ceremony_receipt.json",
                CLAIM_COMPILER_REL,
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because the trust root boundary would be overstated.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "The original planned 3-of-5 root execution is proven.",
            ],
        },
        {
            "assumption_id": "ASSUME_BOOTSTRAP_ROOT_ONLY_VERIFIER_ACCEPTANCE",
            "assumption_class": "VERIFIER_TRUST_BOUNDARY",
            "bounded_scope": "WS14 bounded verifier acceptance state",
            "dependency_kind": "UPSTREAM_POLICY",
            "statement": "Verifier acceptance remains bootstrap-root only, and WS16 does not activate threshold-root verifier acceptance.",
            "evidence_refs": [
                WS14_RECEIPT_REL,
                CLAIM_COMPILER_REL,
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because verifier trust would widen beyond the current proof ceiling.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "Threshold-root verifier acceptance is active.",
            ],
        },
        {
            "assumption_id": "ASSUME_DECLARED_LOCAL_AND_CI_ENVIRONMENTS_ONLY",
            "assumption_class": "ENVIRONMENT_BOUNDARY",
            "bounded_scope": "WS13 determinism and TEVV parity environments",
            "dependency_kind": "UPSTREAM_RECEIPT",
            "statement": f"TEVV parity is bounded to the declared local Windows and GitHub Actions Ubuntu environments on upstream subject head {tevv_subject_head}.",
            "evidence_refs": [
                WS13_RECEIPT_REL,
                "KT_PROD_CLEANROOM/reports/ws13_determinism/local/environment_probe.json",
                "KT_PROD_CLEANROOM/reports/ws13_determinism/ci/environment_probe.json",
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because local-vs-CI parity would no longer be scoped to proven environments.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "Any environment outside the declared WS13 envelope is automatically compatible.",
            ],
        },
        {
            "assumption_id": "ASSUME_KEYLESS_AND_REKOR_BIND_THE_DECLARED_WS11_SURFACE",
            "assumption_class": "PUBLIC_TRUST_DEPENDENCY",
            "bounded_scope": "Imported current bounded keyless verifier surface",
            "dependency_kind": "IMPORTED_EXTERNAL_EVIDENCE",
            "statement": "GitHub OIDC, Sigstore keyless signing, and Rekor inclusion remain bound to the declared public verifier manifest surface only.",
            "evidence_refs": [
                CI_KEYLESS_RECEIPT_REL,
                CI_REMOTE_DIAGNOSTIC_REL,
                CI_SIGNED_SURFACE_REL,
                CI_SIGSTORE_BUNDLE_REL,
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because the declared public-trust surface would lose its bounded signed evidence chain.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "All KT verifier surfaces are keyless-backed.",
            ],
        },
        {
            "assumption_id": "ASSUME_TEVV_PACK_IS_COMPLETE_ONLY_IF_LOCAL_AND_CI_ROWS_BOTH_EXIST",
            "assumption_class": "TEVV_COMPLETENESS",
            "bounded_scope": "WS16 TEVV pack completeness",
            "dependency_kind": "LOCAL_POLICY",
            "statement": "A WS16 TEVV pack is incomplete unless both local and CI truth-barrier rows, their subject sets, and the imported bounded keyless surface are all present and hash-bound.",
            "evidence_refs": [
                TEVV_PACK_POLICY_REL,
                DATASET_PIN_REGISTRY_REL,
                TEVV_PACK_MANIFEST_REL,
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because cherry-picked evidence would become admissible.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "A single surviving row is enough to certify the TEVV pack.",
            ],
        },
        {
            "assumption_id": "ASSUME_REPLAYABILITY_MUST_BE_DECLARED_AND_SECRET_FREE",
            "assumption_class": "REPLAYABILITY_BOUNDARY",
            "bounded_scope": "WS16 replayability requirements",
            "dependency_kind": "LOCAL_POLICY",
            "statement": "Replayability claims must stay bound to declared recipes, manifest verification, and secret-free public surfaces; replay claims do not erase the repo-root import fragility.",
            "evidence_refs": [
                REPLAY_RECIPE_REL,
                "KT_PROD_CLEANROOM/tools/verification/replay_manifest_verify.py",
                "KT_PROD_CLEANROOM/tools/operator/hermetic_replay_linter.py",
                "KT_PROD_CLEANROOM/tools/verification/fl4_replay_from_receipts.py",
            ],
            "validator_refs": [
                "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            ],
            "failure_if_false": "WS16 must fail closed because replayability would become ambiguous or secret-backed.",
            "fail_closed_if_false": True,
            "stronger_claim_not_made": [
                "The repo-root import fragility is fixed.",
                "Replayability alone proves external confirmation.",
            ],
        },
    ]
    return {
        "schema_id": "kt.governance.trust_assumptions_register.v1",
        "register_id": "KT_TRUST_ASSUMPTIONS_REGISTER_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "tevv_subject_head_commit": tevv_subject_head,
        "required_fields": list(TRUST_ASSUMPTION_FIELDS),
        "assumptions": assumptions,
        "stronger_claim_not_made": [
            "WS16 trust assumptions constitute external confirmation.",
            "WS16 widens trust or release boundaries beyond the prior proof ceiling.",
        ],
    }


def build_tevv_pack_policy(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.tevv_pack_policy.v1",
        "policy_id": "KT_TEVV_PACK_POLICY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "required_pack_fields": [
            "pack_id",
            "compiled_against",
            "tevv_subject_head_commit",
            "evidence_position",
            "dataset_pin_registry_ref",
            "comparator_registry_ref",
            "trust_assumptions_ref",
            "benchmark_validity_windows_ref",
            "components",
            "anti_cherry_picking_rules",
            "replayability_requirements",
            "stronger_claim_not_made",
        ],
        "required_components": [
            {"component_id": "local_truth_barrier_current_head", "required": True, "type": "CURRENT_HEAD_RUNTIME_EVIDENCE"},
            {"component_id": "ci_truth_barrier_current_head", "required": True, "type": "CURRENT_HEAD_RUNTIME_EVIDENCE"},
            {"component_id": "local_determinism_subject_set", "required": True, "type": "CANONICAL_SUBJECT_BINDING"},
            {"component_id": "ci_determinism_subject_set", "required": True, "type": "CANONICAL_SUBJECT_BINDING"},
            {"component_id": "bounded_keyless_signed_surface", "required": True, "type": "IMPORTED_CLASS_C_EVIDENCE"},
            {"component_id": "bounded_keyless_sigstore_bundle", "required": True, "type": "IMPORTED_CLASS_C_EVIDENCE"},
            {"component_id": "bounded_keyless_execution_receipt", "required": True, "type": "IMPORTED_CLASS_C_EVIDENCE"},
            {"component_id": "bounded_truth_barrier_remote_diagnostic", "required": True, "type": "IMPORTED_CLASS_C_EVIDENCE"},
            {"component_id": "claim_proof_ceiling_compiler", "required": True, "type": "CURRENT_HEAD_GOVERNANCE_EVIDENCE"},
            {"component_id": "independent_replay_recipe", "required": True, "type": "REPLAYABILITY_GUIDANCE"},
        ],
        "completeness_rules": [
            "All required components must be present and hash-bound before TEVV status may be PASS.",
            "Both local and CI truth-barrier rows must be included; neither may be omitted because of convenience or outcome.",
            "Imported CLASS_C evidence may remain CLASS_C, but may not be silently normalized into deterministic CLASS_A or CLASS_B artifacts.",
            "The comparator registry must be fixed before adjudication, and all declared comparator rows must be executed for the declared surfaces.",
        ],
        "anti_cherry_picking_rules": [
            "all_declared_environment_rows_required",
            "no_failed_row_omission",
            "worst_status_governs_pack_status",
            "comparator_registry_locked_before_adjudication",
            "validity_windows_may_not_be_extended_retroactively",
            "documentary_or_imported_rows_may_not_replace_current_required_rows",
        ],
        "replayability_requirements": [
            "hash-bound packs must provide a manifest-verification path",
            "public replay surfaces must be secret-free",
            "receipt replay requires deterministic scripts or an explicit replay recipe",
            "blocker_or_high_severity findings require replay PASS unless the proof layer itself is the failure class",
            "repo-root import fragility remains visible and cannot be overread as fixed by WS16",
        ],
        "stronger_claim_not_made": [
            "WS16 TEVV completeness is external capability confirmation.",
            "WS16 TEVV policy activates release readiness or threshold-root verifier acceptance.",
        ],
    }


def build_dataset_pin_registry(*, root: Path, current_head: str, tevv_subject_head: str) -> Dict[str, Any]:
    rows = [
        _dataset_row(
            dataset_id="ws13_local_truth_barrier_index",
            dataset_class="CURRENT_HEAD_RUNTIME_EVIDENCE",
            rel=LOCAL_LIVE_INDEX_REL,
            sha256=file_sha256((root / LOCAL_LIVE_INDEX_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="local_current_head_bundle",
            comparator_ids=["live_validation_index_canonical_equivalence_v1", "subject_head_equality_v1", "freshness_window_fail_closed_v1"],
            replay_role="LOCAL_TRUTH_MATRIX",
        ),
        _dataset_row(
            dataset_id="ws13_ci_truth_barrier_index",
            dataset_class="CURRENT_HEAD_RUNTIME_EVIDENCE",
            rel=CI_LIVE_INDEX_REL,
            sha256=file_sha256((root / CI_LIVE_INDEX_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="imported_ci_current_head_bundle",
            comparator_ids=["live_validation_index_canonical_equivalence_v1", "subject_head_equality_v1", "freshness_window_fail_closed_v1"],
            replay_role="CI_TRUTH_MATRIX",
        ),
        _dataset_row(
            dataset_id="ws13_local_subject_set",
            dataset_class="CANONICAL_SUBJECT_BINDING",
            rel=LOCAL_SUBJECT_SET_REL,
            sha256=file_sha256((root / LOCAL_SUBJECT_SET_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="local_current_head_bundle",
            comparator_ids=["sha256_exact_file_match_v1", "subject_head_equality_v1"],
            replay_role="LOCAL_SUBJECT_BINDING",
        ),
        _dataset_row(
            dataset_id="ws13_ci_subject_set",
            dataset_class="CANONICAL_SUBJECT_BINDING",
            rel=CI_SUBJECT_SET_REL,
            sha256=file_sha256((root / CI_SUBJECT_SET_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="imported_ci_current_head_bundle",
            comparator_ids=["sha256_exact_file_match_v1", "subject_head_equality_v1"],
            replay_role="CI_SUBJECT_BINDING",
        ),
        _dataset_row(
            dataset_id="ws11_bounded_keyless_signed_surface",
            dataset_class="IMPORTED_CLASS_C_EVIDENCE",
            rel=CI_SIGNED_SURFACE_REL,
            sha256=file_sha256((root / CI_SIGNED_SURFACE_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="imported_ci_signed_surface",
            comparator_ids=["sha256_exact_file_match_v1", "sigstore_bundle_surface_binding_v1"],
            replay_role="BOUNDED_KEYLESS_SURFACE",
        ),
        _dataset_row(
            dataset_id="ws11_bounded_keyless_sigstore_bundle",
            dataset_class="IMPORTED_CLASS_C_EVIDENCE",
            rel=CI_SIGSTORE_BUNDLE_REL,
            sha256=file_sha256((root / CI_SIGSTORE_BUNDLE_REL).resolve()),
            subject_head_commit=tevv_subject_head,
            origin="imported_ci_sigstore_bundle",
            comparator_ids=["sha256_exact_file_match_v1", "sigstore_bundle_surface_binding_v1"],
            replay_role="BOUNDED_KEYLESS_BUNDLE",
        ),
    ]
    return {
        "schema_id": "kt.governance.dataset_pin_registry.v1",
        "register_id": "KT_DATASET_PIN_REGISTRY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "tevv_subject_head_commit": tevv_subject_head,
        "pinning_rules": {
            "hash_algorithm": "SHA256_FILE_BYTES",
            "repo_relative_paths_only": True,
            "hash_mismatch_action": "FAIL_CLOSED",
            "cross_environment_exact_match_requires_declared_exact_comparator": True,
            "environment_specific_json_requires_declared_canonicalization_or_subject_binding": True,
            "imported_class_c_may_be_pinned_without_being_promoted_to_class_a_or_class_b": True,
            "pinset_must_be_complete_before_adjudication": True,
        },
        "pinned_datasets": rows,
        "stronger_claim_not_made": [
            "WS16 dataset pins convert imported evidence into release-ready deterministic artifacts.",
            "Pinned TEVV sets prove external capability or product readiness.",
        ],
    }


def build_comparator_registry(*, current_head: str) -> Dict[str, Any]:
    comparators = [
        {
            "comparator_id": "sha256_exact_file_match_v1",
            "kind": "EXACT_HASH",
            "deterministic": True,
            "success_condition": "lhs_sha256 == rhs_sha256",
            "implemented_by": "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            "approved_scopes": ["CLASS_A", "CANONICAL_SUBJECT_BINDING", "PIN_REGISTRY_EXACT_ROWS"],
        },
        {
            "comparator_id": "live_validation_index_canonical_equivalence_v1",
            "kind": "JSON_PROJECTION_CANONICAL_HASH",
            "deterministic": True,
            "profile_id": "live_validation_index_v1",
            "profile_ref": DETERMINISM_POLICY_REL,
            "success_condition": "canonical_hash(local_live_validation_index) == canonical_hash(ci_live_validation_index)",
            "implemented_by": DETERMINISM_POLICY_REL,
            "approved_scopes": ["CLASS_B", "TEVV_LOCAL_CI_PARITY"],
        },
        {
            "comparator_id": "subject_head_equality_v1",
            "kind": "SUBJECT_HEAD_BINDING",
            "deterministic": True,
            "success_condition": "all declared subject_head_commit values are equal",
            "implemented_by": "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            "approved_scopes": ["UPSTREAM_PROOF_SUBJECT_BINDING"],
        },
        {
            "comparator_id": "sigstore_bundle_surface_binding_v1",
            "kind": "STRUCTURAL_BINDING",
            "deterministic": True,
            "success_condition": "signed surface sha, keyless receipt, bundle sha, and remote diagnostic run id align for the bounded surface",
            "implemented_by": "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            "approved_scopes": ["BOUNDED_KEYLESS_PUBLIC_TRUST_SURFACE"],
        },
        {
            "comparator_id": "freshness_window_fail_closed_v1",
            "kind": "FRESHNESS_WINDOW",
            "deterministic": True,
            "success_condition": "generated_utc age is within the declared maximum hours or the row fails closed",
            "implemented_by": "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            "approved_scopes": ["CURRENT_HEAD_RUNTIME_EVIDENCE"],
        },
        {
            "comparator_id": "worst_case_pack_status_v1",
            "kind": "PACK_AGGREGATION",
            "deterministic": True,
            "success_condition": "any failed required component forces PACK status away from PASS",
            "implemented_by": "KT_PROD_CLEANROOM/tools/operator/ws16_tevv_dataset_comparator_validate.py",
            "approved_scopes": ["WS16_TEVV_PACK_STATUS"],
        },
    ]
    return {
        "schema_id": "kt.governance.comparator_registry.v1",
        "registry_id": "KT_COMPARATOR_REGISTRY_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "comparators": comparators,
        "stronger_claim_not_made": [
            "Comparator registration alone proves broader model superiority.",
            "WS16 comparators erase environment-specific raw output differences instead of bounding them.",
        ],
    }


def build_benchmark_validity_windows(*, current_head: str) -> Dict[str, Any]:
    return {
        "schema_id": "kt.governance.benchmark_validity_windows.v1",
        "windows_id": "KT_BENCHMARK_VALIDITY_WINDOWS_V1_20260318",
        "status": "ACTIVE",
        "current_repo_head": current_head,
        "windows": [
            {
                "window_id": "local_truth_barrier_current_head",
                "surface_ref": LOCAL_LIVE_INDEX_REL,
                "max_age_hours": 24,
                "requires_subject_binding": True,
                "staleness_action": "FAIL_CLOSED",
            },
            {
                "window_id": "ci_truth_barrier_current_head",
                "surface_ref": CI_LIVE_INDEX_REL,
                "max_age_hours": 24,
                "requires_subject_binding": True,
                "staleness_action": "FAIL_CLOSED",
            },
        ],
        "anti_cherry_picking_boundary": {
            "retroactive_window_extension_allowed": False,
            "historical_row_substitution_allowed": False,
            "worst_case_pack_status_required": True,
        },
        "stronger_claim_not_made": [
            "WS16 benchmark validity windows constitute external confirmation.",
            "WS16 benchmark validity windows widen current bounded surfaces into general benchmark leadership claims.",
        ],
    }


def build_tevv_pack_manifest(
    *,
    root: Path,
    current_head: str,
    tevv_subject_head: str,
    dataset_pin_registry: Dict[str, Any],
) -> Dict[str, Any]:
    components = [
        {"component_id": "trust_assumptions_register", **_path_sha_row(root, TRUST_ASSUMPTIONS_REL), "component_class": "GOVERNANCE_POLICY"},
        {"component_id": "tevv_pack_policy", **_path_sha_row(root, TEVV_PACK_POLICY_REL), "component_class": "GOVERNANCE_POLICY"},
        {"component_id": "dataset_pin_registry", **_path_sha_row(root, DATASET_PIN_REGISTRY_REL), "component_class": "GOVERNANCE_POLICY"},
        {"component_id": "comparator_registry", **_path_sha_row(root, COMPARATOR_REGISTRY_REL), "component_class": "GOVERNANCE_POLICY"},
        {"component_id": "benchmark_validity_windows", **_path_sha_row(root, BENCHMARK_VALIDITY_WINDOWS_REL), "component_class": "GOVERNANCE_POLICY"},
        {"component_id": "claim_proof_ceiling_compiler", **_path_sha_row(root, CLAIM_COMPILER_REL), "component_class": "CURRENT_HEAD_GOVERNANCE_EVIDENCE"},
        {"component_id": "independent_replay_recipe", **_path_sha_row(root, REPLAY_RECIPE_REL), "component_class": "REPLAYABILITY_GUIDANCE"},
        {"component_id": "local_truth_barrier_current_head", **_path_sha_row(root, LOCAL_LIVE_INDEX_REL), "component_class": "CURRENT_HEAD_RUNTIME_EVIDENCE"},
        {"component_id": "ci_truth_barrier_current_head", **_path_sha_row(root, CI_LIVE_INDEX_REL), "component_class": "CURRENT_HEAD_RUNTIME_EVIDENCE"},
        {"component_id": "local_determinism_subject_set", **_path_sha_row(root, LOCAL_SUBJECT_SET_REL), "component_class": "CANONICAL_SUBJECT_BINDING"},
        {"component_id": "ci_determinism_subject_set", **_path_sha_row(root, CI_SUBJECT_SET_REL), "component_class": "CANONICAL_SUBJECT_BINDING"},
        {"component_id": "bounded_keyless_signed_surface", **_path_sha_row(root, CI_SIGNED_SURFACE_REL), "component_class": "IMPORTED_CLASS_C_EVIDENCE"},
        {"component_id": "bounded_keyless_sigstore_bundle", **_path_sha_row(root, CI_SIGSTORE_BUNDLE_REL), "component_class": "IMPORTED_CLASS_C_EVIDENCE"},
        {"component_id": "bounded_keyless_execution_receipt", **_path_sha_row(root, CI_KEYLESS_RECEIPT_REL), "component_class": "IMPORTED_CLASS_C_EVIDENCE"},
        {"component_id": "bounded_truth_barrier_remote_diagnostic", **_path_sha_row(root, CI_REMOTE_DIAGNOSTIC_REL), "component_class": "IMPORTED_CLASS_C_EVIDENCE"},
    ]
    return {
        "schema_id": "kt.operator.tevv_pack_manifest.v1",
        "pack_id": "KT_WS16_TEVV_PACK_V1_20260318",
        "status": "ACTIVE_BOUNDED_PACK",
        "compiled_against": current_head,
        "tevv_subject_head_commit": tevv_subject_head,
        "evidence_position": "CURRENT_HEAD_CONTAINS_UPSTREAM_PASS_EVIDENCE",
        "dataset_pin_registry_ref": DATASET_PIN_REGISTRY_REL,
        "comparator_registry_ref": COMPARATOR_REGISTRY_REL,
        "trust_assumptions_ref": TRUST_ASSUMPTIONS_REL,
        "benchmark_validity_windows_ref": BENCHMARK_VALIDITY_WINDOWS_REL,
        "components": components,
        "pinned_dataset_ids": [row["dataset_id"] for row in dataset_pin_registry["pinned_datasets"]],
        "anti_cherry_picking_rules": [
            "all_declared_environment_rows_required",
            "worst_status_governs_pack_status",
            "historical_substitution_for_current_required_rows_forbidden",
        ],
        "replayability_requirements_refs": [
            REPLAY_RECIPE_REL,
            "KT_PROD_CLEANROOM/tools/verification/replay_manifest_verify.py",
            "KT_PROD_CLEANROOM/tools/operator/hermetic_replay_linter.py",
            "KT_PROD_CLEANROOM/tools/verification/fl4_replay_from_receipts.py",
        ],
        "stronger_claim_not_made": [
            "The WS16 TEVV pack proves external capability confirmation.",
            "The WS16 TEVV pack widens verifier or release boundaries beyond the current proof ceiling.",
        ],
    }


def _validate_freshness_rows(local_live: Dict[str, Any], ci_live: Dict[str, Any], windows: Dict[str, Any]) -> List[str]:
    by_id = {str(row.get("window_id", "")).strip(): row for row in windows.get("windows", []) if isinstance(row, dict)}
    fallback_hours = windows.get("freshness_windows_hours", {}) if isinstance(windows.get("freshness_windows_hours"), dict) else {}
    blockers: List[str] = []
    for window_id, payload in (
        ("local_truth_barrier_current_head", local_live),
        ("ci_truth_barrier_current_head", ci_live),
    ):
        window = by_id.get(window_id, {})
        max_age = int(window.get("max_age_hours", fallback_hours.get("live_validation_index", -1)))
        generated = str(payload.get("generated_utc", "")).strip()
        if max_age < 0 or not generated:
            blockers.append(f"{window_id.upper()}_WINDOW_OR_TIMESTAMP_MISSING")
            continue
        if _hours_old(generated) > float(max_age):
            blockers.append(f"{window_id.upper()}_STALE")
    return blockers


def _update_execution_dag(*, root: Path, current_head: str, status: str) -> Dict[str, Any]:
    dag = _load_required_json(root, EXECUTION_DAG_REL)
    dag["current_repo_head"] = current_head
    dag["generated_utc"] = utc_now_iso_z()
    dag["current_node"] = NEXT_WORKSTREAM_ID if status == "PASS" else WORKSTREAM_ID
    dag["next_lawful_workstream"] = NEXT_WORKSTREAM_ID if status == "PASS" else WORKSTREAM_ID

    for row in dag.get("nodes", []):
        if not isinstance(row, dict):
            continue
        node_id = str(row.get("id", "")).strip()
        if node_id == WORKSTREAM_ID:
            row["status"] = status
            row["ratification_checkpoint"] = Path(RECEIPT_REL).name
            row["claim_boundary"] = (
                "WS16 PASS proves only an explicit trust-assumptions register, TEVV pack completeness rules, cryptographically pinned bounded datasets/evidence sets, machine-readable comparator rules, benchmark validity windows, anti-cherry-picking rules, and replayability requirements for the already-bounded truth-barrier and verifier surfaces."
            )
        elif node_id == "WS17A_EXTERNAL_CONFIRMATION_ASSURANCE":
            row["status"] = "UNLOCKED" if status == "PASS" else "LOCKED_PENDING_WS16_PASS"
            row["unlock_basis"] = "WS16 PASS"
        elif node_id == "WS17B_EXTERNAL_CONFIRMATION_CAPABILITY":
            row["status"] = "UNLOCKED" if status == "PASS" else "LOCKED_PENDING_WS16_PASS"
            row["unlock_basis"] = "WS16 PASS"

    semantic_boundary = dag.get("semantic_boundary", {})
    if not isinstance(semantic_boundary, dict):
        semantic_boundary = {}
        dag["semantic_boundary"] = semantic_boundary
    semantic_boundary["lawful_current_claim"] = (
        "WS10 passed under a reratified 3-of-3 root boundary only. WS11 passed with one bounded keyless surface. "
        "WS12 passed for bounded current-head supply-chain policy. WS13 passed for bounded artifact-class locking and determinism proof. "
        "WS14 froze a bounded static verifier release and bootstrap-root-only acceptance policy. WS15 locked a typed claim ABI, proof ceiling, identity abuse barriers, ledger law, and non-executed release law. "
        "WS16 now locks a bounded trust-assumptions register, TEVV pack completeness rules, pinned evaluation datasets/evidence sets, comparator registry, benchmark validity windows, anti-cherry-picking rules, and replayability requirements without widening threshold-root acceptance, verifier scope, or release readiness."
    )
    semantic_boundary["stronger_claim_not_made"] = [
        "Threshold-root verifier acceptance is active",
        "Release readiness is proven",
        "Campaign completion is proven",
        "WS17A or WS17B has already been substantively started",
    ]
    _write_json(root, EXECUTION_DAG_REL, dag)
    return dag


def build_receipt(
    *,
    root: Path,
    current_head: str,
    tevv_subject_head: str,
    checks: Sequence[Dict[str, Any]],
    blockers: Sequence[str],
    dataset_pin_registry: Dict[str, Any],
    comparator_registry: Dict[str, Any],
) -> Dict[str, Any]:
    status = "PASS" if not blockers else "PARTIAL"
    return {
        "schema_id": "kt.operator.tevv_dataset_registry_receipt.v1",
        "artifact_id": "kt_tevv_dataset_registry_receipt.json",
        "workstream_id": WORKSTREAM_ID,
        "step_id": STEP_ID,
        "status": status,
        "pass_verdict": PASS_VERDICT if status == "PASS" else PARTIAL_VERDICT,
        "compiled_against": current_head,
        "current_repo_head": current_head,
        "tevv_subject_head_commit": tevv_subject_head,
        "current_strongest_claim": (
            "WS16 defines a bounded trust-assumptions register, TEVV pack completeness rules, cryptographically pinned datasets/evidence sets, machine-readable comparators, benchmark validity windows, anti-cherry-picking rules, and replayability requirements for the already-proven bounded truth-barrier and verifier surfaces."
        ),
        "checks": list(checks),
        "blocked_by": list(blockers),
        "trust_assumption_fields_locked": list(TRUST_ASSUMPTION_FIELDS),
        "dataset_hashes": {row["path"]: row["sha256"] for row in dataset_pin_registry["pinned_datasets"]},
        "comparator_registry_ids": [row["comparator_id"] for row in comparator_registry["comparators"]],
        "replayability_rules": [
            "hash-bound packs require manifest verification",
            "public replay surfaces must be secret-free",
            "receipt replay requires declared deterministic scripts or a replay recipe",
            "high-severity claims require replay PASS unless the proof layer itself is the failure class",
            "repo-root import fragility remains visible and not fixed by WS16",
        ],
        "remaining_limitations": [
            "WS16 does not constitute external confirmation.",
            "WS16 does not widen verifier coverage beyond the bounded current surface set.",
            "WS16 does not activate threshold-root verifier acceptance.",
            "WS16 does not prove release readiness, release ceremony execution, or campaign completion.",
            "The repo-root import fragility remains visible and unfixed.",
        ],
        "next_lawful_workstream": NEXT_WORKSTREAM_ID if status == "PASS" else WORKSTREAM_ID,
        "outputs": {
            TRUST_ASSUMPTIONS_REL: file_sha256((root / TRUST_ASSUMPTIONS_REL).resolve()),
            TEVV_PACK_POLICY_REL: file_sha256((root / TEVV_PACK_POLICY_REL).resolve()),
            DATASET_PIN_REGISTRY_REL: file_sha256((root / DATASET_PIN_REGISTRY_REL).resolve()),
            COMPARATOR_REGISTRY_REL: file_sha256((root / COMPARATOR_REGISTRY_REL).resolve()),
            BENCHMARK_VALIDITY_WINDOWS_REL: file_sha256((root / BENCHMARK_VALIDITY_WINDOWS_REL).resolve()),
            TEVV_PACK_MANIFEST_REL: file_sha256((root / TEVV_PACK_MANIFEST_REL).resolve()),
        },
        "stronger_claim_not_made": [
            "WS16 constitutes external assurance or external capability confirmation.",
            "WS16 proves threshold-root verifier acceptance, release readiness, or campaign completion.",
        ],
    }


def emit_ws16_tevv_dataset_registry(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    dirty_relpaths = _dirty_relpaths(_git_status_lines(root))
    unexpected_touches = [path for path in dirty_relpaths if not _path_in_scope(path)]
    if unexpected_touches:
        raise RuntimeError("FAIL_CLOSED: WS16 requires a frozen repo except for the bounded WS16 write set")

    ws15_receipt = _load_required_json(root, WS15_RECEIPT_REL)
    if str(ws15_receipt.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: WS15 must already be PASS before WS16 can start")
    ws15_compiled_against = str(ws15_receipt.get("compiled_against", "")).strip()
    if not ws15_compiled_against or not _git_is_ancestor(root, ws15_compiled_against, current_head):
        raise RuntimeError("FAIL_CLOSED: WS15 frozen boundary is not preserved into current HEAD")

    ws13_receipt = _load_required_json(root, WS13_RECEIPT_REL)
    ws14_receipt = _load_required_json(root, WS14_RECEIPT_REL)
    claim_compiler = _load_required_json(root, CLAIM_COMPILER_REL)
    truth_freshness_windows = _load_required_json(root, TRUTH_FRESHNESS_WINDOWS_REL)
    determinism_policy = _load_required_json(root, DETERMINISM_POLICY_REL)
    local_live = _load_required_json(root, LOCAL_LIVE_INDEX_REL)
    ci_live = _load_required_json(root, CI_LIVE_INDEX_REL)
    local_subject_set = _load_required_json(root, LOCAL_SUBJECT_SET_REL)
    ci_subject_set = _load_required_json(root, CI_SUBJECT_SET_REL)
    keyless_receipt = _load_required_json(root, CI_KEYLESS_RECEIPT_REL)
    remote_diagnostic = _load_required_json(root, CI_REMOTE_DIAGNOSTIC_REL)
    _ = _read_text_required(root, REPLAY_RECIPE_REL)

    blocked_by: List[str] = []
    checks: List[Dict[str, Any]] = []

    subject_candidates = _subject_head_candidates(ws13_receipt, ws14_receipt, local_live, ci_live, local_subject_set, ci_subject_set)
    tevv_subject_head = subject_candidates[0] if len(subject_candidates) == 1 else ""
    if not tevv_subject_head:
        blocked_by.append("UPSTREAM_TEVV_SUBJECT_HEAD_DIVERGENCE")
    checks.append(
        _check(
            bool(tevv_subject_head),
            "upstream_tevv_subject_head_aligned",
            "WS16 requires the upstream WS13/WS14 subject head, local/CI live-validation rows, and subject sets to agree on one bounded proof subject.",
            [WS13_RECEIPT_REL, WS14_RECEIPT_REL, LOCAL_LIVE_INDEX_REL, CI_LIVE_INDEX_REL, LOCAL_SUBJECT_SET_REL, CI_SUBJECT_SET_REL],
            failures=subject_candidates if not tevv_subject_head else None,
            subject_candidates=subject_candidates,
        )
    )

    blocked_claims = {str(item).strip() for item in claim_compiler.get("blocked_current_claim_ids", []) if str(item).strip()}
    missing_blocked_claims = [claim_id for claim_id in REQUIRED_BLOCKED_CLAIMS if claim_id not in blocked_claims]
    if missing_blocked_claims:
        blocked_by.append("PROOF_CEILING_OVERCLAIM_BOUNDARY_BROKEN")
    checks.append(
        _check(
            not missing_blocked_claims,
            "proof_ceiling_still_blocks_stronger_claims",
            "WS16 must preserve the WS15 proof ceiling and keep threshold-root acceptance, release readiness, and campaign completion blocked.",
            [CLAIM_COMPILER_REL, WS15_RECEIPT_REL],
            failures=missing_blocked_claims,
        )
    )

    profile_ids = [str(row.get("profile_id", "")).strip() for row in determinism_policy.get("class_b_canonicalization_profiles", []) if isinstance(row, dict)]
    if "live_validation_index_v1" not in profile_ids:
        blocked_by.append("CLASS_B_CANONICAL_PROFILE_MISSING")
    checks.append(
        _check(
            "live_validation_index_v1" in profile_ids,
            "class_b_canonicalization_profile_declared",
            "WS16 must reuse the declared WS13 CLASS_B canonicalization profile for local-vs-CI truth-barrier comparison.",
            [DETERMINISM_POLICY_REL],
            failures=["live_validation_index_v1 missing"] if "live_validation_index_v1" not in profile_ids else None,
        )
    )

    freshness_blockers = _validate_freshness_rows(local_live, ci_live, truth_freshness_windows)
    blocked_by.extend(freshness_blockers)
    checks.append(
        _check(
            not freshness_blockers,
            "current_head_truth_rows_within_validity_windows",
            "WS16 requires the declared local and CI truth-barrier rows to remain within their fail-closed validity windows.",
            [TRUTH_FRESHNESS_WINDOWS_REL, LOCAL_LIVE_INDEX_REL, CI_LIVE_INDEX_REL],
            failures=freshness_blockers,
        )
    )

    signed_surface_sha256 = file_sha256((root / CI_SIGNED_SURFACE_REL).resolve())
    bundle_sha256 = file_sha256((root / CI_SIGSTORE_BUNDLE_REL).resolve())
    run_id_match = str(keyless_receipt.get("run_id", "")).strip() == str(remote_diagnostic.get("run_id", "")).strip()
    signed_surface_match = str(keyless_receipt.get("signed_surface_sha256", "")).strip() == signed_surface_sha256
    bundle_match = str(keyless_receipt.get("bundle_sha256", "")).strip() == bundle_sha256
    keyless_mode = str(keyless_receipt.get("executed_signer_mode", "")).strip() == "sigstore_keyless"
    bounded_surface_present = "KT_PROD_CLEANROOM/reports/public_verifier_manifest.json" in [str(item).strip() for item in keyless_receipt.get("keyless_backed_surfaces", [])]
    sigstore_failures = []
    if not run_id_match:
        sigstore_failures.append("run_id_mismatch")
    if not signed_surface_match:
        sigstore_failures.append("signed_surface_sha256_mismatch")
    if not bundle_match:
        sigstore_failures.append("bundle_sha256_mismatch")
    if not keyless_mode:
        sigstore_failures.append("executed_signer_mode_not_keyless")
    if not bounded_surface_present:
        sigstore_failures.append("bounded_surface_not_declared")
    if sigstore_failures:
        blocked_by.append("BOUNDED_KEYLESS_SURFACE_BINDING_INVALID")
    checks.append(
        _check(
            not sigstore_failures,
            "bounded_keyless_surface_binding_intact",
            "WS16 must keep the bounded WS11 surface bound across the keyless receipt, remote diagnostic, signed surface, and Sigstore bundle.",
            [CI_KEYLESS_RECEIPT_REL, CI_REMOTE_DIAGNOSTIC_REL, CI_SIGNED_SURFACE_REL, CI_SIGSTORE_BUNDLE_REL],
            failures=sigstore_failures,
            signed_surface_sha256=signed_surface_sha256,
            bundle_sha256=bundle_sha256,
        )
    )

    comparator_registry = build_comparator_registry(current_head=current_head)
    missing_comparators = [comp_id for comp_id in REQUIRED_COMPARATOR_IDS if comp_id not in [row["comparator_id"] for row in comparator_registry["comparators"]]]
    if missing_comparators:
        blocked_by.append("COMPARATOR_REGISTRY_INCOMPLETE")
    checks.append(
        _check(
            not missing_comparators,
            "comparator_registry_machine_readable_and_complete",
            "WS16 must define a machine-readable comparator registry for exact-hash, canonical, subject-binding, bundle-binding, freshness, and worst-case aggregation.",
            [COMPARATOR_REGISTRY_REL],
            failures=missing_comparators,
        )
    )

    trust_assumptions_register = build_trust_assumptions_register(current_head=current_head, tevv_subject_head=tevv_subject_head or "UNRESOLVED")
    tevv_pack_policy = build_tevv_pack_policy(current_head=current_head)
    benchmark_validity_windows = build_benchmark_validity_windows(current_head=current_head)
    dataset_pin_registry = build_dataset_pin_registry(root=root, current_head=current_head, tevv_subject_head=tevv_subject_head or "UNRESOLVED")

    _write_json(root, TRUST_ASSUMPTIONS_REL, trust_assumptions_register)
    _write_json(root, TEVV_PACK_POLICY_REL, tevv_pack_policy)
    _write_json(root, DATASET_PIN_REGISTRY_REL, dataset_pin_registry)
    _write_json(root, COMPARATOR_REGISTRY_REL, comparator_registry)
    _write_json(root, BENCHMARK_VALIDITY_WINDOWS_REL, benchmark_validity_windows)

    tevv_pack_manifest = build_tevv_pack_manifest(
        root=root,
        current_head=current_head,
        tevv_subject_head=tevv_subject_head or "UNRESOLVED",
        dataset_pin_registry=dataset_pin_registry,
    )
    _write_json(root, TEVV_PACK_MANIFEST_REL, tevv_pack_manifest)

    required_component_ids = {row["component_id"] for row in tevv_pack_policy["required_components"]}
    manifest_component_ids = {row["component_id"] for row in tevv_pack_manifest["components"]}
    missing_components = sorted(required_component_ids - manifest_component_ids)
    if missing_components:
        blocked_by.append("TEVV_PACK_COMPONENT_MISSING")
    checks.append(
        _check(
            not missing_components,
            "tevv_pack_complete_for_declared_scope",
            "WS16 requires the TEVV pack manifest to carry every declared required component for the bounded local/CI + keyless surface scope.",
            [TEVV_PACK_POLICY_REL, TEVV_PACK_MANIFEST_REL],
            failures=missing_components,
        )
    )

    blocked_by = sorted(set(blocked_by))
    status = "PASS" if not blocked_by else "PARTIAL"
    _update_execution_dag(root=root, current_head=current_head, status=status)
    receipt = build_receipt(
        root=root,
        current_head=current_head,
        tevv_subject_head=tevv_subject_head or "UNRESOLVED",
        checks=checks,
        blockers=blocked_by,
        dataset_pin_registry=dataset_pin_registry,
        comparator_registry=comparator_registry,
    )
    _write_json(root, RECEIPT_REL, receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit the bounded WS16 TEVV/dataset/comparator governance package.")
    parser.add_argument("--root", default=str(repo_root()))
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    receipt = emit_ws16_tevv_dataset_registry(root=Path(args.root).resolve())
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
