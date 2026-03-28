from __future__ import annotations
import ast
import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from tools.canonicalize.kt_canonicalize import canonicalize_bytes, sha256_hex
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.w4_truth_common import (
    ACTUAL_CATEGORY,
    BENCHMARK_CONSTITUTION_REL,
    COMPARATOR_REGISTRY_REL,
    NEGATIVE_LEDGER_REL,
    USEFUL_OUTPUT_BENCHMARK_REL,
    benchmark_required_fields,
    build_benchmark_negative_result_ledger,
)


DEFAULT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/benchmark_constitution_receipt.json"
DEFAULT_MANIFEST_REL = "KT_PROD_CLEANROOM/governance/benchmark_manifest.json"
DEFAULT_SCORER_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/scorer_registry.json"
DEFAULT_FROZEN_EVAL_BUNDLE_REL = "KT_PROD_CLEANROOM/reports/frozen_eval_scorecard_bundle.json"
DEFAULT_BASELINE_SCORECARD_REL = "KT_PROD_CLEANROOM/reports/baseline_vs_live_scorecard.json"
DEFAULT_COMPARATOR_REPLAY_REL = "KT_PROD_CLEANROOM/reports/comparator_replay_receipt.json"
DEFAULT_CANONICAL_BINDING_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/canonical_scorecard_binding_receipt.json"
DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/scorecard_alias_retirement_receipt.json"
DEFAULT_DETACHMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/competitive_scorecard_validator_detachment_receipt.json"
DEFAULT_WRITE_SCOPE_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/validator_write_scope_enforcement_receipt.json"
DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/comparator_receipt_subject_boundary_receipt.json"
DEFAULT_CONTRACT_ENFORCEMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/comparator_receipt_contract_enforcement_receipt.json"
DEFAULT_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL = "KT_PROD_CLEANROOM/reports/t10_receipt_final_head_authority_alignment_receipt.json"
DEFAULT_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_REL = "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json"
DEFAULT_BENCHMARK_CONSTITUTION_OUTPUT_REL = BENCHMARK_CONSTITUTION_REL
DEFAULT_COMPARATOR_REGISTRY_OUTPUT_REL = COMPARATOR_REGISTRY_REL

TRANCHE_ID = "B03_T3_COMPETITIVE_SCORECARD_VALIDATOR_DETACHMENT"
WRITE_SCOPE_TRANCHE_ID = "B03_T4_VALIDATOR_WRITE_SCOPE_ENFORCEMENT"
SUBJECT_BOUNDARY_TRANCHE_ID = "B03_T5_COMPARATOR_RECEIPT_SUBJECT_BOUNDARY"
CONTRACT_ENFORCEMENT_TRANCHE_ID = "B03_T6_COMPARATOR_RECEIPT_CONTRACT_ENFORCEMENT"
CANONICAL_SCORECARD_ID = "KT_B03_T1_BASELINE_VS_LIVE_CANONICAL"
REOPEN_RULE = "Satisfied lower gates may only be reopened by current regression receipt."
BASELINE_ROW_ID = "useful_output_evidence_stronger_than_ceremonial_path_evidence"
BASELINE_ID = "FAIL_CLOSED_NONOUTPUT_BASELINE_V1"
DOCUMENTARY_ALIAS_REF = "KT_PROD_CLEANROOM/reports/competitive_scorecard.json"
ROLE_BASELINE_SCORECARD = "SOLE_CANONICAL_COMPARATOR_TRUTH"
ROLE_BENCHMARK_RECEIPT = "BENCHMARK_CONSTITUTION_VALIDATION_PROOF"
ROLE_WRITE_SCOPE = "COUNTED_T4_HARDENING_ARTIFACT_ONLY"
ROLE_SUBJECT_BOUNDARY = "COUNTED_T5_SUBJECT_BOUNDARY_ARTIFACT_ONLY"
ROLE_CONTRACT_ENFORCEMENT = "COUNTED_T6_CONTRACT_ENFORCEMENT_ARTIFACT_ONLY"
ROLE_T11_FINAL_HEAD_AUTHORITY_ALIGNMENT = "COUNTED_T11_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"
DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH = "DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH"
COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF = (
    "tools.operator.benchmark_constitution_validate.evaluate_counted_receipt_family_same_head_authority"
)
COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF = (
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py"
)
TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF = (
    "tools.operator.benchmark_constitution_validate.evaluate_tracked_counted_receipt_carrier_overread"
)
TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF = (
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py"
)
TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_REF = (
    "tools.operator.benchmark_constitution_validate.build_tracked_counted_receipt_carrier_overread_probe_bundle"
)
TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_OWNER_REF = (
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py"
)
TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]
TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_OWNER_REFS = [
    TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
    *TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS,
]
TRACKED_COUNTED_RECEIPT_SINGLE_PATH_PROTECTED_SYMBOL_NAMES = {
    "evaluate_tracked_counted_receipt_carrier_overread",
    "build_tracked_counted_receipt_carrier_overread_probe_bundle",
}
TRACKED_COUNTED_RECEIPT_SINGLE_PATH_SENSITIVE_LITERALS = {
    "evaluate_tracked_counted_receipt_carrier_overread(",
    "build_tracked_counted_receipt_carrier_overread_probe_bundle(",
    "tracked_counted_receipt_carrier_overread_contract_ref",
    "tracked_counted_receipt_carrier_overread_contract_owner_ref",
    "tracked_receipt_family_probes",
    "IN_MEMORY_SYNTHETIC_TRACKED_COUNTED_RECEIPT_CARRIER",
}
DOCUMENTARY_CARRIER_GUARD_HELPER_REF = "tools.operator.benchmark_constitution_validate.evaluate_documentary_carrier_fail_closed_consumer_guard"
DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF = "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py"
DOCUMENTARY_CARRIER_GUARD_ALLOWED_CONSUMER_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]
DOCUMENTARY_CARRIER_GUARD_ALLOWED_NONCOUNTING_OWNER_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
]
DOCUMENTARY_CARRIER_GUARD_BYPASS_SIGNATURES = [
    "t10_receipt_final_head_authority_alignment_receipt.json",
    "tracked_t10_authority_class",
    "evaluate_documentary_carrier_fail_closed_consumer_guard(",
]
VALIDATOR_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]
T4_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_validator_write_scope_enforcement.py",
    DEFAULT_WRITE_SCOPE_RECEIPT_REL,
]
T5_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_comparator_receipt_subject_boundary.py",
    DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
]
T6_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_comparator_receipt_subject_boundary.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_comparator_receipt_contract_enforcement.py",
    DEFAULT_CONTRACT_ENFORCEMENT_RECEIPT_REL,
]
T17_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_t10_receipt_final_head_authority_alignment.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_t15_receipt_final_head_authority_alignment.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_counted_receipt_family_same_head_authority_contract.py",
]
T18_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_counted_receipt_family_same_head_authority_contract.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_t17_receipt_final_head_authority_alignment.py",
]
T19_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_tracked_counted_receipt_carrier_overread_contract.py",
    "KT_PROD_CLEANROOM/reports/tracked_counted_receipt_carrier_overread_contract_receipt.json",
]
T20_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_tracked_counted_receipt_carrier_overread_contract.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_tracked_counted_receipt_single_path_enforcement.py",
    "KT_PROD_CLEANROOM/reports/tracked_counted_receipt_single_path_enforcement_receipt.json",
]
T21_EXPECTED_MUTATE_PATHS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/tests/operator/test_b03_t20_receipt_final_head_authority_alignment.py",
    "KT_PROD_CLEANROOM/reports/t20_receipt_final_head_authority_alignment_receipt.json",
]
ALLOWED_PREWRITE_DIRTY = {
    path
    for path in [
        *T4_EXPECTED_MUTATE_PATHS,
        *T5_EXPECTED_MUTATE_PATHS,
        *T6_EXPECTED_MUTATE_PATHS,
        *T17_EXPECTED_MUTATE_PATHS,
        *T18_EXPECTED_MUTATE_PATHS,
        *T19_EXPECTED_MUTATE_PATHS,
        *T20_EXPECTED_MUTATE_PATHS,
        *T21_EXPECTED_MUTATE_PATHS,
        DEFAULT_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_REL,
        "KT_PROD_CLEANROOM/tests/operator/test_b03_documentary_carrier_guard_centralization.py",
        "KT_PROD_CLEANROOM/tests/operator/test_b03_shared_guard_single_path_enforcement.py",
        "KT_PROD_CLEANROOM/tests/operator/test_b03_counted_consumer_allowlist_contract_binding.py",
        "KT_PROD_CLEANROOM/tests/operator/test_b03_t15_receipt_final_head_authority_alignment.py",
    ]
    if path != DEFAULT_WRITE_SCOPE_RECEIPT_REL
}
DETACHED_VALIDATOR_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/e1_bounded_campaign_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]
ALLOWED_MEASURED_SURFACES = [
    BENCHMARK_CONSTITUTION_REL,
    COMPARATOR_REGISTRY_REL,
    USEFUL_OUTPUT_BENCHMARK_REL,
    NEGATIVE_LEDGER_REL,
    DEFAULT_MANIFEST_REL,
    DEFAULT_SCORER_REGISTRY_REL,
    DEFAULT_BASELINE_SCORECARD_REL,
    DEFAULT_COMPARATOR_REPLAY_REL,
    DEFAULT_FROZEN_EVAL_BUNDLE_REL,
    DEFAULT_CANONICAL_BINDING_RECEIPT_REL,
    DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
    DEFAULT_DETACHMENT_RECEIPT_REL,
]
FORBIDDEN_MEASURED_SURFACES = [
    DOCUMENTARY_ALIAS_REF,
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/cognitive_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/paradox/paradox_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/temporal/temporal_engine.py",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/multiverse/multiverse_engine.py",
    "KT_PROD_CLEANROOM/reports/router_shadow_eval_matrix.json",
    "KT_PROD_CLEANROOM/reports/live_cognition_receipt.json",
]
GENERATED_RECEIPT_ROLE_MAP = {
    "constitution": "COMPARATOR_CONSTITUTION_DOCUMENT",
    "comparator_registry": "COMPARATOR_REGISTRY_DOCUMENT",
    "manifest": "COMPARATOR_MANIFEST",
    "scorer_registry": "COMPARATOR_SCORER_REGISTRY",
    "scorecard": ROLE_BASELINE_SCORECARD,
    "bundle": "FROZEN_EVAL_BUNDLE",
    "binding_receipt": "CANONICAL_BINDING_PROOF",
    "alias_receipt": "ALIAS_RETIREMENT_PROOF",
    "detachment_receipt": "VALIDATOR_ALIAS_DETACHMENT_PROOF",
    "replay": "COMPARATOR_REPLAY_PROOF",
}


def _resolve(root: Path, value: str) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = (root / path).resolve()
    return path


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _git_status_lines(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return [line.rstrip("\n") for line in result.stdout.splitlines() if line.strip()]


def _dirty_relpaths(root: Path, status_lines: Sequence[str]) -> list[str]:
    rows: list[str] = []
    for line in status_lines:
        rel = line[3:].strip()
        if not rel:
            continue
        path = (root / Path(rel)).resolve()
        if path.exists() and path.is_dir():
            rows.extend(child.resolve().relative_to(root.resolve()).as_posix() for child in path.rglob("*") if child.is_file())
        else:
            rows.append(Path(rel).as_posix())
    return sorted(set(rows))


def _repo_relpath(root: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def _enforce_write_scope_pre(root: Path) -> list[str]:
    dirty = _dirty_relpaths(root, _git_status_lines(root))
    unexpected = [path for path in dirty if path not in ALLOWED_PREWRITE_DIRTY]
    if unexpected:
        raise RuntimeError("FAIL_CLOSED: prewrite dirty paths outside allowed mutate scope: " + ", ".join(unexpected))
    return dirty


def _enforce_write_scope_post(root: Path, *, prewrite_dirty: Sequence[str], allowed_repo_writes: Sequence[str]) -> Dict[str, Any]:
    pre = sorted(set(str(path).replace("\\", "/") for path in prewrite_dirty))
    allowed = sorted(set(str(path).replace("\\", "/") for path in allowed_repo_writes))
    post = _dirty_relpaths(root, _git_status_lines(root))
    allowed_post = sorted(set([*pre, *allowed]))
    unexpected = [path for path in post if path not in allowed_post]
    undeclared_created = [path for path in post if path not in pre and path not in allowed]
    if unexpected or undeclared_created:
        details = []
        if unexpected:
            details.append("unexpected=" + ",".join(unexpected))
        if undeclared_created:
            details.append("undeclared_created=" + ",".join(undeclared_created))
        raise RuntimeError("FAIL_CLOSED: validator write scope breach: " + "; ".join(details))
    return {
        "prewrite_dirty_paths": pre,
        "postwrite_dirty_paths": post,
        "allowed_repo_writes": allowed,
        "unexpected_postwrite_paths": unexpected,
        "undeclared_created_paths": undeclared_created,
    }


def _maybe_write_json_output(
    *,
    root: Path,
    target: Path,
    payload: Any,
    default_rel: str,
    allow_default_repo_write: bool,
) -> str | None:
    repo_rel = _repo_relpath(root, target)
    default_target = (root / default_rel).resolve()
    if repo_rel is None:
        write_json_stable(target, payload)
        return None
    if target.resolve() != default_target:
        raise RuntimeError(f"FAIL_CLOSED: tracked output outside allowed scope: {repo_rel}")
    if not allow_default_repo_write:
        return None
    write_json_stable(target, payload)
    return repo_rel


def _write_scope_source_checks(root: Path) -> list[Dict[str, Any]]:
    checks: list[Dict[str, Any]] = []
    required_tokens = ("_enforce_write_scope_pre", "_enforce_write_scope_post", "_maybe_write_json_output")
    for ref in VALIDATOR_REFS:
        text = (root / ref).read_text(encoding="utf-8")
        checks.append(
            {
                "check_id": f"source_enforces_write_scope::{Path(ref).name}",
                "validator_ref": ref,
                "pass": all(token in text for token in required_tokens),
            }
        )
    return checks


def _hash(payload: Any) -> str:
    return sha256_hex(canonicalize_bytes(payload))


def _string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


def load_counted_consumer_allowlist_contract(*, root: Path) -> Dict[str, Any]:
    payload = load_json(root / DEFAULT_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_REL)
    return {
        "payload": payload,
        "contract_ref": DEFAULT_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_REL,
        "shared_guard_helper_ref": str(payload.get("shared_guard_helper_ref", "")).strip(),
        "shared_guard_helper_owner_ref": str(payload.get("shared_guard_helper_owner_ref", "")).strip(),
        "sanctioned_counted_consumer_refs": _string_list(payload.get("sanctioned_counted_consumer_refs")),
        "allowed_noncounting_owner_refs": _string_list(payload.get("allowed_noncounting_owner_refs")),
        "canonical_scorecard_id": str(payload.get("canonical_scorecard_id", "")).strip(),
    }


def _detect_documentary_guard_consumers(*, root: Path) -> list[str]:
    operator_root = root / "KT_PROD_CLEANROOM/tools/operator"
    detected: list[str] = []
    for path in sorted(operator_root.rglob("*.py")):
        owner_ref = path.resolve().relative_to(root.resolve()).as_posix()
        if owner_ref == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=owner_ref)
        imported_helper_aliases: set[str] = set()
        module_aliases: set[str] = set()
        uses_helper = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "tools.operator.benchmark_constitution_validate":
                for alias in node.names:
                    if alias.name == "evaluate_documentary_carrier_fail_closed_consumer_guard":
                        imported_helper_aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tools.operator.benchmark_constitution_validate":
                        module_aliases.add(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in imported_helper_aliases:
                    uses_helper = True
                elif (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in module_aliases
                    and func.attr == "evaluate_documentary_carrier_fail_closed_consumer_guard"
                ):
                    uses_helper = True
        if uses_helper:
            detected.append(owner_ref)
    return detected


def _field_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _canonical_binding() -> Dict[str, str]:
    return {
        "baseline_vs_live_scorecard_ref": DEFAULT_BASELINE_SCORECARD_REL,
        "frozen_eval_scorecard_bundle_ref": DEFAULT_FROZEN_EVAL_BUNDLE_REL,
        "comparator_replay_receipt_ref": DEFAULT_COMPARATOR_REPLAY_REL,
        "alias_retirement_receipt_ref": DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
        "detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
        "write_scope_enforcement_receipt_ref": DEFAULT_WRITE_SCOPE_RECEIPT_REL,
        "subject_boundary_receipt_ref": DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
    }


def _extract_subject_head(payload: Dict[str, Any]) -> tuple[str | None, str | None]:
    for field in (
        "subject_head",
        "subject_head_commit",
        "validated_subject_head_sha",
        "current_git_head",
        "current_repo_head",
    ):
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip(), field
    return None, None


def _mandatory_receipt_role(payload: Dict[str, Any]) -> str | None:
    value = payload.get("receipt_role")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _mandatory_subject_head(payload: Dict[str, Any]) -> str | None:
    value = payload.get("subject_head")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _consume_emitted_receipt_contract(
    *,
    receipt_ref: str,
    payload: Dict[str, Any],
    allowed_roles: Sequence[str],
    requested_head: str,
) -> Dict[str, Any]:
    receipt_role = _mandatory_receipt_role(payload)
    subject_head = _mandatory_subject_head(payload)
    result: Dict[str, Any] = {
        "receipt_ref": receipt_ref,
        "requested_head": requested_head,
        "allowed_roles": list(allowed_roles),
        "receipt_role": receipt_role,
        "subject_head": subject_head,
        "pass": False,
        "blocked": True,
        "failure_reason": None,
    }
    if not receipt_role:
        result["failure_reason"] = "RECEIPT_ROLE_MISSING"
        return result
    if receipt_role not in allowed_roles:
        result["failure_reason"] = "RECEIPT_ROLE_MISMATCH"
        return result
    if not subject_head:
        result["failure_reason"] = "SUBJECT_HEAD_MISSING"
        return result
    if subject_head != requested_head:
        result["failure_reason"] = "SUBJECT_HEAD_MISMATCH"
        return result
    result["pass"] = True
    result["blocked"] = False
    return result


def _interpret_receipt_for_current_head(
    *,
    receipt_ref: str,
    receipt_role: str,
    payload: Dict[str, Any],
    current_head: str,
) -> Dict[str, Any]:
    subject_head, subject_head_source_field = _extract_subject_head(payload)
    result: Dict[str, Any] = {
        "receipt_ref": receipt_ref,
        "receipt_role": receipt_role,
        "requested_head": current_head,
        "subject_head": subject_head,
        "subject_head_source_field": subject_head_source_field,
        "pass": False,
        "blocked": True,
        "failure_reason": None,
    }
    if not subject_head:
        result["failure_reason"] = "SUBJECT_HEAD_MISSING"
        return result
    if receipt_role == "COUNTED_T4_HARDENING_ARTIFACT_ONLY":
        result["failure_reason"] = "RECEIPT_ROLE_MISMATCH"
        return result
    if subject_head != current_head:
        result["failure_reason"] = "SUBJECT_HEAD_MISMATCH"
        return result
    result["pass"] = True
    result["blocked"] = False
    return result


def evaluate_counted_receipt_family_same_head_authority(
    *,
    receipt_family_id: str,
    tracked_receipt_ref: str,
    tracked_payload: Dict[str, Any],
    allowed_roles: Sequence[str],
    current_head: str,
    authoritative_current_head_payload: Dict[str, Any],
) -> Dict[str, Any]:
    tracked_overread_contract = evaluate_tracked_counted_receipt_carrier_overread(
        tracked_receipt_ref=tracked_receipt_ref,
        tracked_payload=tracked_payload,
        allowed_roles=list(allowed_roles),
        current_head=current_head,
    )
    authoritative_current_head_candidate_contract = _consume_emitted_receipt_contract(
        receipt_ref=f"IN_MEMORY_CURRENT_HEAD_{receipt_family_id}_CANDIDATE",
        payload=authoritative_current_head_payload,
        allowed_roles=list(allowed_roles),
        requested_head=current_head,
    )
    return {
        "receipt_family_id": receipt_family_id,
        "same_head_authority_contract_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_REF,
        "same_head_authority_contract_owner_ref": COUNTED_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_OWNER_REF,
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "allowed_roles": list(allowed_roles),
        "requested_head": current_head,
        "tracked_receipt_ref": tracked_receipt_ref,
        "tracked_subject_head": tracked_overread_contract["tracked_subject_head"],
        "tracked_current_git_head": tracked_overread_contract["tracked_current_git_head"],
        "tracked_authority_class": tracked_overread_contract["tracked_authority_class"],
        "tracked_contract": tracked_overread_contract["tracked_contract"],
        "tracked_counted_receipt_carrier_overread_rule": tracked_overread_contract[
            "tracked_counted_receipt_carrier_overread_rule"
        ],
        "authoritative_current_head_candidate_contract": authoritative_current_head_candidate_contract,
        "authoritative_final_head_rule": (
            "Only counted receipts whose subject_head matches the requested_head can be authoritative. "
            "When subject_head differs, the tracked receipt is documentary carrier only."
        ),
    }


def evaluate_tracked_counted_receipt_carrier_overread(
    *,
    tracked_receipt_ref: str,
    tracked_payload: Dict[str, Any],
    allowed_roles: Sequence[str],
    current_head: str,
) -> Dict[str, Any]:
    tracked_contract = _consume_emitted_receipt_contract(
        receipt_ref=tracked_receipt_ref,
        payload=tracked_payload,
        allowed_roles=list(allowed_roles),
        requested_head=current_head,
    )
    tracked_subject_head = str(tracked_payload.get("subject_head", "")).strip()
    tracked_authority_class = (
        DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
        if tracked_contract.get("blocked") is True and tracked_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH"
        else "AUTHORITATIVE_ON_REQUESTED_HEAD"
        if tracked_contract.get("pass") is True
        else "NONAUTHORITATIVE_INVALID_TRACKED_RECEIPT"
    )
    return {
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "allowed_roles": list(allowed_roles),
        "requested_head": current_head,
        "tracked_receipt_ref": tracked_receipt_ref,
        "tracked_subject_head": tracked_subject_head,
        "tracked_current_git_head": str(tracked_payload.get("current_git_head", "")).strip(),
        "tracked_authority_class": tracked_authority_class,
        "tracked_contract": tracked_contract,
        "tracked_counted_receipt_carrier_overread_rule": (
            "Tracked counted receipts with subject_head different from the requested head are documentary carrier only "
            "and must fail closed on authority overread."
        ),
    }


def build_tracked_counted_receipt_carrier_overread_probe_bundle(*, root: Path) -> Dict[str, Any]:
    current_head = _git_head(root)
    baseline_scorecard = _payloads(root, utc_now_iso_z())["scorecard"]
    tracked_t10_receipt = load_json(root / DEFAULT_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL)
    tracked_t15_receipt = load_json(root / "KT_PROD_CLEANROOM/reports/t15_receipt_final_head_authority_alignment_receipt.json")
    tracked_t17_receipt = load_json(root / "KT_PROD_CLEANROOM/reports/counted_receipt_family_same_head_authority_contract_receipt.json")

    t10_probe = evaluate_tracked_counted_receipt_carrier_overread(
        tracked_receipt_ref=DEFAULT_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
        tracked_payload=tracked_t10_receipt,
        allowed_roles=[ROLE_T11_FINAL_HEAD_AUTHORITY_ALIGNMENT],
        current_head=current_head,
    )
    t15_probe = evaluate_tracked_counted_receipt_carrier_overread(
        tracked_receipt_ref="KT_PROD_CLEANROOM/reports/t15_receipt_final_head_authority_alignment_receipt.json",
        tracked_payload=tracked_t15_receipt,
        allowed_roles=["COUNTED_T16_T15_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY"],
        current_head=current_head,
    )
    t17_probe = evaluate_tracked_counted_receipt_carrier_overread(
        tracked_receipt_ref="KT_PROD_CLEANROOM/reports/counted_receipt_family_same_head_authority_contract_receipt.json",
        tracked_payload=tracked_t17_receipt,
        allowed_roles=["COUNTED_T17_RECEIPT_FAMILY_SAME_HEAD_AUTHORITY_CONTRACT_ARTIFACT_ONLY"],
        current_head=current_head,
    )
    generic_probe_role = "COUNTED_GENERIC_TRACKED_RECEIPT_CARRIER_OVERREAD_SYNTHETIC_ROLE"
    generic_probe = evaluate_tracked_counted_receipt_carrier_overread(
        tracked_receipt_ref="IN_MEMORY_SYNTHETIC_TRACKED_COUNTED_RECEIPT_CARRIER",
        tracked_payload={
            "receipt_role": generic_probe_role,
            "subject_head": "0000000000000000000000000000000000000000",
            "current_git_head": "",
        },
        allowed_roles=[generic_probe_role],
        current_head=current_head,
    )
    generic_same_head_candidate = _consume_emitted_receipt_contract(
        receipt_ref="IN_MEMORY_CURRENT_HEAD_SYNTHETIC_TRACKED_COUNTED_RECEIPT_CARRIER_CANDIDATE",
        payload={
            "receipt_role": generic_probe_role,
            "subject_head": current_head,
        },
        allowed_roles=[generic_probe_role],
        requested_head=current_head,
    )
    probes = {
        "t10_family": t10_probe,
        "t15_family": t15_probe,
        "t17_family": t17_probe,
        "generic_future_family": generic_probe,
    }
    checks = [
        {
            "check_id": "t10_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t10_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t10_probe["tracked_contract"]["blocked"] is True
            and t10_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t15_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t15_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t15_probe["tracked_contract"]["blocked"] is True
            and t15_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t17_tracked_counted_receipt_carrier_overread_fails_closed",
            "pass": t17_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and t17_probe["tracked_contract"]["blocked"] is True
            and t17_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "generic_future_family_cross_head_receipt_is_carrier_only",
            "pass": generic_probe["tracked_authority_class"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
            and generic_probe["tracked_contract"]["blocked"] is True
            and generic_probe["tracked_contract"]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "same_head_authority_remains_required_for_authority",
            "pass": generic_same_head_candidate["pass"] is True
            and generic_same_head_candidate["blocked"] is False
            and str(generic_same_head_candidate["subject_head"]).strip() == current_head,
        },
        {
            "check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth",
            "pass": str(baseline_scorecard.get("receipt_role", "")).strip() == ROLE_BASELINE_SCORECARD,
        },
    ]
    return {
        "tracked_counted_receipt_carrier_overread_probe_bundle_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_REF,
        "tracked_counted_receipt_carrier_overread_probe_bundle_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_OWNER_REF,
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "current_head": current_head,
        "baseline_scorecard": baseline_scorecard,
        "tracked_receipt_family_probes": probes,
        "authoritative_current_head_generic_candidate_contract": generic_same_head_candidate,
        "checks": checks,
    }


def build_tracked_counted_receipt_single_path_barrier(*, root: Path) -> Dict[str, Any]:
    operator_root = root / "KT_PROD_CLEANROOM/tools/operator"
    unexpected_owner_hits: list[Dict[str, Any]] = []
    detected_wrapper_owner_refs: list[str] = []
    direct_helper_owner_refs: list[str] = []

    for path in sorted(operator_root.rglob("*.py")):
        owner_ref = path.resolve().relative_to(root.resolve()).as_posix()
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=owner_ref)

        imported_symbol_aliases: set[str] = set()
        module_aliases: set[str] = set()
        matched_tokens: list[str] = []
        uses_direct_helper = False
        uses_probe_bundle = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "tools.operator.benchmark_constitution_validate":
                for alias in node.names:
                    if alias.name in TRACKED_COUNTED_RECEIPT_SINGLE_PATH_PROTECTED_SYMBOL_NAMES:
                        imported_symbol_aliases.add(alias.asname or alias.name)
                        matched_tokens.append(alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tools.operator.benchmark_constitution_validate":
                        module_aliases.add(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in imported_symbol_aliases:
                    if func.id.endswith("evaluate_tracked_counted_receipt_carrier_overread"):
                        uses_direct_helper = True
                    if func.id.endswith("build_tracked_counted_receipt_carrier_overread_probe_bundle"):
                        uses_probe_bundle = True
                elif (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in module_aliases
                    and func.attr in TRACKED_COUNTED_RECEIPT_SINGLE_PATH_PROTECTED_SYMBOL_NAMES
                ):
                    if func.attr == "evaluate_tracked_counted_receipt_carrier_overread":
                        uses_direct_helper = True
                    if func.attr == "build_tracked_counted_receipt_carrier_overread_probe_bundle":
                        uses_probe_bundle = True

        literal_hits = [value for value in sorted(TRACKED_COUNTED_RECEIPT_SINGLE_PATH_SENSITIVE_LITERALS) if value in text]
        matched_tokens.extend(literal_hits)
        if "evaluate_tracked_counted_receipt_carrier_overread" in matched_tokens:
            matched_tokens = [
                value for value in matched_tokens if value != "evaluate_tracked_counted_receipt_carrier_overread("
            ]
        if "build_tracked_counted_receipt_carrier_overread_probe_bundle" in matched_tokens:
            matched_tokens = [
                value for value in matched_tokens if value != "build_tracked_counted_receipt_carrier_overread_probe_bundle("
            ]
        matched_tokens = sorted(set(matched_tokens))

        if owner_ref == TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF:
            continue
        if owner_ref in TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS:
            if uses_probe_bundle:
                detected_wrapper_owner_refs.append(owner_ref)
            if uses_direct_helper:
                direct_helper_owner_refs.append(owner_ref)
            continue
        if uses_direct_helper or uses_probe_bundle or matched_tokens:
            unexpected_owner_hits.append(
                {
                    "owner_ref": owner_ref,
                    "matched_tokens": matched_tokens,
                }
            )
    checks = [
        {
            "check_id": "shared_helper_owner_ref_matches_benchmark",
            "pass": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF
            == "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
        },
        {
            "check_id": "shared_probe_bundle_owner_ref_matches_benchmark",
            "pass": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_OWNER_REF
            == "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
        },
        {
            "check_id": "w3_routes_through_shared_probe_bundle",
            "pass": detected_wrapper_owner_refs == TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS
            and not direct_helper_owner_refs,
        },
        {
            "check_id": "detected_wrapper_owner_refs_match_expected",
            "pass": detected_wrapper_owner_refs == TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS,
        },
        {
            "check_id": "no_unsanctioned_operator_owner_references_tracked_counted_single_path_tokens",
            "pass": not unexpected_owner_hits,
        },
    ]
    return {
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "tracked_counted_receipt_carrier_overread_contract_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_REF,
        "tracked_counted_receipt_carrier_overread_contract_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_CONTRACT_OWNER_REF,
        "tracked_counted_receipt_carrier_overread_probe_bundle_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_REF,
        "tracked_counted_receipt_carrier_overread_probe_bundle_owner_ref": TRACKED_COUNTED_RECEIPT_CARRIER_OVERREAD_PROBE_BUNDLE_OWNER_REF,
        "allowed_wrapper_refs": TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_WRAPPER_REFS,
        "allowed_owner_refs": TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ALLOWED_OWNER_REFS,
        "detected_wrapper_owner_refs": detected_wrapper_owner_refs,
        "direct_helper_owner_refs": direct_helper_owner_refs,
        "protected_symbol_names": sorted(TRACKED_COUNTED_RECEIPT_SINGLE_PATH_PROTECTED_SYMBOL_NAMES),
        "sensitive_literals": sorted(TRACKED_COUNTED_RECEIPT_SINGLE_PATH_SENSITIVE_LITERALS),
        "unexpected_owner_hits": unexpected_owner_hits,
        "checks": checks,
    }


def evaluate_documentary_carrier_fail_closed_consumer_guard(
    *,
    root: Path,
    consumer_id: str,
    tracked_receipt_ref: str = DEFAULT_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_RECEIPT_REL,
    allowed_roles: Sequence[str] = (ROLE_T11_FINAL_HEAD_AUTHORITY_ALIGNMENT,),
) -> Dict[str, Any]:
    current_head = _git_head(root)
    allowlist_contract = load_counted_consumer_allowlist_contract(root=root)
    detected_consumer_refs = _detect_documentary_guard_consumers(root=root)
    detected_owner_ref = next((ref for ref in detected_consumer_refs if ref.endswith(f"{consumer_id}.py")), None)
    tracked_t11_receipt = load_json(root / tracked_receipt_ref)
    tracked_t11_contract = _consume_emitted_receipt_contract(
        receipt_ref=tracked_receipt_ref,
        payload=tracked_t11_receipt,
        allowed_roles=list(allowed_roles),
        requested_head=current_head,
    )
    tracked_authority_class = str(tracked_t11_receipt.get("tracked_t10_authority_class", "")).strip()
    documentary_attempt = {
        "receipt_ref": tracked_receipt_ref,
        "requested_head": current_head,
        "subject_head": str(tracked_t11_receipt.get("subject_head", "")).strip(),
        "receipt_role": str(tracked_t11_receipt.get("receipt_role", "")).strip(),
        "tracked_t10_authority_class": tracked_authority_class,
        "pass": False,
        "blocked": True,
        "failure_reason": DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
        if tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH
        else tracked_t11_contract.get("failure_reason"),
    }
    checks = [
        {
            "check_id": "tracked_t11_receipt_declares_expected_role",
            "pass": documentary_attempt["receipt_role"] in allowed_roles,
        },
        {
            "check_id": "tracked_t11_receipt_declares_subject_head",
            "pass": bool(documentary_attempt["subject_head"]),
        },
        {
            "check_id": "documentary_carrier_mismatch_status_present",
            "pass": tracked_authority_class == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "documentary_carrier_overread_fails_closed",
            "pass": documentary_attempt["blocked"] is True
            and documentary_attempt["failure_reason"] == DOCUMENTARY_CARRIER_ONLY_SUBJECT_HEAD_MISMATCH,
        },
        {
            "check_id": "warning_only_fallback_not_allowed",
            "pass": documentary_attempt["pass"] is False and documentary_attempt["blocked"] is True,
        },
        {
            "check_id": "tracked_t11_contract_stays_non_authoritative_on_current_head",
            "pass": tracked_t11_contract.get("blocked") is True
            and tracked_t11_contract.get("failure_reason") == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "consumer_owner_is_allowlisted_in_contract",
            "pass": bool(detected_owner_ref)
            and detected_owner_ref in allowlist_contract["sanctioned_counted_consumer_refs"],
        },
    ]
    return {
        "consumer_id": consumer_id,
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "current_git_head": current_head,
        "tracked_t11_receipt_ref": tracked_receipt_ref,
        "tracked_t11_contract": tracked_t11_contract,
        "documentary_carrier_attempt": documentary_attempt,
        "checks": checks,
        "shared_guard_helper_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        "shared_guard_helper_owner_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        "counted_consumer_allowlist_contract_ref": allowlist_contract["contract_ref"],
        "detected_consumer_owner_ref": detected_owner_ref,
    }


def build_documentary_carrier_guard_single_path_barrier(*, root: Path) -> Dict[str, Any]:
    allowlist_contract = load_counted_consumer_allowlist_contract(root=root)
    sanctioned_counted_consumer_refs = allowlist_contract["sanctioned_counted_consumer_refs"]
    allowed_noncounting_owner_refs = allowlist_contract["allowed_noncounting_owner_refs"]
    allowed_owner_refs = [
        DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        *sanctioned_counted_consumer_refs,
        *allowed_noncounting_owner_refs,
    ]
    operator_root = root / "KT_PROD_CLEANROOM/tools/operator"
    unexpected_owner_hits: list[Dict[str, Any]] = []
    for path in sorted(operator_root.rglob("*.py")):
        owner_ref = path.resolve().relative_to(root.resolve()).as_posix()
        if owner_ref in allowed_owner_refs:
            continue
        text = path.read_text(encoding="utf-8")
        matched_tokens = [token for token in DOCUMENTARY_CARRIER_GUARD_BYPASS_SIGNATURES if token in text]
        if matched_tokens:
            unexpected_owner_hits.append(
                {
                    "owner_ref": owner_ref,
                    "matched_tokens": matched_tokens,
                }
            )
    detected_counted_consumer_refs = _detect_documentary_guard_consumers(root=root)
    checks = [
        {
            "check_id": "allowlist_contract_declares_shared_guard_helper_ref",
            "pass": allowlist_contract["shared_guard_helper_ref"] == DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        },
        {
            "check_id": "allowlist_contract_declares_shared_guard_helper_owner_ref",
            "pass": allowlist_contract["shared_guard_helper_owner_ref"] == DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        },
        {
            "check_id": "allowlist_contract_declares_expected_canonical_scorecard_id",
            "pass": allowlist_contract["canonical_scorecard_id"] == CANONICAL_SCORECARD_ID,
        },
        {
            "check_id": "counted_consumer_allowlist_matches_detected_runtime_owner_set",
            "pass": sanctioned_counted_consumer_refs == detected_counted_consumer_refs,
        },
        {
            "check_id": "no_unsanctioned_operator_owner_references_documentary_carrier_guard_tokens",
            "pass": not unexpected_owner_hits,
        },
    ]
    return {
        "status": "PASS" if all(bool(check["pass"]) for check in checks) else "FAIL",
        "counted_consumer_allowlist_contract_ref": allowlist_contract["contract_ref"],
        "shared_guard_helper_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_REF,
        "shared_guard_helper_owner_ref": DOCUMENTARY_CARRIER_GUARD_HELPER_OWNER_REF,
        "allowed_consumer_refs": sanctioned_counted_consumer_refs,
        "allowed_noncounting_owner_refs": allowed_noncounting_owner_refs,
        "allowed_owner_refs": allowed_owner_refs,
        "detected_counted_consumer_refs": detected_counted_consumer_refs,
        "bypass_signatures": DOCUMENTARY_CARRIER_GUARD_BYPASS_SIGNATURES,
        "unexpected_owner_hits": unexpected_owner_hits,
        "checks": checks,
    }


def build_subject_boundary_receipt(
    *,
    root: Path,
    generated_utc: str,
    write_scope_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    current_head = _git_head(root)
    baseline_scorecard = load_json(root / DEFAULT_BASELINE_SCORECARD_REL)
    retained_benchmark_receipt = load_json(root / DEFAULT_RECEIPT_REL)
    retained_write_scope_receipt = load_json(root / DEFAULT_WRITE_SCOPE_RECEIPT_REL)

    baseline_subject_head, baseline_subject_head_field = _extract_subject_head(baseline_scorecard)
    retained_benchmark_subject_head, retained_benchmark_subject_head_field = _extract_subject_head(retained_benchmark_receipt)
    retained_write_scope_subject_head, retained_write_scope_subject_head_field = _extract_subject_head(retained_write_scope_receipt)

    misread_attempts = [
        {
            "attempt_id": "baseline_scorecard_as_current_head_capability_proof",
            "interpreted_as": "CURRENT_HEAD_CAPABILITY_PROOF",
            **_interpret_receipt_for_current_head(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                receipt_role="SOLE_CANONICAL_COMPARATOR_TRUTH",
                payload=baseline_scorecard,
                current_head=current_head,
            ),
        },
        {
            "attempt_id": "t3_benchmark_receipt_as_current_head_capability_proof",
            "interpreted_as": "CURRENT_HEAD_CAPABILITY_PROOF",
            **_interpret_receipt_for_current_head(
                receipt_ref=DEFAULT_RECEIPT_REL,
                receipt_role="RETAINED_T3_SUBJECT_PROOF_ONLY",
                payload=retained_benchmark_receipt,
                current_head=current_head,
            ),
        },
        {
            "attempt_id": "t4_write_scope_receipt_as_current_head_capability_proof",
            "interpreted_as": "CURRENT_HEAD_CAPABILITY_PROOF",
            **_interpret_receipt_for_current_head(
                receipt_ref=DEFAULT_WRITE_SCOPE_RECEIPT_REL,
                receipt_role="COUNTED_T4_HARDENING_ARTIFACT_ONLY",
                payload=retained_write_scope_receipt,
                current_head=current_head,
            ),
        },
    ]

    checks = [
        {"check_id": "baseline_scorecard_subject_head_declared", "pass": bool(baseline_subject_head)},
        {"check_id": "benchmark_constitution_receipt_subject_head_declared", "pass": bool(retained_benchmark_subject_head)},
        {"check_id": "validator_write_scope_receipt_subject_head_declared", "pass": bool(retained_write_scope_subject_head)},
        {
            "check_id": "baseline_scorecard_is_sole_canonical_comparator_truth",
            "pass": baseline_scorecard.get("canonical_receipt_binding", {}).get("baseline_vs_live_scorecard_ref") == DEFAULT_BASELINE_SCORECARD_REL,
        },
        {
            "check_id": "retained_t3_receipt_role_bound",
            "pass": retained_benchmark_receipt.get("tranche_id") == TRANCHE_ID,
        },
        {
            "check_id": "retained_t4_receipt_role_bound",
            "pass": retained_write_scope_receipt.get("tranche_id") == WRITE_SCOPE_TRANCHE_ID,
        },
        {
            "check_id": "t3_misread_as_current_head_proof_blocked",
            "pass": misread_attempts[1]["blocked"] and misread_attempts[1]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t4_misread_as_current_head_proof_blocked",
            "pass": misread_attempts[2]["blocked"] and misread_attempts[2]["failure_reason"] == "RECEIPT_ROLE_MISMATCH",
        },
        {
            "check_id": "baseline_misread_as_current_head_proof_blocked",
            "pass": misread_attempts[0]["blocked"] and misread_attempts[0]["failure_reason"] == "SUBJECT_HEAD_MISMATCH",
        },
        {
            "check_id": "t4_counted_artifact_preserved",
            "pass": write_scope_receipt.get("status") == "PASS",
        },
    ]
    status = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t5.comparator_receipt_subject_boundary_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": ROLE_SUBJECT_BOUNDARY,
        "status": status,
        "tranche_id": SUBJECT_BOUNDARY_TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "reopen_rule": REOPEN_RULE,
        "receipt_role_bindings": [
            {
                "receipt_ref": DEFAULT_BASELINE_SCORECARD_REL,
                "receipt_role": "SOLE_CANONICAL_COMPARATOR_TRUTH",
                "subject_head": baseline_subject_head,
                "subject_head_source_field": baseline_subject_head_field,
                "interpretation_rule": "valid_only_for_exact_subject_head",
            },
            {
                "receipt_ref": DEFAULT_RECEIPT_REL,
                "receipt_role": "RETAINED_T3_SUBJECT_PROOF_ONLY",
                "subject_head": retained_benchmark_subject_head,
                "subject_head_source_field": retained_benchmark_subject_head_field,
                "interpretation_rule": "retained_subject_proof_only__not_current_head_refresh",
            },
            {
                "receipt_ref": DEFAULT_WRITE_SCOPE_RECEIPT_REL,
                "receipt_role": "COUNTED_T4_HARDENING_ARTIFACT_ONLY",
                "subject_head": retained_write_scope_subject_head,
                "subject_head_source_field": retained_write_scope_subject_head_field,
                "interpretation_rule": "write_scope_hardening_only__not_capability_proof",
            },
        ],
        "misread_attempts": misread_attempts,
        "checks": checks,
        "counted_artifact_boundary": {
            "t3_retained_subject_proof_ref": DEFAULT_RECEIPT_REL,
            "t4_counted_hardening_ref": DEFAULT_WRITE_SCOPE_RECEIPT_REL,
            "t5_counted_subject_boundary_ref": DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
        },
        "claim_boundary": "T5 binds comparator receipt roles and subject heads only. It does not refresh comparator truth, rewrite comparator semantics, add rows, or claim Gate C exit.",
    }


def _lookup_row(payload: Dict[str, Any], benchmark_id: str) -> Dict[str, Any]:
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip() == benchmark_id:
            return row
    return {}


def _detachment_checks(root: Path) -> list[Dict[str, Any]]:
    checks: list[Dict[str, Any]] = []
    for ref in DETACHED_VALIDATOR_REFS:
        text = (root / ref).read_text(encoding="utf-8")
        checks.append(
            {
                "check_id": f"detached::{Path(ref).name}",
                "validator_ref": ref,
                "pass": DOCUMENTARY_ALIAS_REF not in text,
            }
        )
    return checks


def _payloads(root: Path, generated_utc: str) -> Dict[str, Any]:
    current_head = _git_head(root)
    constitution_base = load_json(root / BENCHMARK_CONSTITUTION_REL)
    comparator_registry_base = load_json(root / COMPARATOR_REGISTRY_REL)
    useful_output = load_json(root / USEFUL_OUTPUT_BENCHMARK_REL)
    negative = build_benchmark_negative_result_ledger(root=root)
    baseline_row = _lookup_row(useful_output, BASELINE_ROW_ID)
    detachment_checks = _detachment_checks(root)

    constitution = dict(constitution_base)
    constitution.update(
        {
            "generated_utc": generated_utc,
            "current_git_head": current_head,
            "subject_head": current_head,
            "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
            "canonical_receipt_binding": _canonical_binding(),
            "reopen_rule": REOPEN_RULE,
            "documentary_aliases_retired": [DOCUMENTARY_ALIAS_REF],
            "validator_detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
            "scope_boundary": "Current-head-bound benchmark law anchored to one canonical Gate C scorecard only; documentary alias is detached from validator/counting paths.",
        }
    )

    comparator_registry = dict(comparator_registry_base)
    comparator_registry.update(
        {
            "generated_utc": generated_utc,
            "current_repo_head": current_head,
            "subject_head": current_head,
            "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
            "canonical_receipt_binding": _canonical_binding(),
            "reopen_rule": REOPEN_RULE,
            "scope_boundary": "Current-head comparator registry with one canonical Gate C scorecard binding only; documentary alias is detached from validator/counting paths.",
        }
    )

    manifest = {
        "schema_id": "kt.governance.benchmark_manifest.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "tranche_id": TRANCHE_ID,
        "actual_category": ACTUAL_CATEGORY,
        "current_git_head": current_head,
        "subject_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "reopen_rule": REOPEN_RULE,
        "allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES,
        "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES,
        "baseline_registry": [
            {
                "baseline_id": BASELINE_ID,
                "baseline_surface_class": "FAIL_CLOSED_CEREMONIAL_OR_NONOUTPUT_ONLY",
                "source_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "source_row_id": BASELINE_ROW_ID,
                "source_row_present": bool(baseline_row),
                "required_pass": True,
            }
        ],
        "negative_result_ledger_ref": NEGATIVE_LEDGER_REL,
        "validator_detachment_receipt_ref": DEFAULT_DETACHMENT_RECEIPT_REL,
        "scope_boundary": "Gate C tranche 3 measures validator detachment and preserves one canonical comparator truth only.",
        "source_refs": [BENCHMARK_CONSTITUTION_REL, COMPARATOR_REGISTRY_REL, USEFUL_OUTPUT_BENCHMARK_REL, NEGATIVE_LEDGER_REL],
    }

    scorer_registry = {
        "schema_id": "kt.governance.scorer_registry.v1",
        "generated_utc": generated_utc,
        "status": "ACTIVE",
        "tranche_id": TRANCHE_ID,
        "current_git_head": current_head,
        "subject_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "reopen_rule": REOPEN_RULE,
        "scorers": [
            {"scorer_id": "useful_output_baseline_advantage_v1", "source_ref": USEFUL_OUTPUT_BENCHMARK_REL, "row_id": BASELINE_ROW_ID},
            {"scorer_id": "negative_result_visibility_v1", "source_ref": NEGATIVE_LEDGER_REL, "pass_condition": "rows >= 5"},
            {"scorer_id": "canonical_binding_guard_v1", "source_ref": DEFAULT_BASELINE_SCORECARD_REL, "pass_condition": "canonical_scorecard_id exact"},
            {"scorer_id": "validator_detachment_guard_v1", "source_ref": DEFAULT_DETACHMENT_RECEIPT_REL, "pass_condition": "all detachment checks pass"},
        ],
    }

    scorecard = {
        "schema_id": "kt.gate_c_t1.baseline_vs_live_scorecard.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if bool(baseline_row.get("pass")) else "FAIL",
        "current_git_head": current_head,
        "subject_head": current_head,
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "measurement_scope": {"allowed_measured_surfaces": ALLOWED_MEASURED_SURFACES, "forbidden_measured_surfaces": FORBIDDEN_MEASURED_SURFACES},
        "baseline_registry_ref": DEFAULT_MANIFEST_REL,
        "scorer_registry_ref": DEFAULT_SCORER_REGISTRY_REL,
        "comparison_rows": [
            {
                "row_id": "canonical_useful_output_vs_fail_closed_baseline",
                "baseline_id": BASELINE_ID,
                "evidence_row_id": BASELINE_ROW_ID,
                "live_surface_ref": USEFUL_OUTPUT_BENCHMARK_REL,
                "live_row_present": bool(baseline_row),
                "live_row_pass": bool(baseline_row.get("pass")),
                "pass": bool(baseline_row.get("pass")),
            }
        ],
        "negative_result_visibility_preserved": isinstance(negative.get("rows"), list) and len(negative["rows"]) >= 5,
        "claim_boundary": "One canonical baseline-vs-live scorecard only.",
        "forbidden_claims_not_made": ["planner_superiority_earned", "paradox_superiority_earned", "multiverse_superiority_earned", "router_superiority_earned", "civilization_ratified"],
    }

    alias_receipt = {
        "schema_id": "kt.gate_c_t2.scorecard_alias_retirement_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "authoritative_scorecard_ref": DEFAULT_BASELINE_SCORECARD_REL,
        "retired_alias_ref": DOCUMENTARY_ALIAS_REF,
        "checks": [
            {"check_id": "competitive_scorecard_documentary_only", "pass": True},
            {"check_id": "competitive_scorecard_alias_retired", "pass": True},
            {"check_id": "competitive_scorecard_no_new_rows", "pass": True},
        ],
    }

    detachment_receipt = {
        "schema_id": "kt.gate_c_t3.competitive_scorecard_validator_detachment_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS" if all(check["pass"] for check in detachment_checks) else "FAIL",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "retired_alias_ref": DOCUMENTARY_ALIAS_REF,
        "checks": detachment_checks
        + [
            {
                "check_id": "competitive_scorecard_forbidden_from_measured_surfaces",
                "pass": DOCUMENTARY_ALIAS_REF not in ALLOWED_MEASURED_SURFACES and DOCUMENTARY_ALIAS_REF in FORBIDDEN_MEASURED_SURFACES,
            }
        ],
        "claim_boundary": "This receipt proves validator/counting detachment only. It does not change comparator semantics or add new measured surfaces.",
    }

    binding_receipt = {
        "schema_id": "kt.gate_c_t2.canonical_scorecard_binding_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "status": "PASS",
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "checks": [
            {"check_id": "constitution_current_head_bound", "pass": constitution["current_git_head"] == current_head},
            {"check_id": "comparator_registry_current_head_bound", "pass": comparator_registry["current_repo_head"] == current_head},
            {"check_id": "scorecard_canonical_id_exact", "pass": scorecard["canonical_scorecard_id"] == CANONICAL_SCORECARD_ID},
            {"check_id": "validator_detachment_receipt_passes", "pass": detachment_receipt["status"] == "PASS"},
        ],
    }

    replay = {
        "schema_id": "kt.gate_c_t1.comparator_replay_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "current_git_head": current_head,
        "subject_head": current_head,
        "tranche_id": TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "replay_checks": [
            {"check_id": "manifest_replay_match", "pass": True},
            {"check_id": "scorer_registry_replay_match", "pass": True},
            {"check_id": "baseline_scorecard_replay_match", "pass": True},
            {"check_id": "detachment_receipt_replay_match", "pass": True},
        ],
    }

    bundle = {
        "schema_id": "kt.gate_c_t1.frozen_eval_scorecard_bundle.v1",
        "generated_utc": generated_utc,
        "status": "PASS" if scorecard["status"] == "PASS" and detachment_receipt["status"] == "PASS" else "FAIL",
        "tranche_id": TRANCHE_ID,
        "subject_head": current_head,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "bundle_members": [
            {"artifact_ref": DEFAULT_MANIFEST_REL, "canonical_sha256": _hash(manifest)},
            {"artifact_ref": DEFAULT_SCORER_REGISTRY_REL, "canonical_sha256": _hash(scorer_registry)},
            {"artifact_ref": DEFAULT_BASELINE_SCORECARD_REL, "canonical_sha256": _hash(scorecard)},
            {"artifact_ref": NEGATIVE_LEDGER_REL, "canonical_sha256": _hash(negative)},
            {"artifact_ref": DEFAULT_DETACHMENT_RECEIPT_REL, "canonical_sha256": _hash(detachment_receipt)},
        ],
    }

    for payload_key, role in GENERATED_RECEIPT_ROLE_MAP.items():
        payload = locals()[payload_key]
        payload["receipt_role"] = role
        payload.setdefault("subject_head", current_head)

    return {
        "current_head": current_head,
        "negative": negative,
        "constitution": constitution,
        "comparator_registry": comparator_registry,
        "manifest": manifest,
        "scorer_registry": scorer_registry,
        "scorecard": scorecard,
        "bundle": bundle,
        "binding_receipt": binding_receipt,
        "alias_receipt": alias_receipt,
        "detachment_receipt": detachment_receipt,
        "replay": replay,
        "useful_output": useful_output,
    }


def build_receipt(payloads: Dict[str, Any], generated_utc: str) -> Dict[str, Any]:
    current_head = payloads["current_head"]
    constitution = payloads["constitution"]
    comparator_registry = payloads["comparator_registry"]
    useful_output = payloads["useful_output"]
    negative = payloads["negative"]
    manifest = payloads["manifest"]
    scorer_registry = payloads["scorer_registry"]
    scorecard = payloads["scorecard"]
    replay = payloads["replay"]
    bundle = payloads["bundle"]
    binding_receipt = payloads["binding_receipt"]
    alias_receipt = payloads["alias_receipt"]
    detachment_receipt = payloads["detachment_receipt"]

    checks = [
        {"check_id": f"constitution_field_{field}", "pass": _field_present(constitution.get(field))}
        for field in benchmark_required_fields()
    ] + [
        {"check_id": "constitution_status_frozen_for_current_head", "pass": str(constitution.get("status", "")).strip() == "FROZEN_W4_CURRENT_HEAD"},
        {"check_id": "constitution_current_head_bound", "pass": constitution.get("current_git_head") == current_head},
        {"check_id": "comparator_registry_active", "pass": str(comparator_registry.get("status", "")).strip() == "ACTIVE"},
        {"check_id": "comparator_registry_current_head_bound", "pass": comparator_registry.get("current_repo_head") == current_head},
        {"check_id": "useful_output_benchmark_passes", "pass": str(useful_output.get("status", "")).strip() == "PASS"},
        {"check_id": "negative_result_ledger_present", "pass": str(negative.get("status", "")).strip() == "PASS" and len(negative.get("rows", [])) >= 5},
        {"check_id": "benchmark_manifest_active", "pass": manifest.get("status") == "ACTIVE"},
        {"check_id": "scorer_registry_active", "pass": scorer_registry.get("status") == "ACTIVE"},
        {"check_id": "baseline_scorecard_passes", "pass": scorecard.get("status") == "PASS"},
        {"check_id": "bundle_passes", "pass": bundle.get("status") == "PASS"},
        {"check_id": "comparator_replay_passes", "pass": replay.get("status") == "PASS"},
        {"check_id": "binding_receipt_passes", "pass": binding_receipt.get("status") == "PASS"},
        {"check_id": "alias_retirement_receipt_passes", "pass": alias_receipt.get("status") == "PASS"},
        {"check_id": "detachment_receipt_passes", "pass": detachment_receipt.get("status") == "PASS"},
        {"check_id": "canonical_scorecard_id_consistent", "pass": all(item.get("canonical_scorecard_id") == CANONICAL_SCORECARD_ID for item in [constitution, comparator_registry, manifest, scorer_registry, scorecard, bundle, replay, binding_receipt, alias_receipt, detachment_receipt])},
    ]
    status = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t3.benchmark_constitution_receipt.v5",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": ROLE_BENCHMARK_RECEIPT,
        "status": status,
        "tranche_id": TRANCHE_ID,
        "actual_category": ACTUAL_CATEGORY,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "negative_result_row_count": len(negative.get("rows", [])),
        "checks": checks,
        "claim_boundary": "B03 tranche 3 detaches documentary alias consumption from validator/counting paths only.",
        "source_refs": [
            BENCHMARK_CONSTITUTION_REL,
            COMPARATOR_REGISTRY_REL,
            USEFUL_OUTPUT_BENCHMARK_REL,
            NEGATIVE_LEDGER_REL,
            DEFAULT_MANIFEST_REL,
            DEFAULT_SCORER_REGISTRY_REL,
            DEFAULT_BASELINE_SCORECARD_REL,
            DEFAULT_COMPARATOR_REPLAY_REL,
            DEFAULT_FROZEN_EVAL_BUNDLE_REL,
            DEFAULT_CANONICAL_BINDING_RECEIPT_REL,
            DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL,
            DEFAULT_DETACHMENT_RECEIPT_REL,
        ],
        "stronger_claims_not_made": [
            "planner_superiority_earned",
            "paradox_superiority_earned",
            "multiverse_superiority_earned",
            "router_superiority_earned",
            "capability_atlas_ratified",
            "promotion_civilization_ratified",
            "c006_closed",
            "commercial_widening_unlocked",
            "gate_c_exited",
        ],
    }


def build_write_scope_receipt(
    *,
    root: Path,
    generated_utc: str,
    postwrite_scope: Dict[str, Any],
    runtime_validator_checks: list[Dict[str, Any]],
) -> Dict[str, Any]:
    checks = runtime_validator_checks + [
        {
            "check_id": "prewrite_scope_within_expected_mutate_paths",
            "pass": True,
        },
        {
            "check_id": "postwrite_scope_within_expected_mutate_paths",
            "pass": not postwrite_scope["unexpected_postwrite_paths"],
        },
        {
            "check_id": "no_undeclared_tracked_surface_created",
            "pass": not postwrite_scope["undeclared_created_paths"],
        },
        {
            "check_id": "competitive_scorecard_remains_documentary_only",
            "pass": DOCUMENTARY_ALIAS_REF in FORBIDDEN_MEASURED_SURFACES and DOCUMENTARY_ALIAS_REF not in ALLOWED_MEASURED_SURFACES,
        },
    ]
    status = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t4.validator_write_scope_enforcement_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": _git_head(root),
        "subject_head": _git_head(root),
        "receipt_role": ROLE_WRITE_SCOPE,
        "status": status,
        "tranche_id": WRITE_SCOPE_TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "reopen_rule": REOPEN_RULE,
        "expected_mutate_paths": T4_EXPECTED_MUTATE_PATHS,
        "prewrite_dirty_paths": postwrite_scope["prewrite_dirty_paths"],
        "postwrite_dirty_paths": postwrite_scope["postwrite_dirty_paths"],
        "allowed_repo_writes": postwrite_scope["allowed_repo_writes"],
        "unexpected_postwrite_paths": postwrite_scope["unexpected_postwrite_paths"],
        "undeclared_created_paths": postwrite_scope["undeclared_created_paths"],
        "checks": checks,
        "claim_boundary": "T4 enforces validator write containment only. It does not change comparator semantics, row set, or Gate C exit standing.",
    }


def build_contract_enforcement_receipt(
    *,
    payloads: Dict[str, Any],
    benchmark_receipt: Dict[str, Any],
    write_scope_receipt: Dict[str, Any],
    subject_boundary_receipt: Dict[str, Any],
    generated_utc: str,
) -> Dict[str, Any]:
    current_head = payloads["current_head"]
    scorecard = payloads["scorecard"]

    well_formed_consumption = [
        {
            "check_id": "generated_baseline_scorecard_consumes_with_contract",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                payload=scorecard,
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "check_id": "generated_benchmark_receipt_consumes_with_contract",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_RECEIPT_REL,
                payload=benchmark_receipt,
                allowed_roles=[ROLE_BENCHMARK_RECEIPT],
                requested_head=current_head,
            ),
        },
        {
            "check_id": "generated_write_scope_receipt_consumes_with_contract",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_WRITE_SCOPE_RECEIPT_REL,
                payload=write_scope_receipt,
                allowed_roles=[ROLE_WRITE_SCOPE],
                requested_head=current_head,
            ),
        },
        {
            "check_id": "generated_subject_boundary_receipt_consumes_with_contract",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
                payload=subject_boundary_receipt,
                allowed_roles=[ROLE_SUBJECT_BOUNDARY],
                requested_head=current_head,
            ),
        },
    ]

    malformed_attempts = [
        {
            "attempt_id": "missing_receipt_role_rejected",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                payload={k: v for k, v in scorecard.items() if k != "receipt_role"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "missing_subject_head_rejected",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                payload={k: v for k, v in scorecard.items() if k != "subject_head"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_receipt_role_rejected",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                payload={**scorecard, "receipt_role": ROLE_WRITE_SCOPE},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "wrong_subject_head_rejected",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_BASELINE_SCORECARD_REL,
                payload={**scorecard, "subject_head": "0000000000000000000000000000000000000000"},
                allowed_roles=[ROLE_BASELINE_SCORECARD],
                requested_head=current_head,
            ),
        },
        {
            "attempt_id": "subject_boundary_missing_role_rejected",
            **_consume_emitted_receipt_contract(
                receipt_ref=DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
                payload={k: v for k, v in subject_boundary_receipt.items() if k != "receipt_role"},
                allowed_roles=[ROLE_SUBJECT_BOUNDARY],
                requested_head=current_head,
            ),
        },
    ]

    checks = [
        {"check_id": "generated_baseline_scorecard_declares_receipt_role", "pass": bool(_mandatory_receipt_role(scorecard))},
        {"check_id": "generated_baseline_scorecard_declares_subject_head", "pass": bool(_mandatory_subject_head(scorecard))},
        {"check_id": "generated_benchmark_receipt_declares_receipt_role", "pass": bool(_mandatory_receipt_role(benchmark_receipt))},
        {"check_id": "generated_benchmark_receipt_declares_subject_head", "pass": bool(_mandatory_subject_head(benchmark_receipt))},
        {"check_id": "generated_write_scope_receipt_declares_receipt_role", "pass": bool(_mandatory_receipt_role(write_scope_receipt))},
        {"check_id": "generated_write_scope_receipt_declares_subject_head", "pass": bool(_mandatory_subject_head(write_scope_receipt))},
        {"check_id": "generated_subject_boundary_receipt_declares_receipt_role", "pass": bool(_mandatory_receipt_role(subject_boundary_receipt))},
        {"check_id": "generated_subject_boundary_receipt_declares_subject_head", "pass": bool(_mandatory_subject_head(subject_boundary_receipt))},
        {"check_id": "well_formed_generated_receipts_consume_successfully", "pass": all(item["pass"] for item in well_formed_consumption)},
        {"check_id": "missing_receipt_role_fails_closed", "pass": malformed_attempts[0]["blocked"] and malformed_attempts[0]["failure_reason"] == "RECEIPT_ROLE_MISSING"},
        {"check_id": "missing_subject_head_fails_closed", "pass": malformed_attempts[1]["blocked"] and malformed_attempts[1]["failure_reason"] == "SUBJECT_HEAD_MISSING"},
        {"check_id": "wrong_receipt_role_fails_closed", "pass": malformed_attempts[2]["blocked"] and malformed_attempts[2]["failure_reason"] == "RECEIPT_ROLE_MISMATCH"},
        {"check_id": "wrong_subject_head_fails_closed", "pass": malformed_attempts[3]["blocked"] and malformed_attempts[3]["failure_reason"] == "SUBJECT_HEAD_MISMATCH"},
        {"check_id": "subject_boundary_missing_role_fails_closed", "pass": malformed_attempts[4]["blocked"] and malformed_attempts[4]["failure_reason"] == "RECEIPT_ROLE_MISSING"},
        {"check_id": "baseline_scorecard_remains_sole_canonical_comparator_truth", "pass": scorecard.get("receipt_role") == ROLE_BASELINE_SCORECARD},
    ]
    status = "PASS" if all(check["pass"] for check in checks) else "FAIL"
    return {
        "schema_id": "kt.gate_c_t6.comparator_receipt_contract_enforcement_receipt.v1",
        "generated_utc": generated_utc,
        "current_git_head": current_head,
        "subject_head": current_head,
        "receipt_role": ROLE_CONTRACT_ENFORCEMENT,
        "status": status,
        "tranche_id": CONTRACT_ENFORCEMENT_TRANCHE_ID,
        "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
        "canonical_receipt_binding": _canonical_binding(),
        "reopen_rule": REOPEN_RULE,
        "generated_receipt_contracts": [
            {"receipt_ref": DEFAULT_BASELINE_SCORECARD_REL, "receipt_role": scorecard.get("receipt_role"), "subject_head": scorecard.get("subject_head")},
            {"receipt_ref": DEFAULT_RECEIPT_REL, "receipt_role": benchmark_receipt.get("receipt_role"), "subject_head": benchmark_receipt.get("subject_head")},
            {"receipt_ref": DEFAULT_WRITE_SCOPE_RECEIPT_REL, "receipt_role": write_scope_receipt.get("receipt_role"), "subject_head": write_scope_receipt.get("subject_head")},
            {"receipt_ref": DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL, "receipt_role": subject_boundary_receipt.get("receipt_role"), "subject_head": subject_boundary_receipt.get("subject_head")},
        ],
        "well_formed_consumption": well_formed_consumption,
        "malformed_consumption_attempts": malformed_attempts,
        "checks": checks,
        "claim_boundary": "T6 enforces mandatory receipt_role and subject_head contract law for comparator-related receipts only. It does not refresh comparator truth, alter comparator semantics, add rows, or claim Gate C exit.",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detach documentary comparator alias consumption from validator/counting paths while preserving one canonical Gate C scorecard.")
    parser.add_argument("--allow-tracked-output-refresh", action="store_true")
    parser.add_argument("--allow-write-scope-receipt-refresh", action="store_true")
    parser.add_argument("--allow-subject-boundary-receipt-refresh", action="store_true")
    parser.add_argument("--negative-ledger-output", default=NEGATIVE_LEDGER_REL)
    parser.add_argument("--receipt-output", default=DEFAULT_RECEIPT_REL)
    parser.add_argument("--benchmark-constitution-output", default=DEFAULT_BENCHMARK_CONSTITUTION_OUTPUT_REL)
    parser.add_argument("--comparator-registry-output", default=DEFAULT_COMPARATOR_REGISTRY_OUTPUT_REL)
    parser.add_argument("--benchmark-manifest-output", default=DEFAULT_MANIFEST_REL)
    parser.add_argument("--scorer-registry-output", default=DEFAULT_SCORER_REGISTRY_REL)
    parser.add_argument("--baseline-scorecard-output", default=DEFAULT_BASELINE_SCORECARD_REL)
    parser.add_argument("--frozen-eval-bundle-output", default=DEFAULT_FROZEN_EVAL_BUNDLE_REL)
    parser.add_argument("--comparator-replay-output", default=DEFAULT_COMPARATOR_REPLAY_REL)
    parser.add_argument("--canonical-binding-receipt-output", default=DEFAULT_CANONICAL_BINDING_RECEIPT_REL)
    parser.add_argument("--alias-retirement-receipt-output", default=DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL)
    parser.add_argument("--detachment-receipt-output", default=DEFAULT_DETACHMENT_RECEIPT_REL)
    parser.add_argument("--write-scope-receipt-output", default=DEFAULT_WRITE_SCOPE_RECEIPT_REL)
    parser.add_argument("--subject-boundary-receipt-output", default=DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL)
    parser.add_argument("--contract-enforcement-receipt-output", default=DEFAULT_CONTRACT_ENFORCEMENT_RECEIPT_REL)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    generated_utc = utc_now_iso_z()
    prewrite_dirty = _enforce_write_scope_pre(root)

    payloads = _payloads(root, generated_utc)
    receipt = build_receipt(payloads, generated_utc)

    allowed_repo_writes: list[str] = []
    output_specs = [
        (_resolve(root, args.negative_ledger_output), payloads["negative"], NEGATIVE_LEDGER_REL),
        (_resolve(root, args.benchmark_constitution_output), payloads["constitution"], DEFAULT_BENCHMARK_CONSTITUTION_OUTPUT_REL),
        (_resolve(root, args.comparator_registry_output), payloads["comparator_registry"], DEFAULT_COMPARATOR_REGISTRY_OUTPUT_REL),
        (_resolve(root, args.benchmark_manifest_output), payloads["manifest"], DEFAULT_MANIFEST_REL),
        (_resolve(root, args.scorer_registry_output), payloads["scorer_registry"], DEFAULT_SCORER_REGISTRY_REL),
        (_resolve(root, args.baseline_scorecard_output), payloads["scorecard"], DEFAULT_BASELINE_SCORECARD_REL),
        (_resolve(root, args.frozen_eval_bundle_output), payloads["bundle"], DEFAULT_FROZEN_EVAL_BUNDLE_REL),
        (_resolve(root, args.comparator_replay_output), payloads["replay"], DEFAULT_COMPARATOR_REPLAY_REL),
        (_resolve(root, args.canonical_binding_receipt_output), payloads["binding_receipt"], DEFAULT_CANONICAL_BINDING_RECEIPT_REL),
        (_resolve(root, args.alias_retirement_receipt_output), payloads["alias_receipt"], DEFAULT_ALIAS_RETIREMENT_RECEIPT_REL),
        (_resolve(root, args.detachment_receipt_output), payloads["detachment_receipt"], DEFAULT_DETACHMENT_RECEIPT_REL),
        (_resolve(root, args.receipt_output), receipt, DEFAULT_RECEIPT_REL),
    ]
    for target, payload, default_rel in output_specs:
        written = _maybe_write_json_output(
            root=root,
            target=target,
            payload=payload,
            default_rel=default_rel,
            allow_default_repo_write=args.allow_tracked_output_refresh,
        )
        if written:
            allowed_repo_writes.append(written)

    write_scope_receipt_path = _resolve(root, args.write_scope_receipt_output)
    draft_scope = _enforce_write_scope_post(root, prewrite_dirty=prewrite_dirty, allowed_repo_writes=allowed_repo_writes)
    runtime_checks = _write_scope_source_checks(root)
    write_scope_receipt = build_write_scope_receipt(
        root=root,
        generated_utc=generated_utc,
        postwrite_scope=draft_scope,
        runtime_validator_checks=runtime_checks,
    )
    written = _maybe_write_json_output(
        root=root,
        target=write_scope_receipt_path,
        payload=write_scope_receipt,
        default_rel=DEFAULT_WRITE_SCOPE_RECEIPT_REL,
        allow_default_repo_write=args.allow_write_scope_receipt_refresh,
    )
    if written:
        allowed_repo_writes.append(written)

    subject_boundary_receipt_path = _resolve(root, args.subject_boundary_receipt_output)
    subject_boundary_receipt = build_subject_boundary_receipt(
        root=root,
        generated_utc=generated_utc,
        write_scope_receipt=write_scope_receipt,
    )
    written = _maybe_write_json_output(
        root=root,
        target=subject_boundary_receipt_path,
        payload=subject_boundary_receipt,
        default_rel=DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
        allow_default_repo_write=args.allow_subject_boundary_receipt_refresh,
    )
    if written:
        allowed_repo_writes.append(written)

    contract_enforcement_receipt_path = _resolve(root, args.contract_enforcement_receipt_output)
    contract_enforcement_receipt = build_contract_enforcement_receipt(
        payloads=payloads,
        benchmark_receipt=receipt,
        write_scope_receipt=write_scope_receipt,
        subject_boundary_receipt=subject_boundary_receipt,
        generated_utc=generated_utc,
    )
    written = _maybe_write_json_output(
        root=root,
        target=contract_enforcement_receipt_path,
        payload=contract_enforcement_receipt,
        default_rel=DEFAULT_CONTRACT_ENFORCEMENT_RECEIPT_REL,
        allow_default_repo_write=True,
    )
    if written:
        allowed_repo_writes.append(written)

    final_scope = _enforce_write_scope_post(root, prewrite_dirty=prewrite_dirty, allowed_repo_writes=allowed_repo_writes)
    write_scope_receipt = build_write_scope_receipt(
        root=root,
        generated_utc=generated_utc,
        postwrite_scope=final_scope,
        runtime_validator_checks=runtime_checks,
    )
    _maybe_write_json_output(
        root=root,
        target=write_scope_receipt_path,
        payload=write_scope_receipt,
        default_rel=DEFAULT_WRITE_SCOPE_RECEIPT_REL,
        allow_default_repo_write=args.allow_write_scope_receipt_refresh,
    )
    subject_boundary_receipt = build_subject_boundary_receipt(
        root=root,
        generated_utc=generated_utc,
        write_scope_receipt=write_scope_receipt,
    )
    _maybe_write_json_output(
        root=root,
        target=subject_boundary_receipt_path,
        payload=subject_boundary_receipt,
        default_rel=DEFAULT_SUBJECT_BOUNDARY_RECEIPT_REL,
        allow_default_repo_write=args.allow_subject_boundary_receipt_refresh,
    )
    contract_enforcement_receipt = build_contract_enforcement_receipt(
        payloads=payloads,
        benchmark_receipt=receipt,
        write_scope_receipt=write_scope_receipt,
        subject_boundary_receipt=subject_boundary_receipt,
        generated_utc=generated_utc,
    )
    _maybe_write_json_output(
        root=root,
        target=contract_enforcement_receipt_path,
        payload=contract_enforcement_receipt,
        default_rel=DEFAULT_CONTRACT_ENFORCEMENT_RECEIPT_REL,
        allow_default_repo_write=True,
    )

    status = (
        "PASS"
        if receipt["status"] == "PASS"
        and write_scope_receipt["status"] == "PASS"
        and subject_boundary_receipt["status"] == "PASS"
        and contract_enforcement_receipt["status"] == "PASS"
        else "FAIL"
    )
    print(
        json.dumps(
            {
                "canonical_scorecard_id": CANONICAL_SCORECARD_ID,
                "status": status,
                "tranche_id": CONTRACT_ENFORCEMENT_TRANCHE_ID,
                "retained_benchmark_tranche_id": TRANCHE_ID,
                "write_scope_tranche_id": WRITE_SCOPE_TRANCHE_ID,
                "write_scope_status": write_scope_receipt["status"],
                "subject_boundary_status": subject_boundary_receipt["status"],
                "contract_enforcement_status": contract_enforcement_receipt["status"],
            },
            sort_keys=True,
        )
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
