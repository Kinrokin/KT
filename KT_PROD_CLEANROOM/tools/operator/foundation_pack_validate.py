from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import jsonschema

from tools.operator.titanium_common import file_sha256, load_json, repo_root, utc_now_iso_z, write_json_stable


FOUNDATION_ROOT_REL = "KT_PROD_CLEANROOM/governance/foundation_pack"
RECEIPT_REL = "KT_PROD_CLEANROOM/reports/kt_foundation_pack_ratification_receipt.json"
TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/foundation_pack_validate.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_foundation_pack_validate.py"

FOUNDATION_ARTIFACT_REFS = [
    f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json",
    f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.json",
    f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.json",
    f"{FOUNDATION_ROOT_REL}/kt_snapshot_manifest.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_fact_graph.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_interface_law.json",
    f"{FOUNDATION_ROOT_REL}/kt_state_vector.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_evidence_ledger.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_safety_envelope.json",
    f"{FOUNDATION_ROOT_REL}/kt_run_modes.json",
    f"{FOUNDATION_ROOT_REL}/kt_release_law.json",
]

SCHEMA_INSTANCE_PAIRS = {
    f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.schema.json": f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json",
    f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.schema.json": f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.json",
    f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.schema.json": f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.json",
}

SCHEMA_ONLY_REFS = [
    f"{FOUNDATION_ROOT_REL}/kt_snapshot_manifest.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_fact_graph.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_state_vector.schema.json",
    f"{FOUNDATION_ROOT_REL}/kt_evidence_ledger.schema.json",
]

SUBJECT_ARTIFACT_REFS = FOUNDATION_ARTIFACT_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

REQUIRED_FIRST_CLASS_ORGANS = {
    "governance_spine",
    "constitutional_meta_governance",
    "truth_authority_plane",
    "runtime_spine",
    "operator_factory",
    "verification_delivery_security_plane",
    "lab_adaptation_plane",
    "experiment_crucible_plane",
    "paradox_metabolism_plane",
    "public_claims_and_doctrine_plane",
    "commercial_surface_plane",
    "archive_memory_plane",
    "release_profile_plane",
    "adjudication_plane",
}

REQUIRED_CLAIM_STATUSES = {
    "evidenced",
    "partially_evidenced",
    "contradicted",
    "aspirational",
    "obsolete",
    "unclear",
}

REQUIRED_RUN_MODES = {
    "read_only_plus_bundle_emit",
    "proposal_then_ratification",
    "read_only_ingestion",
    "read_only_compiler_run",
    "read_only_rule_engine_run",
    "proposal_only",
    "read_only_registry_compilation",
    "mixed_modeling_and_testing",
    "generated_docs_plus_ratification",
    "adversarial_tribunal",
}

REQUIRED_FAIL_CLOSED_DOMAINS = {
    "authority",
    "runtime_integrity",
    "publication_claims",
    "security",
    "external_profiles",
    "paradox_resolution",
    "governance",
}

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _git_history_for_paths(root: Path, paths: Sequence[str]) -> List[str]:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "log", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [str(line).strip() for line in output.splitlines() if str(line).strip()]


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_changed_files(root: Path, commit: str) -> List[str]:
    if not str(commit).strip():
        return []
    try:
        output = _git(root, "show", "--pretty=", "--name-only", commit)
    except Exception:  # noqa: BLE001
        return []
    files = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not str(older).strip() or not str(newer).strip():
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    files = []
    for line in output.splitlines():
        value = str(line).strip().replace("\\", "/")
        if value:
            files.append(value)
    return files


def _load_json_rel(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _check_schema(schema: Dict[str, Any]) -> None:
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)


def _status_row(*, check: str, passed: bool, detail: str, refs: Sequence[str]) -> Dict[str, Any]:
    return {
        "check": check,
        "detail": detail,
        "refs": list(refs),
        "status": "PASS" if passed else "FAIL",
    }


def _is_protected(path: str) -> bool:
    normalized = str(path).replace("\\", "/")
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _artifact_digests(root: Path, refs: Sequence[str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for rel in refs:
        path = (root / Path(rel)).resolve()
        if path.exists():
            rows.append({"artifact_ref": rel, "sha256": file_sha256(path)})
    return rows


def build_foundation_pack_ratification_report(*, root: Path) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    trust_zones = _load_json_rel(root, "KT_PROD_CLEANROOM/governance/trust_zone_registry.json")
    ontology_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.schema.json")
    ontology = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json")
    invariant_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.schema.json")
    invariants = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.json")
    claim_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.schema.json")
    claim_taxonomy = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.json")
    snapshot_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_snapshot_manifest.schema.json")
    fact_graph_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_fact_graph.schema.json")
    interface_law = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_interface_law.json")
    state_vector_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_state_vector.schema.json")
    evidence_ledger_schema = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_evidence_ledger.schema.json")
    safety_envelope = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_safety_envelope.json")
    run_modes = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_run_modes.json")
    release_law = _load_json_rel(root, f"{FOUNDATION_ROOT_REL}/kt_release_law.json")

    expected_zones = {str(row.get("zone_id", "")).strip() for row in trust_zones.get("zones", []) if isinstance(row, dict)}
    organ_ids = [str(row.get("organ_id", "")).strip() for row in ontology.get("organs", []) if isinstance(row, dict)]
    invariant_rows = [row for row in invariants.get("invariants", []) if isinstance(row, dict)]
    invariant_organs = {str(row.get("organ_id", "")).strip() for row in invariant_rows}
    claim_classes = [row for row in claim_taxonomy.get("claim_classes", []) if isinstance(row, dict)]
    claim_statuses = {str(item).strip() for item in claim_taxonomy.get("claim_statuses", [])}
    admissibility_ceilings = {str(item).strip() for item in claim_taxonomy.get("admissibility_ceilings", [])}
    mode_ids = {str(row.get("mode_id", "")).strip() for row in run_modes.get("modes", []) if isinstance(row, dict)}
    fail_closed_domains = {str(item).strip() for item in safety_envelope.get("fail_closed_domains", [])}
    quality_level_keys = set(release_law.get("quality_levels", {}).keys()) if isinstance(release_law.get("quality_levels"), dict) else set()
    release_profiles = [row for row in release_law.get("release_profiles", []) if isinstance(row, dict)]

    for schema_ref in list(SCHEMA_INSTANCE_PAIRS.keys()) + list(SCHEMA_ONLY_REFS):
        try:
            _check_schema(_load_json_rel(root, schema_ref))
            checks.append(_status_row(check=f"schema_valid:{schema_ref}", passed=True, detail="JSON Schema is structurally valid.", refs=[schema_ref]))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"schema_invalid:{schema_ref}")
            checks.append(_status_row(check=f"schema_valid:{schema_ref}", passed=False, detail=str(exc), refs=[schema_ref]))

    for schema_ref, instance_ref in SCHEMA_INSTANCE_PAIRS.items():
        try:
            jsonschema.validate(instance=_load_json_rel(root, instance_ref), schema=_load_json_rel(root, schema_ref))
            checks.append(
                _status_row(
                    check=f"instance_valid:{instance_ref}",
                    passed=True,
                    detail="Instance validates against its paired schema.",
                    refs=[schema_ref, instance_ref],
                )
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"instance_invalid:{instance_ref}")
            checks.append(
                _status_row(
                    check=f"instance_valid:{instance_ref}",
                    passed=False,
                    detail=str(exc),
                    refs=[schema_ref, instance_ref],
                )
            )

    all_organ_zones = {
        zone
        for row in ontology.get("organs", [])
        if isinstance(row, dict)
        for zone in row.get("trust_zones", [])
        if isinstance(zone, str)
    }
    checks.append(
        _status_row(
            check="required_first_class_organs_covered",
            passed=REQUIRED_FIRST_CLASS_ORGANS.issubset(set(organ_ids)),
            detail="Ontology must cover all first-class KT organs.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json"],
        )
    )
    if not REQUIRED_FIRST_CLASS_ORGANS.issubset(set(organ_ids)):
        failures.append("required_first_class_organs_covered")

    checks.append(
        _status_row(
            check="ontology_trust_zones_known",
            passed=all_organ_zones.issubset(expected_zones),
            detail="Ontology trust-zone references must reuse the repo trust-zone registry.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json", "KT_PROD_CLEANROOM/governance/trust_zone_registry.json"],
        )
    )
    if not all_organ_zones.issubset(expected_zones):
        failures.append("ontology_trust_zones_known")

    missing_invariant_coverage = REQUIRED_FIRST_CLASS_ORGANS - invariant_organs
    checks.append(
        _status_row(
            check="invariant_coverage_per_organ",
            passed=not missing_invariant_coverage,
            detail="Every first-class organ must have at least one invariant.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.json"],
        )
    )
    if missing_invariant_coverage:
        failures.append("invariant_coverage_per_organ")

    invariants_have_targets = all(bool(row.get("active_refs")) or bool(row.get("planned_workstreams")) for row in invariant_rows)
    checks.append(
        _status_row(
            check="invariants_mechanically_targetable",
            passed=invariants_have_targets,
            detail="Each invariant must be active today or explicitly lineaged to a planned workstream target.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_organ_invariants.json"],
        )
    )
    if not invariants_have_targets:
        failures.append("invariants_mechanically_targetable")

    checks.append(
        _status_row(
            check="claim_statuses_locked",
            passed=claim_statuses == REQUIRED_CLAIM_STATUSES,
            detail="Claim statuses must match the controlling work order exactly.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.json"],
        )
    )
    if claim_statuses != REQUIRED_CLAIM_STATUSES:
        failures.append("claim_statuses_locked")

    claim_class_organs_ok = all(
        set(str(item).strip() for item in row.get("applicable_organs", [])).issubset(set(organ_ids)) for row in claim_classes
    )
    claim_class_ceilings_ok = all(
        str(row.get("max_admissibility_ceiling", "")).strip() in admissibility_ceilings for row in claim_classes
    )
    checks.append(
        _status_row(
            check="claim_classes_reference_known_organs_and_ceilings",
            passed=claim_class_organs_ok and claim_class_ceilings_ok,
            detail="Claim classes must reference ontology organs and declared admissibility ceilings.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_claim_taxonomy.json", f"{FOUNDATION_ROOT_REL}/kt_organ_ontology.json"],
        )
    )
    if not (claim_class_organs_ok and claim_class_ceilings_ok):
        failures.append("claim_classes_reference_known_organs_and_ceilings")

    zone_transition_statuses = {str(row.get("status", "")).strip() for row in interface_law.get("zone_transitions", []) if isinstance(row, dict)}
    checks.append(
        _status_row(
            check="interface_law_defines_allowed_and_forbidden_transitions",
            passed=bool(interface_law.get("organ_transitions"))
            and "CONDITIONAL" in zone_transition_statuses
            and "FORBIDDEN" in zone_transition_statuses,
            detail="Interface law must define conditional and forbidden transitions.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_interface_law.json"],
        )
    )
    if not (bool(interface_law.get("organ_transitions")) and "CONDITIONAL" in zone_transition_statuses and "FORBIDDEN" in zone_transition_statuses):
        failures.append("interface_law_defines_allowed_and_forbidden_transitions")

    checks.append(
        _status_row(
            check="safety_envelope_explicit",
            passed=REQUIRED_FAIL_CLOSED_DOMAINS.issubset(fail_closed_domains)
            and bool(safety_envelope.get("state_taint_rule"))
            and bool(safety_envelope.get("paradox_hold_policy")),
            detail="Safety envelope must explicitly define fail-closed domains, taint rules, and paradox hold policy.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_safety_envelope.json"],
        )
    )
    if not (REQUIRED_FAIL_CLOSED_DOMAINS.issubset(fail_closed_domains) and bool(safety_envelope.get("state_taint_rule")) and bool(safety_envelope.get("paradox_hold_policy"))):
        failures.append("safety_envelope_explicit")

    checks.append(
        _status_row(
            check="run_modes_complete",
            passed=mode_ids == REQUIRED_RUN_MODES,
            detail="All packet-defined run modes must exist and be explicit.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_run_modes.json"],
        )
    )
    if mode_ids != REQUIRED_RUN_MODES:
        failures.append("run_modes_complete")

    state_vector_required = {"claim_ceiling_status", "open_blockers", "organ_readiness", "doctrine_version", "canon_version", "proof_obligations", "lineage_completeness", "normalization_status", "adjudication_status"}
    evidence_ledger_required = {"schema_id", "ledger_id", "generated_utc", "entries"}
    checks.append(
        _status_row(
            check="state_vector_and_evidence_ledger_schemas_explicit",
            passed=state_vector_required.issubset(set(state_vector_schema.get("required", [])))
            and evidence_ledger_required.issubset(set(evidence_ledger_schema.get("required", []))),
            detail="State vector and evidence ledger schemas must expose the required work-order structure.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_state_vector.schema.json", f"{FOUNDATION_ROOT_REL}/kt_evidence_ledger.schema.json"],
        )
    )
    if not (
        state_vector_required.issubset(set(state_vector_schema.get("required", [])))
        and evidence_ledger_required.issubset(set(evidence_ledger_schema.get("required", [])))
    ):
        failures.append("state_vector_and_evidence_ledger_schemas_explicit")

    h1_profile = next((row for row in release_profiles if str(row.get("profile_id", "")).strip() == "h1_activation"), None)
    checks.append(
        _status_row(
            check="release_law_explicit",
            passed=quality_level_keys == {"QL0", "QL1", "QL2", "QL3"} and h1_profile is not None,
            detail="Release law must define quality levels and an explicit H1 activation profile.",
            refs=[f"{FOUNDATION_ROOT_REL}/kt_release_law.json"],
        )
    )
    if not (quality_level_keys == {"QL0", "QL1", "QL2", "QL3"} and h1_profile is not None):
        failures.append("release_law_explicit")

    subject_commit = _git_last_commit_for_paths(root, SUBJECT_ARTIFACT_REFS)
    current_head_commit = _git_head(root)
    subject_history = _git_history_for_paths(root, SUBJECT_ARTIFACT_REFS)
    earliest_subject_commit = subject_history[-1] if subject_history else ""
    step_baseline_commit = _git_parent(root, earliest_subject_commit)
    actual_subject_touched = _git_diff_files(root, step_baseline_commit, subject_commit, SUBJECT_ARTIFACT_REFS)
    if not actual_subject_touched:
        actual_subject_touched = _git_changed_files(root, subject_commit)
    actual_touched = sorted(set(actual_subject_touched + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = sorted(path for path in actual_touched if _is_protected(path))
    post_touch_ok = set(actual_touched) == set(PLANNED_MUTATES) and not unexpected_touches and not protected_touch_violations
    checks.append(
        _status_row(
            check="post_touch_accounting_clean",
            passed=post_touch_ok,
            detail="Actual touched set must match the lawful Step 2 subject files plus the ratification receipt.",
            refs=PLANNED_MUTATES,
        )
    )
    if not post_touch_ok:
        failures.append("post_touch_accounting_clean")

    status = "PASS" if not failures else "FAIL_CLOSED"
    verdict = "FOUNDATION_PACK_RATIFIED" if status == "PASS" else "FOUNDATION_PACK_REJECTED_FAIL_CLOSED"

    return {
        "schema_id": "kt.operator.foundation_pack_ratification_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "pass_verdict": verdict,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 2,
            "step_name": "FOUNDATION_PACK_RATIFICATION",
        },
        "foundation_pack_root": FOUNDATION_ROOT_REL,
        "current_head_commit": current_head_commit,
        "compiled_head_commit": subject_commit,
        "claim_boundary": (
            "This receipt ratifies the Step 2 foundation pack for compiled_head_commit only. "
            "A later repository head that contains this receipt is evidence about compiled_head_commit, not automatically the compiled head itself."
        ),
        "planned_mutates": list(PLANNED_MUTATES),
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "required_first_class_organs": sorted(REQUIRED_FIRST_CLASS_ORGANS),
        "counts": {
            "foundation_artifact_count": len(FOUNDATION_ARTIFACT_REFS),
            "organ_count": len(organ_ids),
            "invariant_count": len(invariant_rows),
            "claim_class_count": len(claim_classes),
            "run_mode_count": len(mode_ids),
        },
        "baseline_input_refs": [
            "KT_PROD_CLEANROOM/reports/ws0_ws11_closeout_summary.json",
            "KT_PROD_CLEANROOM/reports/ws0_ws11_closeout_blocker_register.json",
            "KT_PROD_CLEANROOM/reports/ws0_ws11_closeout_proof_class_ladder.json",
        ],
        "artifact_digests": _artifact_digests(root, SUBJECT_ARTIFACT_REFS),
        "checks": checks,
        "planned_workstream_targets": sorted(
            {
                target
                for row in invariant_rows
                for target in row.get("planned_workstreams", [])
                if isinstance(target, str) and str(target).strip()
            }
        ),
        "next_lawful_step": {
            "step_id": 1,
            "step_name": "KT_GOVERNANCE_CLOSEOUT_BASELINE_INGESTION",
            "status_after_step_2": "UNLOCKED" if status == "PASS" else "BLOCKED",
        },
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate and ratify the KT Step 2 foundation pack.")
    parser.add_argument("--root", default="", help="Optional repository root override.")
    parser.add_argument("--output", default=RECEIPT_REL, help="Receipt path relative to the repository root.")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = Path(str(args.root)).resolve() if str(args.root).strip() else repo_root()
    report = build_foundation_pack_ratification_report(root=root)
    output_path = Path(str(args.output)).expanduser()
    if not output_path.is_absolute():
        output_path = (root / output_path).resolve()
    write_json_stable(output_path, report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "pass_verdict": report["pass_verdict"],
                "compiled_head_commit": report["compiled_head_commit"],
                "current_head_commit": report["current_head_commit"],
                "unexpected_touches": report["unexpected_touches"],
                "protected_touch_violations": report["protected_touch_violations"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
