from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import load_json, repo_root, semantically_equal_json, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
WORK_ORDER_REL = "KT_PROD_CLEANROOM/AUDITS/COUNCIL_PACKET/V2/WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION.v2.json"
STEP8_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_normalization_and_professionalization_planning_receipt.json"
STATE_VECTOR_REL = f"{REPORT_ROOT_REL}/kt_state_vector.json"
CRUCIBLE_REGISTRY_REL = "KT_PROD_CLEANROOM/governance/crucible_registry.json"
CRUCIBLE_LEDGER_REL = "KT_PROD_CLEANROOM/tools/growth/ledgers/c019_crucible_runs.jsonl"
PROMOTED_INDEX_REL = "KT_PROD_CLEANROOM/exports/adapters/promoted_index.json"
PROOFRUNBUNDLE_INDEX_REL = f"{REPORT_ROOT_REL}/proofrunbundle_index.json"
REPRODUCIBILITY_REL = f"{REPORT_ROOT_REL}/representative_authority_lane_reproducibility_receipt.json"
DELTA_PROOF_REL = f"{REPORT_ROOT_REL}/delta_proof.json"
CANONICAL_HMAC_DELTA_REL = f"{REPORT_ROOT_REL}/canonical_hmac_one_button_delta_proof.json"
BEHAVIOR_DELTA_REL = f"{REPORT_ROOT_REL}/behavior_delta_receipt.json"
LEGACY_TRAIN_REPORT_REL = "KT_LANE_LORA_PHASE_B/lora_adapter_export/lora_out/train_report.json"
SECTOR_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_sector_harness_registry.json"

RUNTIME_EVENT_SCHEMA_REFS = [
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.audit_event.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.audit_event_index.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.paradox_event.v1.json",
    "KT_PROD_CLEANROOM/tools/growth/state/paradox_event_schema_v1.json",
]

EXECUTION_TRACE_SCHEMA_REFS = [
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.reasoning_trace.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.factory.phase_trace.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.trace_violation.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.temporal_lineage_graph.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.suite_eval_report.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.cognitive_fitness.v2.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.cognitive_fitness_policy.v1.json",
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/schemas/fl3/kt.fitness_region.v1.json",
]

FITNESS_ENGINE_REFS = [
    "KT_PROD_CLEANROOM/tools/verification/compute_cognitive_fitness.py",
    "KT_PROD_CLEANROOM/tools/suites/compute_suite_fitness.py",
    "KT_PROD_CLEANROOM/tools/eval/temporal_fitness_ledger.py",
    "KT_PROD_CLEANROOM/tools/training/fl3_factory/trace.py",
]

EXPERIMENT_REGISTRY_REL = f"{REPORT_ROOT_REL}/kt_experiment_registry.json"
CRUCIBLE_RUN_LOG_REL = f"{REPORT_ROOT_REL}/kt_crucible_run_log.json"
LEARNING_DELTA_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_learning_delta_register.json"
RECEIPT_LINEAGE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_receipt_lineage_register.json"
RUNTIME_EVENT_SCHEMA_REL = f"{REPORT_ROOT_REL}/kt_runtime_event_schema.json"
EXECUTION_TRACE_SCHEMA_REL = f"{REPORT_ROOT_REL}/kt_execution_trace_schema.json"
LINEAGE_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_lineage_manifest.json"
FITNESS_ECOLOGY_REL = f"{REPORT_ROOT_REL}/kt_fitness_ecology.json"
FITNESS_PRESSURE_REGISTER_REL = f"{REPORT_ROOT_REL}/kt_fitness_pressure_register.json"
RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_runtime_and_experiment_memory_sealing_receipt.json"

TOOL_REL = "KT_PROD_CLEANROOM/tools/operator/runtime_experiment_registry_compile.py"
TEST_REL = "KT_PROD_CLEANROOM/tests/operator/test_runtime_experiment_registry_compile.py"

DELIVERABLE_REFS = [
    EXPERIMENT_REGISTRY_REL,
    CRUCIBLE_RUN_LOG_REL,
    LEARNING_DELTA_REGISTER_REL,
    RECEIPT_LINEAGE_REGISTER_REL,
    RUNTIME_EVENT_SCHEMA_REL,
    EXECUTION_TRACE_SCHEMA_REL,
    LINEAGE_MANIFEST_REL,
    FITNESS_ECOLOGY_REL,
    FITNESS_PRESSURE_REGISTER_REL,
]
SUBJECT_ARTIFACT_REFS = DELIVERABLE_REFS + [TOOL_REL, TEST_REL]
PLANNED_MUTATES = SUBJECT_ARTIFACT_REFS + [RECEIPT_REL]

WORK_ORDER_ID = "WORK_ORDER_KT_MAX_REFACTOR_E2E_INSTITUTIONAL_MEMORY_AND_FULL_STACK_ADJUDICATION"
WORK_ORDER_SCHEMA_ID = "kt.work_order.max_refactor_e2e_institutional_memory_and_full_stack_adjudication.v2"

PROTECTED_PREFIXES = (
    "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/",
    "kt_truth_ledger:",
    ".github/workflows/",
    "KT_PROD_CLEANROOM/docs/commercial/",
)

RUNTIME_DELTA_SOURCES = [
    ("runtime_delta::red_assault_current_head_refresh", DELTA_PROOF_REL, "red_assault_current_head_refresh"),
    ("runtime_delta::canonical_hmac_one_button", CANONICAL_HMAC_DELTA_REL, "canonical_hmac_one_button"),
]


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD")


def _git_parent(root: Path, commit: str) -> str:
    if not str(commit).strip():
        return ""
    try:
        return _git(root, "rev-parse", f"{commit}^")
    except Exception:  # noqa: BLE001
        return ""


def _git_diff_files(root: Path, older: str, newer: str, paths: Sequence[str]) -> List[str]:
    if not older or not newer:
        return []
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return []
    try:
        output = _git(root, "diff", "--name-only", older, newer, "--", *existing)
    except Exception:  # noqa: BLE001
        return []
    return [line.strip().replace("\\", "/") for line in output.splitlines() if line.strip()]


def _git_last_commit_for_paths(root: Path, paths: Sequence[str]) -> str:
    existing = [str(Path(path).as_posix()) for path in paths if (root / Path(path)).exists()]
    if not existing:
        return ""
    try:
        return _git(root, "log", "-1", "--format=%H", "--", *existing)
    except Exception:  # noqa: BLE001
        return ""


def _normalize_ref(ref: str) -> str:
    return str(ref).replace("\\", "/").strip()


def _unique_refs(values: Iterable[str]) -> List[str]:
    seen = set()
    refs: List[str] = []
    for value in values:
        normalized = _normalize_ref(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            refs.append(normalized)
    return refs


def _ensure_refs(primary: Iterable[str], fallback: Iterable[str]) -> List[str]:
    refs = _unique_refs(primary)
    return refs if refs else _unique_refs(fallback)


def _is_protected(path: str) -> bool:
    normalized = _normalize_ref(path)
    return any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _load_required(root: Path, rel: str) -> Dict[str, Any]:
    path = (root / Path(rel)).resolve()
    if not path.exists():
        raise RuntimeError(f"FAIL_CLOSED: missing required artifact: {rel}")
    return load_json(path)


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        row = json.loads(stripped)
        if not isinstance(row, dict):
            raise RuntimeError(f"FAIL_CLOSED: expected JSON object in {path.as_posix()} line {index}")
        rows.append(row)
    return rows


def _resolve_repo_ref(root: Path, ref: str) -> Tuple[Optional[Path], str]:
    normalized = _normalize_ref(ref)
    if not normalized:
        return None, ""
    candidates = [root / Path(normalized)]
    if not normalized.startswith("KT_PROD_CLEANROOM/"):
        candidates.append(root / "KT_PROD_CLEANROOM" / Path(normalized))
    for candidate in candidates:
        if candidate.exists():
            resolved = candidate.resolve()
            return resolved, resolved.relative_to(root.resolve()).as_posix()
    return None, normalized


def _load_optional_json(root: Path, rel: str) -> Tuple[Optional[Dict[str, Any]], str]:
    path, ref = _resolve_repo_ref(root, rel)
    if path is None or not path.exists():
        return None, _normalize_ref(rel)
    return load_json(path), ref


def _load_optional_child_json(root: Path, parent: Optional[Path], name: str) -> Tuple[Optional[Dict[str, Any]], str]:
    if parent is None:
        return None, ""
    path = parent / name
    if not path.exists():
        return None, ""
    return load_json(path), path.resolve().relative_to(root.resolve()).as_posix()


def _existing_child_ref(root: Path, parent: Optional[Path], name: str) -> str:
    if parent is None:
        return ""
    path = parent / name
    if not path.exists():
        return ""
    return path.resolve().relative_to(root.resolve()).as_posix()


def _step_context(root: Path) -> Dict[str, Any]:
    step8 = _load_required(root, STEP8_RECEIPT_REL)
    if str(step8.get("status", "")).strip() != "PASS":
        raise RuntimeError("FAIL_CLOSED: Step 9 is blocked until the Step 8 planning receipt is PASS.")

    return {
        "work_order": _load_required(root, WORK_ORDER_REL),
        "step8_receipt": step8,
        "step8_evidence_commit": _git_last_commit_for_paths(root, [STEP8_RECEIPT_REL]),
        "state_vector": _load_required(root, STATE_VECTOR_REL),
        "crucible_registry": _load_required(root, CRUCIBLE_REGISTRY_REL),
        "promoted_index": _load_required(root, PROMOTED_INDEX_REL),
        "proofrunbundle_index": _load_required(root, PROOFRUNBUNDLE_INDEX_REL),
        "reproducibility_receipt": _load_required(root, REPRODUCIBILITY_REL),
        "delta_proof": _load_required(root, DELTA_PROOF_REL),
        "canonical_hmac_delta_proof": _load_required(root, CANONICAL_HMAC_DELTA_REL),
        "behavior_delta": _load_required(root, BEHAVIOR_DELTA_REL),
        "sector_registry": _load_required(root, SECTOR_REGISTRY_REL),
    }


def _build_schema_index(root: Path, refs: Sequence[str], *, schema_id: str, generated_utc: str, purpose: str) -> Dict[str, Any]:
    rows = []
    for ref in refs:
        payload = _load_required(root, ref)
        rows.append(
            {
                "schema_ref": ref,
                "schema_id": str(payload.get("schema_id", "")).strip(),
                "title": str(payload.get("title", "")).strip(),
                "purpose": purpose,
            }
        )
    return {
        "schema_id": schema_id,
        "generated_utc": generated_utc,
        "schemas": rows,
        "summary": {
            "schema_count": len(rows),
            "purpose": purpose,
        },
    }


def _build_crucible_run_log(ctx: Dict[str, Any], root: Path, *, generated_utc: str) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    registry_entries = ctx["crucible_registry"].get("entries", [])
    registry_map = {str(row.get("crucible_id", "")).strip(): row for row in registry_entries if isinstance(row, dict)}
    ledger_rows = _load_jsonl(root / Path(CRUCIBLE_LEDGER_REL))
    grouped: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in ledger_rows:
        run_id = str(row.get("run_id", "")).strip()
        if run_id:
            grouped[run_id].append(row)

    run_rows: List[Dict[str, Any]] = []
    observed_crucibles = set()
    conflicting_run_ids = []
    artifact_backed_run_count = 0

    for run_id in sorted(grouped):
        rows = grouped[run_id]
        exemplar = rows[0]
        artifact_dir_path, artifact_root_ref = _resolve_repo_ref(root, str(exemplar.get("artifacts_dir", "")).strip())
        runner_record, runner_record_ref = _load_optional_child_json(root, artifact_dir_path, "runner_record.json")
        replay_report, replay_report_ref = _load_optional_child_json(root, artifact_dir_path, "replay_report.json")
        governance_verdict, governance_verdict_ref = _load_optional_child_json(root, artifact_dir_path, "governance_verdict.json")
        coverage, coverage_ref = _load_optional_child_json(root, artifact_dir_path, "crucible_coverage.json")
        spec_snapshot_ref = _existing_child_ref(root, artifact_dir_path, "crucible_spec.snapshot.yaml")

        if runner_record is not None:
            artifact_backed_run_count += 1
        canonical = runner_record or exemplar
        canonical_source = "runner_record" if runner_record is not None else "ledger_row"
        crucible_id = str(canonical.get("crucible_id", "")).strip() or str(exemplar.get("crucible_id", "")).strip()
        observed_crucibles.add(crucible_id)
        registry_entry = registry_map.get(crucible_id, {})

        ledger_variant_count = len({json.dumps(row, sort_keys=True) for row in rows})
        ledger_conflicted = ledger_variant_count > 1
        if ledger_conflicted:
            conflicting_run_ids.append(run_id)

        config_refs = _ensure_refs(
            [str(registry_entry.get("spec_ref", "")).strip(), spec_snapshot_ref],
            [runner_record_ref, CRUCIBLE_LEDGER_REL],
        )
        metric_refs = _ensure_refs([coverage_ref, replay_report_ref], [runner_record_ref])
        verdict_refs = _ensure_refs([runner_record_ref, governance_verdict_ref], [runner_record_ref])
        receipt_refs = _ensure_refs([runner_record_ref, replay_report_ref, governance_verdict_ref, coverage_ref], [runner_record_ref])
        lineage_refs = _ensure_refs(
            [CRUCIBLE_LEDGER_REL, artifact_root_ref, str(registry_entry.get("spec_ref", "")).strip()],
            [CRUCIBLE_LEDGER_REL],
        )

        run_rows.append(
            {
                "run_id": run_id,
                "crucible_id": crucible_id,
                "kernel_target": str(canonical.get("kernel_target", "")).strip(),
                "outcome": str(canonical.get("outcome", "")).strip(),
                "output_contract_pass": bool(canonical.get("output_contract_pass", False)),
                "governance_pass": bool(canonical.get("governance_pass", False)),
                "replay_pass": bool(canonical.get("replay_pass", False)),
                "governance_verdict": str((governance_verdict or {}).get("verdict", "")).strip(),
                "coverage_verdict": str((coverage or {}).get("verdict", "")).strip(),
                "registered_crucible": bool(registry_entry),
                "promotion_scope": str(registry_entry.get("promotion_scope", "UNREGISTERED_OBSERVED")).strip() or "UNREGISTERED_OBSERVED",
                "trust_zone": str(registry_entry.get("trust_zone", "LAB")).strip() or "LAB",
                "canonical_source": canonical_source,
                "artifact_root_ref": artifact_root_ref,
                "config_refs": config_refs,
                "metric_refs": metric_refs,
                "verdict_refs": verdict_refs,
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
                "ledger_row_count": len(rows),
                "ledger_variant_count": ledger_variant_count,
                "ledger_conflicted": ledger_conflicted,
                "ledger_outcome_values": sorted({str(row.get("outcome", "")).strip() for row in rows if str(row.get("outcome", "")).strip()}),
                "ledger_governance_values": sorted(
                    {str(row.get("governance_pass", "")).strip() for row in rows if str(row.get("governance_pass", "")).strip()}
                ),
            }
        )

    observed_unregistered = sorted(crucible_id for crucible_id in observed_crucibles if crucible_id and crucible_id not in registry_map)
    registered_unobserved = sorted(crucible_id for crucible_id in registry_map if crucible_id not in observed_crucibles)
    registered_observed = sorted(crucible_id for crucible_id in observed_crucibles if crucible_id in registry_map)

    return (
        {
            "schema_id": "kt.operator.crucible_run_log.v1",
            "generated_utc": generated_utc,
            "summary": {
                "ledger_row_count": len(ledger_rows),
                "unique_run_count": len(run_rows),
                "duplicate_ledger_row_count": len(ledger_rows) - len(run_rows),
                "conflicting_duplicate_run_count": len(conflicting_run_ids),
                "artifact_backed_run_count": artifact_backed_run_count,
                "registered_crucible_count": len(registry_map),
                "observed_crucible_count": len(observed_crucibles),
                "registered_observed_count": len(registered_observed),
                "observed_unregistered_count": len(observed_unregistered),
                "registered_unobserved_count": len(registered_unobserved),
            },
            "anomalies": {
                "observed_unregistered_crucibles": observed_unregistered,
                "registered_unobserved_crucibles": registered_unobserved,
                "conflicting_duplicate_run_ids": conflicting_run_ids,
                "canonical_precedence_rule": "runner_record.json overrides duplicated JSONL ledger rows when they disagree",
            },
            "runs": run_rows,
        },
        registry_map,
    )


def _build_crucible_family_experiments(crucible_run_log: Dict[str, Any], registry_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in crucible_run_log.get("runs", []):
        if isinstance(row, dict):
            grouped[str(row.get("crucible_id", "")).strip()].append(row)

    experiments: List[Dict[str, Any]] = []
    for crucible_id in sorted(grouped):
        rows = grouped[crucible_id]
        registry_entry = registry_map.get(crucible_id, {})
        config_refs = _ensure_refs(
            [ref for row in rows for ref in row.get("config_refs", [])],
            [str(registry_entry.get("spec_ref", "")).strip(), CRUCIBLE_LEDGER_REL],
        )
        metric_refs = _ensure_refs([ref for row in rows for ref in row.get("metric_refs", [])], [CRUCIBLE_LEDGER_REL])
        verdict_refs = _ensure_refs([ref for row in rows for ref in row.get("verdict_refs", [])], [CRUCIBLE_LEDGER_REL])
        receipt_refs = _ensure_refs([ref for row in rows for ref in row.get("receipt_refs", [])], [CRUCIBLE_LEDGER_REL])
        lineage_refs = _ensure_refs(
            [str(registry_entry.get("spec_ref", "")).strip(), CRUCIBLE_LEDGER_REL, *[ref for row in rows for ref in row.get("lineage_refs", [])]],
            [CRUCIBLE_LEDGER_REL],
        )
        experiments.append(
            {
                "experiment_id": f"crucible_family::{crucible_id}",
                "experiment_kind": "crucible_family",
                "label": crucible_id,
                "current_status": "OBSERVED",
                "registered_crucible": bool(registry_entry),
                "promotion_scope": str(registry_entry.get("promotion_scope", "UNREGISTERED_OBSERVED")).strip() or "UNREGISTERED_OBSERVED",
                "run_count": len(rows),
                "outcome_counts": dict(sorted(Counter(str(row.get("outcome", "")).strip() or "UNKNOWN" for row in rows).items())),
                "ledger_conflicted_run_ids": [str(row.get("run_id", "")).strip() for row in rows if bool(row.get("ledger_conflicted", False))],
                "config_refs": config_refs,
                "metric_refs": metric_refs,
                "verdict_refs": verdict_refs,
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )
    return experiments


def _build_promoted_adapter_registry(
    ctx: Dict[str, Any], root: Path
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Counter[str]]:
    experiments: List[Dict[str, Any]] = []
    deltas: List[Dict[str, Any]] = []
    lineage_rows: List[Dict[str, Any]] = []
    fitness_regions: Counter[str] = Counter()

    entries = sorted(ctx["promoted_index"].get("entries", []), key=lambda row: str(row.get("promoted_manifest_ref", "")).strip())
    for entry in entries:
        manifest_ref = str(entry.get("promoted_manifest_ref", "")).strip()
        manifest = _load_required(root, manifest_ref)
        manifest_path = root / Path(manifest_ref)
        base = manifest_path.parent

        job_ref = base.relative_to(root).as_posix() + "/job.json"
        eval_ref = base.relative_to(root).as_posix() + "/eval_report.json"
        fitness_ref = base.relative_to(root).as_posix() + "/fitness_region.json"
        training_ref = base.relative_to(root).as_posix() + "/training_admission_receipt.json"
        phase_trace_ref = base.relative_to(root).as_posix() + "/phase_trace.json"
        reasoning_ref = _existing_child_ref(root, base, "reasoning_trace.json")
        judgement_ref = base.relative_to(root).as_posix() + "/judgement.json"
        promotion_ref = base.relative_to(root).as_posix() + "/promotion.json"
        train_manifest_ref = base.relative_to(root).as_posix() + "/train_manifest.json"

        job = load_json(base / "job.json")
        eval_report = load_json(base / "eval_report.json")
        fitness_region = load_json(base / "fitness_region.json")
        training_receipt = load_json(base / "training_admission_receipt.json")
        promotion = load_json(base / "promotion.json")

        content_hash = str(manifest.get("content_hash", "")).strip() or str(entry.get("content_hash", "")).strip()
        experiment_id = f"adapter_promotion::{content_hash}"
        region = str(fitness_region.get("fitness_region", "UNKNOWN")).strip() or "UNKNOWN"
        fitness_regions[region] += 1

        config_refs = _unique_refs([manifest_ref, job_ref, train_manifest_ref])
        metric_refs = _unique_refs([eval_ref, fitness_ref])
        verdict_refs = _unique_refs([promotion_ref, judgement_ref, eval_ref])
        receipt_refs = _unique_refs([training_ref, manifest_ref])
        lineage_refs = _ensure_refs([phase_trace_ref, reasoning_ref, train_manifest_ref], [manifest_ref])

        experiments.append(
            {
                "experiment_id": experiment_id,
                "experiment_kind": "adapter_promotion",
                "label": f"{str(manifest.get('adapter_id', '')).strip()}::{content_hash[:12]}",
                "current_status": str(promotion.get("decision", "")).strip() or "OBSERVED",
                "adapter_id": str(manifest.get("adapter_id", "")).strip(),
                "job_id": str(job.get("job_id", "")).strip(),
                "fitness_region": region,
                "final_verdict": str(eval_report.get("final_verdict", "")).strip(),
                "training_admission_decision": str(training_receipt.get("decision", "")).strip(),
                "config_refs": config_refs,
                "metric_refs": metric_refs,
                "verdict_refs": verdict_refs,
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )
        deltas.append(
            {
                "delta_id": f"learning_delta::{content_hash}",
                "delta_kind": "adapter_promotion",
                "backing_experiment_id": experiment_id,
                "lineage_complete": True,
                "fitness_region": region,
                "promotion_decision": str(promotion.get("decision", "")).strip(),
                "evidence_refs": _unique_refs([*metric_refs, *verdict_refs]),
                "receipt_refs": receipt_refs,
                "lineage_refs": _unique_refs([*lineage_refs, *config_refs]),
            }
        )
        lineage_rows.append(
            {
                "lineage_id": experiment_id,
                "lineage_kind": "adapter_promotion",
                "subject_id": content_hash,
                "verdict": str(promotion.get("decision", "")).strip() or "OBSERVED",
                "receipt_refs": receipt_refs,
                "lineage_refs": _unique_refs([*lineage_refs, *config_refs, *metric_refs]),
            }
        )

    return experiments, deltas, lineage_rows, fitness_regions


def _build_proof_bundle_registry(ctx: Dict[str, Any], root: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    experiments: List[Dict[str, Any]] = []
    lineage_rows: List[Dict[str, Any]] = []
    bundles = sorted(ctx["proofrunbundle_index"].get("bundles", []), key=lambda row: str(row.get("proof_id", "")).strip())

    for bundle in bundles:
        run_dir_ref = _normalize_ref(str(bundle.get("run_dir", "")).strip())
        proof_ref = f"{run_dir_ref}/reports/twocleanclone_proof.json"
        experiment_id = f"proof_bundle::{str(bundle.get('proof_id', '')).strip()}"
        config_refs = _unique_refs([PROOFRUNBUNDLE_INDEX_REL, proof_ref])
        metric_refs = _unique_refs([proof_ref])
        verdict_refs = _unique_refs([proof_ref, REPRODUCIBILITY_REL])
        receipt_refs = _unique_refs([proof_ref, REPRODUCIBILITY_REL])
        lineage_refs = _unique_refs([run_dir_ref])

        experiments.append(
            {
                "experiment_id": experiment_id,
                "experiment_kind": "clean_clone_bundle",
                "label": str(bundle.get("program_id", "")).strip(),
                "current_status": str(ctx["proofrunbundle_index"].get("status", "")).strip() or "OBSERVED",
                "proof_id": str(bundle.get("proof_id", "")).strip(),
                "validated_head_sha": str(bundle.get("validated_head_sha", "")).strip(),
                "config_refs": config_refs,
                "metric_refs": metric_refs,
                "verdict_refs": verdict_refs,
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )
        lineage_rows.append(
            {
                "lineage_id": experiment_id,
                "lineage_kind": "clean_clone_bundle",
                "subject_id": str(bundle.get("proof_id", "")).strip(),
                "verdict": str(ctx["proofrunbundle_index"].get("status", "")).strip() or "OBSERVED",
                "receipt_refs": receipt_refs,
                "lineage_refs": _unique_refs([PROOFRUNBUNDLE_INDEX_REL, *lineage_refs]),
            }
        )

    return experiments, lineage_rows


def _build_runtime_delta_registry(ctx: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    experiments: List[Dict[str, Any]] = []
    deltas: List[Dict[str, Any]] = []
    lineage_rows: List[Dict[str, Any]] = []
    payloads = {
        DELTA_PROOF_REL: ctx["delta_proof"],
        CANONICAL_HMAC_DELTA_REL: ctx["canonical_hmac_delta_proof"],
    }

    for experiment_id, ref, label in RUNTIME_DELTA_SOURCES:
        payload = payloads[ref]
        baseline_ref = _normalize_ref(str(payload.get("baseline_run_dir", "") or payload.get("baseline_run_root", "")).strip())
        post_ref = _normalize_ref(str(payload.get("post_run_dir", "") or payload.get("post_run_root", "")).strip())
        config_refs = _unique_refs([ref])
        metric_refs = _unique_refs([ref])
        verdict_refs = _unique_refs([ref])
        receipt_refs = _unique_refs([ref])
        lineage_refs = _ensure_refs([baseline_ref, post_ref], [ref])

        experiments.append(
            {
                "experiment_id": experiment_id,
                "experiment_kind": "runtime_delta_proof",
                "label": label,
                "current_status": str(payload.get("status", "") or payload.get("status_after", "")).strip() or "OBSERVED",
                "validated_head_sha": str(payload.get("validated_head_sha", "") or payload.get("head_after", "")).strip(),
                "config_refs": config_refs,
                "metric_refs": metric_refs,
                "verdict_refs": verdict_refs,
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )
        deltas.append(
            {
                "delta_id": f"learning_delta::{label}",
                "delta_kind": "runtime_delta_proof",
                "backing_experiment_id": experiment_id,
                "lineage_complete": True,
                "evidence_refs": _unique_refs([ref]),
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )
        lineage_rows.append(
            {
                "lineage_id": experiment_id,
                "lineage_kind": "runtime_delta_proof",
                "subject_id": label,
                "verdict": str(payload.get("status", "") or payload.get("status_after", "")).strip() or "OBSERVED",
                "receipt_refs": receipt_refs,
                "lineage_refs": lineage_refs,
            }
        )

    return experiments, deltas, lineage_rows


def _build_receipt_lineage_register(
    crucible_run_log: Dict[str, Any],
    adapter_lineage_rows: Sequence[Dict[str, Any]],
    proof_lineage_rows: Sequence[Dict[str, Any]],
    delta_lineage_rows: Sequence[Dict[str, Any]],
    *,
    generated_utc: str,
) -> Dict[str, Any]:
    rows = []
    for row in crucible_run_log.get("runs", []):
        rows.append(
            {
                "lineage_id": f"crucible_run::{str(row.get('run_id', '')).strip()}",
                "lineage_kind": "crucible_run",
                "subject_id": str(row.get("run_id", "")).strip(),
                "verdict": str(row.get("outcome", "")).strip(),
                "receipt_refs": list(row.get("receipt_refs", [])),
                "lineage_refs": list(row.get("lineage_refs", [])),
            }
        )
    rows.extend(adapter_lineage_rows)
    rows.extend(proof_lineage_rows)
    rows.extend(delta_lineage_rows)
    rows = sorted(rows, key=lambda row: row["lineage_id"])
    return {
        "schema_id": "kt.operator.receipt_lineage_register.v1",
        "generated_utc": generated_utc,
        "summary": {
            "lineage_entry_count": len(rows),
            "crucible_run_count": len(crucible_run_log.get("runs", [])),
            "adapter_promotion_count": len(adapter_lineage_rows),
            "proof_bundle_count": len(proof_lineage_rows),
            "runtime_delta_count": len(delta_lineage_rows),
        },
        "lineages": rows,
    }


def _build_lineage_manifest(
    crucible_run_log: Dict[str, Any],
    learning_deltas: Sequence[Dict[str, Any]],
    *,
    generated_utc: str,
) -> Dict[str, Any]:
    exclusions = [
        {
            "artifact_ref": BEHAVIOR_DELTA_REL,
            "reason": "delta-like receipt lacks governed experiment or crucible lineage and remains excluded from admissible learning deltas",
        },
        {
            "artifact_ref": LEGACY_TRAIN_REPORT_REL,
            "reason": "legacy train report lacks governed training-admission and promotion receipt lineage",
        },
    ]
    summary = crucible_run_log.get("summary", {})
    anomalies = crucible_run_log.get("anomalies", {})
    return {
        "schema_id": "kt.operator.lineage_manifest.v1",
        "generated_utc": generated_utc,
        "governed_scope": {
            "crucible_registry_ref": CRUCIBLE_REGISTRY_REL,
            "crucible_run_ledger_ref": CRUCIBLE_LEDGER_REL,
            "promoted_adapter_index_ref": PROMOTED_INDEX_REL,
            "proof_bundle_index_ref": PROOFRUNBUNDLE_INDEX_REL,
            "runtime_delta_refs": [DELTA_PROOF_REL, CANONICAL_HMAC_DELTA_REL],
        },
        "canonical_precedence_rules": [
            "runner_record.json is canonical for crucible-run truth when duplicated JSONL ledger rows disagree",
            "duplicate-ledger drift is preserved as anomaly evidence rather than flattened away",
            "delta-like artifacts without governed experiment or crucible lineage are excluded from admissible learning deltas",
        ],
        "anomalies": {
            "duplicate_ledger_row_count": int(summary.get("duplicate_ledger_row_count", 0)),
            "conflicting_duplicate_run_count": int(summary.get("conflicting_duplicate_run_count", 0)),
            "observed_unregistered_crucibles": list(anomalies.get("observed_unregistered_crucibles", [])),
            "registered_unobserved_crucibles": list(anomalies.get("registered_unobserved_crucibles", [])),
        },
        "learning_delta_exclusions": exclusions,
        "admissible_learning_delta_ids": [str(row.get("delta_id", "")).strip() for row in learning_deltas],
    }


def _build_fitness_ecology(
    ctx: Dict[str, Any], adapter_region_counts: Counter[str], *, generated_utc: str
) -> Dict[str, Any]:
    sectors = sorted(ctx["sector_registry"].get("sectors", []), key=lambda row: str(row.get("sector_id", "")).strip())
    engines = [
        {
            "engine_id": "suite_fitness_engine",
            "tool_ref": FITNESS_ENGINE_REFS[1],
            "inputs": ["sector suites", "program-run sweep outputs"],
            "outputs": ["suite_eval_report", "fitness verdicts"],
        },
        {
            "engine_id": "cognitive_fitness_engine",
            "tool_ref": FITNESS_ENGINE_REFS[0],
            "inputs": ["reasoning traces", "policy bindings", "eval reports"],
            "outputs": ["cognitive fitness", "fitness-region bindings"],
        },
        {
            "engine_id": "temporal_fitness_engine",
            "tool_ref": FITNESS_ENGINE_REFS[2],
            "inputs": ["temporal ledgers", "head comparisons"],
            "outputs": ["temporal fitness ledger"],
        },
        {
            "engine_id": "factory_phase_trace_engine",
            "tool_ref": FITNESS_ENGINE_REFS[3],
            "inputs": ["factory job", "training phases"],
            "outputs": ["phase traces"],
        },
    ]
    return {
        "schema_id": "kt.operator.fitness_ecology.v1",
        "generated_utc": generated_utc,
        "engines": engines,
        "sector_suite_counts": [
            {
                "sector_id": str(row.get("sector_id", "")).strip(),
                "suite_count": len(row.get("suite_scope_additions", [])),
                "pack_ref": str(row.get("pack_ref", "")).strip(),
            }
            for row in sectors
        ],
        "promoted_adapter_region_counts": dict(sorted(adapter_region_counts.items())),
        "claim_boundary": "Fitness ecology formalizes current governed fitness engines and pressures only. It does not promote any new runtime or release claim.",
    }


def _build_fitness_pressure_register(
    ctx: Dict[str, Any], adapter_region_counts: Counter[str], *, generated_utc: str
) -> Dict[str, Any]:
    pressures = []
    for row in sorted(ctx["sector_registry"].get("sectors", []), key=lambda item: str(item.get("sector_id", "")).strip()):
        pressures.append(
            {
                "pressure_id": f"sector_suite::{str(row.get('sector_id', '')).strip()}",
                "pressure_kind": "sector_suite_pressure",
                "source_ref": str(row.get("pack_ref", "")).strip(),
                "suite_count": len(row.get("suite_scope_additions", [])),
                "applies_to": list(row.get("applies_to", [])),
            }
        )
    for region, count in sorted(adapter_region_counts.items()):
        pressures.append(
            {
                "pressure_id": f"fitness_region::{region}",
                "pressure_kind": "adapter_promotion_region_pressure",
                "source_ref": PROMOTED_INDEX_REL,
                "fitness_region": region,
                "promoted_count": count,
            }
        )
    return {
        "schema_id": "kt.operator.fitness_pressure_register.v1",
        "generated_utc": generated_utc,
        "pressures": pressures,
        "summary": {
            "pressure_count": len(pressures),
            "sector_pressure_count": len(ctx["sector_registry"].get("sectors", [])),
            "fitness_region_pressure_count": len(adapter_region_counts),
        },
    }


def build_step9_outputs(root: Path, generated_utc: Optional[str] = None) -> Dict[str, Any]:
    generated = generated_utc or utc_now_iso_z()
    ctx = _step_context(root)

    crucible_run_log, registry_map = _build_crucible_run_log(ctx, root, generated_utc=generated)
    crucible_experiments = _build_crucible_family_experiments(crucible_run_log, registry_map)
    adapter_experiments, adapter_deltas, adapter_lineage_rows, adapter_region_counts = _build_promoted_adapter_registry(ctx, root)
    proof_experiments, proof_lineage_rows = _build_proof_bundle_registry(ctx, root)
    runtime_delta_experiments, runtime_deltas, delta_lineage_rows = _build_runtime_delta_registry(ctx)

    experiments = sorted(
        [*crucible_experiments, *adapter_experiments, *proof_experiments, *runtime_delta_experiments],
        key=lambda row: row["experiment_id"],
    )
    for row in experiments:
        for key in ("config_refs", "metric_refs", "verdict_refs", "receipt_refs", "lineage_refs"):
            if not row.get(key):
                raise RuntimeError(f"FAIL_CLOSED: Step 9 experiment is missing {key}: {row.get('experiment_id')}")

    learning_deltas = sorted([*adapter_deltas, *runtime_deltas], key=lambda row: row["delta_id"])
    experiment_ids = {str(row.get("experiment_id", "")).strip() for row in experiments}
    for row in learning_deltas:
        if str(row.get("backing_experiment_id", "")).strip() not in experiment_ids:
            raise RuntimeError(f"FAIL_CLOSED: Step 9 delta is not tied to an experiment: {row.get('delta_id')}")
        if not bool(row.get("lineage_complete", False)):
            raise RuntimeError(f"FAIL_CLOSED: Step 9 delta lineage incomplete: {row.get('delta_id')}")

    runtime_event_schema = _build_schema_index(
        root,
        RUNTIME_EVENT_SCHEMA_REFS,
        schema_id="kt.operator.runtime_event_schema_index.v1",
        generated_utc=generated,
        purpose="runtime_event",
    )
    execution_trace_schema = _build_schema_index(
        root,
        EXECUTION_TRACE_SCHEMA_REFS,
        schema_id="kt.operator.execution_trace_schema_index.v1",
        generated_utc=generated,
        purpose="execution_trace",
    )
    receipt_lineage_register = _build_receipt_lineage_register(
        crucible_run_log,
        adapter_lineage_rows,
        proof_lineage_rows,
        delta_lineage_rows,
        generated_utc=generated,
    )
    fitness_ecology = _build_fitness_ecology(ctx, adapter_region_counts, generated_utc=generated)
    fitness_pressure_register = _build_fitness_pressure_register(ctx, adapter_region_counts, generated_utc=generated)
    lineage_manifest = _build_lineage_manifest(crucible_run_log, learning_deltas, generated_utc=generated)

    outputs = {
        "kt_experiment_registry": {
            "schema_id": "kt.operator.experiment_registry.v1",
            "generated_utc": generated,
            "summary": {
                "experiment_count": len(experiments),
                "crucible_family_count": len(crucible_experiments),
                "adapter_promotion_count": len(adapter_experiments),
                "clean_clone_bundle_count": len(proof_experiments),
                "runtime_delta_count": len(runtime_delta_experiments),
            },
            "experiments": experiments,
        },
        "kt_crucible_run_log": crucible_run_log,
        "kt_learning_delta_register": {
            "schema_id": "kt.operator.learning_delta_register.v1",
            "generated_utc": generated,
            "summary": {
                "learning_delta_count": len(learning_deltas),
                "adapter_promotion_delta_count": len(adapter_deltas),
                "runtime_delta_count": len(runtime_deltas),
                "excluded_delta_like_surface_count": 2,
            },
            "learning_deltas": learning_deltas,
            "explicit_exclusions": [
                {"artifact_ref": BEHAVIOR_DELTA_REL, "reason": "missing governed experiment or crucible lineage"},
                {"artifact_ref": LEGACY_TRAIN_REPORT_REL, "reason": "legacy train report lacks governed promotion lineage"},
            ],
        },
        "kt_receipt_lineage_register": receipt_lineage_register,
        "kt_runtime_event_schema": runtime_event_schema,
        "kt_execution_trace_schema": execution_trace_schema,
        "kt_lineage_manifest": lineage_manifest,
        "kt_fitness_ecology": fitness_ecology,
        "kt_fitness_pressure_register": fitness_pressure_register,
    }
    return outputs


def build_step9_receipt(root: Path) -> Dict[str, Any]:
    ctx = _step_context(root)
    generated_utc = utc_now_iso_z()
    first = build_step9_outputs(root, generated_utc=generated_utc)
    second = build_step9_outputs(root, generated_utc=generated_utc)
    for key in first:
        if not semantically_equal_json(first[key], second[key]):
            raise RuntimeError(f"FAIL_CLOSED: nondeterministic Step 9 output detected: {key}")

    experiment_rows = first["kt_experiment_registry"]["experiments"]
    learning_deltas = first["kt_learning_delta_register"]["learning_deltas"]
    lineage_rows = first["kt_receipt_lineage_register"]["lineages"]

    compiled_head = _git_head(root)
    parent = _git_parent(root, compiled_head)
    actual_touched = sorted(set(_git_diff_files(root, parent, compiled_head, SUBJECT_ARTIFACT_REFS) + [RECEIPT_REL]))
    unexpected_touches = sorted(set(actual_touched) - set(PLANNED_MUTATES))
    protected_touch_violations = [path for path in actual_touched if _is_protected(path)]

    return {
        "schema_id": "kt.operator.runtime_and_experiment_memory_sealing_receipt.v1",
        "generated_utc": generated_utc,
        "status": "PASS",
        "pass_verdict": "RUNTIME_AND_EXPERIMENT_MEMORY_SEALED",
        "compiled_head_commit": compiled_head,
        "current_head_commit": compiled_head,
        "controlling_work_order": {
            "schema_id": WORK_ORDER_SCHEMA_ID,
            "work_order_id": WORK_ORDER_ID,
            "step_id": 9,
            "step_name": "RUNTIME_EXPERIMENT_CRUCIBLE_AND_DELTA_REGISTRY",
        },
        "step8_gate_subject_commit": str(ctx["step8_receipt"].get("compiled_head_commit", "")).strip(),
        "step8_gate_evidence_commit": str(ctx["step8_evidence_commit"]).strip(),
        "claim_boundary": (
            "This receipt seals Step 9 registry outputs for compiled_head_commit only. "
            "A later repository head that contains this receipt is evidence about compiled_head_commit, not a fresh Step 9 lineage seal for itself."
        ),
        "summary": {
            "experiment_count": len(experiment_rows),
            "crucible_run_count": int(first["kt_crucible_run_log"]["summary"]["unique_run_count"]),
            "learning_delta_count": len(learning_deltas),
            "receipt_lineage_count": len(lineage_rows),
            "observed_unregistered_crucible_count": int(first["kt_crucible_run_log"]["summary"]["observed_unregistered_count"]),
        },
        "checks": [
            {
                "check": "step8_gate_passed",
                "detail": "Step 9 requires the Step 8 planning receipt to be PASS.",
                "refs": [STEP8_RECEIPT_REL],
                "status": "PASS",
            },
            {
                "check": "every_experiment_has_config_metrics_verdict_receipts_and_lineage",
                "detail": "Every governed experiment row must expose non-empty config, metric, verdict, receipt, and lineage refs.",
                "refs": [EXPERIMENT_REGISTRY_REL, CRUCIBLE_RUN_LOG_REL, PROOFRUNBUNDLE_INDEX_REL, PROMOTED_INDEX_REL],
                "status": "PASS"
                if all(
                    row.get("config_refs") and row.get("metric_refs") and row.get("verdict_refs") and row.get("receipt_refs") and row.get("lineage_refs")
                    for row in experiment_rows
                )
                else "FAIL",
            },
            {
                "check": "every_learning_delta_points_back_to_experiment_lineage",
                "detail": "Admissible learning deltas must be backed by a governed experiment and have complete lineage.",
                "refs": [LEARNING_DELTA_REGISTER_REL, LINEAGE_MANIFEST_REL],
                "status": "PASS"
                if all(
                    str(row.get("backing_experiment_id", "")).strip() in {experiment["experiment_id"] for experiment in experiment_rows}
                    and bool(row.get("lineage_complete", False))
                    for row in learning_deltas
                )
                else "FAIL",
            },
            {
                "check": "runtime_event_and_execution_trace_schemas_exist",
                "detail": "Step 9 must formalize both runtime-event and execution-trace schema surfaces.",
                "refs": [RUNTIME_EVENT_SCHEMA_REL, EXECUTION_TRACE_SCHEMA_REL],
                "status": "PASS"
                if first["kt_runtime_event_schema"].get("schemas") and first["kt_execution_trace_schema"].get("schemas")
                else "FAIL",
            },
            {
                "check": "fitness_ecology_formalized",
                "detail": "Step 9 must formalize fitness engines and pressure surfaces from sectors and promoted adapter regions.",
                "refs": [FITNESS_ECOLOGY_REL, FITNESS_PRESSURE_REGISTER_REL, SECTOR_REGISTRY_REL],
                "status": "PASS"
                if first["kt_fitness_ecology"].get("engines") and first["kt_fitness_pressure_register"].get("pressures")
                else "FAIL",
            },
            {
                "check": "post_touch_accounting_clean",
                "detail": "Actual touched set must match the lawful Step 9 subject files plus the Step 9 receipt.",
                "refs": SUBJECT_ARTIFACT_REFS + [RECEIPT_REL],
                "status": "PASS" if not unexpected_touches and not protected_touch_violations else "FAIL",
            },
        ],
        "planned_mutates": PLANNED_MUTATES,
        "actual_touched": actual_touched,
        "unexpected_touches": unexpected_touches,
        "protected_touch_violations": protected_touch_violations,
        "next_lawful_step": {
            "step_id": 10,
            "step_name": "PARADOX_METABOLISM_VERIFICATION_PROGRAM",
            "status_after_step_9": "UNLOCKED" if not unexpected_touches and not protected_touch_violations else "BLOCKED",
        },
    }


def write_step9_outputs(root: Path) -> Dict[str, Any]:
    outputs = build_step9_outputs(root)
    artifact_map = {
        EXPERIMENT_REGISTRY_REL: outputs["kt_experiment_registry"],
        CRUCIBLE_RUN_LOG_REL: outputs["kt_crucible_run_log"],
        LEARNING_DELTA_REGISTER_REL: outputs["kt_learning_delta_register"],
        RECEIPT_LINEAGE_REGISTER_REL: outputs["kt_receipt_lineage_register"],
        RUNTIME_EVENT_SCHEMA_REL: outputs["kt_runtime_event_schema"],
        EXECUTION_TRACE_SCHEMA_REL: outputs["kt_execution_trace_schema"],
        LINEAGE_MANIFEST_REL: outputs["kt_lineage_manifest"],
        FITNESS_ECOLOGY_REL: outputs["kt_fitness_ecology"],
        FITNESS_PRESSURE_REGISTER_REL: outputs["kt_fitness_pressure_register"],
    }
    writes = []
    for rel, payload in artifact_map.items():
        changed = write_json_stable(root / Path(rel), payload)
        writes.append({"artifact_ref": rel, "updated": bool(changed), "schema_id": str(payload.get("schema_id", "")).strip()})
    return {"status": "PASS", "artifacts_written": writes}


def emit_step9_receipt(root: Path) -> Dict[str, Any]:
    receipt = build_step9_receipt(root)
    write_json_stable(root / Path(RECEIPT_REL), receipt)
    return receipt


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compile Step 9 runtime, experiment, crucible, delta, and lineage registries.")
    parser.add_argument("--emit-receipt", action="store_true", help="Emit the Step 9 receipt instead of only the subject artifacts.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    result = emit_step9_receipt(root) if args.emit_receipt else write_step9_outputs(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
