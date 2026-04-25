from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema, MODE_DRY_RUN as COGNITION_MODE_DRY_RUN
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from council.council_router import CouncilRouter
from council.council_schemas import CouncilPlanSchema, CouncilRequestSchema, MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN
from memory.replay import validate_state_vault_chain
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH
from schemas.schema_hash import canonical_json, sha256_text
from tools.operator.claim_compiler import build_claim_compiler_receipt
from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.public_verifier import build_public_verifier_report
from tools.operator.public_verifier_detached_validate import (
    DETACHED_RUNTIME_TOOL_REL,
    PACKAGED_INPUT_REFS,
    PARITY_FIELDS,
    _build_hmac_signoffs,
    _copy_packaged_file,
    _local_dependency_closure,
    _package_root_sha256,
    _validate_revision_policy_trust_roots,
    _verify_signoffs,
)
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/wave3_minimum_viable_civilization"
WAVE_ID = "WAVE_3_MINIMUM_VIABLE_CIVILIZATION_RUN_AND_DETACHED_VERIFIER"
WORK_ORDER_ID = "KT_UNIFIED_CONVERGENCE_MAX_POWER_CAMPAIGN_V2_1_1_FINAL"
OPEN_CONTRADICTIONS = [
    "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
    "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
    "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
    "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE",
]
MAIN_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave3_minimum_viable_civilization_run_pack.json"
DETACHED_VERIFIER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave3_detached_verifier_receipt.json"
CLAIM_COMPILER_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave3_claim_compiler_receipt.json"
CLAIM_CLASS_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave3_claim_class_matrix.json"
BOUNDED_OUTPUT_REL = f"{REPORT_ROOT_REL}/kt_wave3_bounded_output.json"
TOOLCHAIN_TELEMETRY_REL = f"{REPORT_ROOT_REL}/kt_wave3_toolchain_telemetry.jsonl"
DETACHED_BOUNDARY = (
    "Wave 3 detached verifier proves same-host packaged detached replay only. "
    "It does not claim independent hostile replay, public challenge survival, or external confirmation above E1."
)


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _tool_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _base_context() -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _emit_toolchain(path: Path, *, probe_id: str, receipt_ref: str, result_status: str) -> None:
    started = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id=f"tools.operator.wave3.{probe_id}",
        zone="TOOLCHAIN_PROVING",
        event_type="wave3.probe",
        start_ts=started,
        end_ts=telemetry_now_ms(),
        result_status=result_status,
        policy_applied="wave3.minimum_viable_civilization",
        receipt_ref=receipt_ref,
        trace_id=f"wave3-{probe_id}",
        request_id=f"wave3.{probe_id}",
        path=path,
    )


def _expected_specs(registry_hash: str) -> List[Dict[str, Any]]:
    base_context = _base_context()

    council_request = CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "wave3.council.request",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_DRY_RUN,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 128,
            "total_token_cap": 256,
            "input_hash": sha256_text("wave3 council input"),
        }
    )
    council_plan = CouncilRouter.plan(context=base_context, request=council_request).to_dict()
    council_result = CouncilRouter.execute(context=base_context, plan=CouncilPlanSchema.from_dict(council_plan)).to_dict()

    cognition_request = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "wave3.cognition.request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("wave3 cognition input"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("wave3.trace"), "artifact_id": "wave3.trace"}],
        }
    )
    cognition_plan = CognitiveEngine.plan(context=base_context, request=cognition_request).to_dict()
    cognition_result = CognitiveEngine.execute(context=base_context, plan=CognitivePlanSchema.from_dict(cognition_plan)).to_dict()

    return [
        {
            "step_id": "router_plan",
            "path_role": "router",
            "payload": council_request.to_dict(),
            "slice_key": "council",
            "expected": {
                "status": council_plan["status"],
                "mode": council_plan["mode"],
                "plan_hash": council_plan["plan_hash"],
                "request_hash": council_plan["request_hash"],
            },
        },
        {
            "step_id": "adapter_execute",
            "path_role": "adapter_or_provider",
            "payload": CouncilPlanSchema.from_dict(council_plan).to_dict(),
            "slice_key": "council",
            "expected": {
                "status": council_result["status"],
                "plan_hash": council_result["plan_hash"],
                "result_hash": council_result["result_hash"],
            },
            "extra_assertions": {"invocation_count": 1},
        },
        {
            "step_id": "organ_plan",
            "path_role": "organ_stack",
            "payload": cognition_request.to_dict(),
            "slice_key": "cognition",
            "expected": {
                "status": cognition_plan["status"],
                "mode": cognition_plan["mode"],
                "plan_hash": cognition_plan["plan_hash"],
                "request_hash": cognition_plan["request_hash"],
                "steps": len(cognition_plan["steps"]),
            },
        },
        {
            "step_id": "organ_execute",
            "path_role": "organ_stack",
            "payload": CognitivePlanSchema.from_dict(cognition_plan).to_dict(),
            "slice_key": "cognition",
            "expected": {
                "status": cognition_result["status"],
                "plan_hash": cognition_result["plan_hash"],
                "result_hash": cognition_result["result_hash"],
                "steps": len(cognition_result["steps"]),
            },
        },
    ]


def _run_entry_probe(root: Path, export_root: Path, telemetry_path: Path, spec: Dict[str, Any]) -> Dict[str, Any]:
    probe_root = (export_root / "canonical_run" / spec["step_id"]).resolve()
    probe_root.mkdir(parents=True, exist_ok=True)
    artifact_root = (probe_root / "artifacts").resolve()
    payload_path = probe_root / "payload.json"
    output_path = probe_root / "entry_result.json"
    runtime_telemetry_path = probe_root / "runtime_telemetry.jsonl"

    payload = dict(spec["payload"])
    payload_path.write_text(canonical_json(payload), encoding="utf-8")
    env = _tool_env(root)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.wave3_canonical_entry_probe",
            "--payload-file",
            str(payload_path),
            "--artifact-root",
            str(artifact_root),
            "--output",
            str(output_path),
            "--telemetry-output",
            str(runtime_telemetry_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: Wave 3 canonical entry probe failed for {spec['step_id']}: {proc.stdout}")

    probe_payload = json.loads(output_path.read_text(encoding="utf-8"))
    result = dict(probe_payload["entry_result"])
    if str(result.get("status", "")).strip() != "OK":
        raise RuntimeError(f"FAIL_CLOSED: Wave 3 canonical entry result not OK for {spec['step_id']}: {result}")

    runtime_slice = result.get(str(spec["slice_key"]), {})
    comparison = {key: runtime_slice.get(key) == value for key, value in spec["expected"].items()}
    extra = {}
    expected_count = spec.get("extra_assertions", {}).get("invocation_count")
    if expected_count is not None:
        observed = len(runtime_slice.get("invocation_ids", [])) if isinstance(runtime_slice.get("invocation_ids"), list) else 0
        comparison["invocation_count"] = observed == int(expected_count)
        extra["invocation_count"] = {"expected": int(expected_count), "observed": observed}
    comparison_pass = all(comparison.values())
    governance_verdict_path = artifact_root / "governance_verdict.json"
    row = {
        "step_id": spec["step_id"],
        "path_role": spec["path_role"],
        "entrypoint": "kt.entrypoint.invoke",
        "canonical_spine": "core.spine.run",
        "payload_schema_id": payload.get("schema_id", ""),
        "status": "PASS" if comparison_pass else "FAIL",
        "comparison_pass": comparison_pass,
        "comparison": comparison,
        "expected_fields": dict(spec["expected"]),
        "observed_fields": {key: runtime_slice.get(key) for key in spec["expected"]},
        "extra_assertions": extra,
        "result_head_hash": result.get("head_hash", ""),
        "result_record_count": result.get("record_count", 0),
        "artifact_refs": {
            "artifact_root_ref": _rel(root, artifact_root),
            "payload_ref": _rel(root, payload_path),
            "entry_result_ref": _rel(root, output_path),
            "runtime_telemetry_ref": _rel(root, runtime_telemetry_path) if runtime_telemetry_path.exists() else "",
            "governance_verdict_ref": _rel(root, governance_verdict_path) if governance_verdict_path.exists() else "",
        },
    }
    _emit_toolchain(telemetry_path, probe_id=spec["step_id"], receipt_ref=row["artifact_refs"]["entry_result_ref"], result_status=row["status"])
    return row


def _parity_map(repo_local_report: Dict[str, Any], detached_report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for field in PARITY_FIELDS:
        left = repo_local_report.get(field)
        right = detached_report.get(field)
        rows[field] = {"repo_local": left, "detached": right, "match": left == right}
    return rows


def _build_detached_verifier(root: Path, export_root: Path) -> Dict[str, Any]:
    ws17_policy = load_json((root / "KT_PROD_CLEANROOM" / "reports" / "kt_signed_revision_policy.json").resolve())
    trust_roots = _validate_revision_policy_trust_roots(ws17_policy)

    detached_root = (export_root / "detached_verifier").resolve()
    if detached_root.exists():
        shutil.rmtree(detached_root)
    package_root = (detached_root / "package").resolve()
    detached_cwd = (package_root / "KT_PROD_CLEANROOM").resolve()
    reports_root = (detached_root / "reports").resolve()
    reports_root.mkdir(parents=True, exist_ok=True)

    source_closure = _local_dependency_closure(root, DETACHED_RUNTIME_TOOL_REL)
    package_components = [_copy_packaged_file(root, package_root, rel) for rel in sorted(set([*source_closure, *PACKAGED_INPUT_REFS]))]
    package_root_sha256 = _package_root_sha256(package_components)
    package_manifest = {
        "schema_id": "kt.wave3.detached_verifier_package_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "compiled_head_commit": _git_head(root),
        "detached_entrypoint": "python -m tools.operator.public_verifier_detached_runtime",
        "detached_package_root_ref": _rel(root, package_root),
        "package_root_sha256": package_root_sha256,
        "source_dependency_closure": list(source_closure),
        "packaged_input_refs": list(PACKAGED_INPUT_REFS),
        "packaged_file_count": len(package_components),
        "release_signatures": _build_hmac_signoffs(package_root_sha256, trust_roots),
        "repo_local_parity_fields": list(PARITY_FIELDS),
        "stronger_claim_not_made": DETACHED_BOUNDARY,
        "included_paths": [row["path"] for row in package_components],
    }
    package_sbom = {
        "schema_id": "kt.wave3.detached_verifier_package_sbom.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "package_root_sha256": package_root_sha256,
        "component_count": len(package_components),
        "components": list(package_components),
    }
    manifest_path = reports_root / "wave3_detached_verifier_package_manifest.json"
    sbom_path = reports_root / "wave3_detached_verifier_package_sbom.json"
    detached_report_path = reports_root / "detached_public_verifier_report.json"
    detached_runtime_receipt_path = reports_root / "detached_runtime_receipt.json"
    write_json_stable(manifest_path, package_manifest)
    write_json_stable(sbom_path, package_sbom)

    detached_env = dict(os.environ)
    detached_env.pop("PYTHONPATH", None)
    detached_env.pop("GIT_DIR", None)
    detached_env.pop("GIT_WORK_TREE", None)
    detached_env["GIT_CEILING_DIRECTORIES"] = str(package_root)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.public_verifier_detached_runtime",
            "--report-output",
            str(detached_report_path),
            "--receipt-output",
            str(detached_runtime_receipt_path),
        ],
        cwd=str(detached_cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=detached_env,
        check=False,
    )
    if result.returncode != 0 or not detached_runtime_receipt_path.exists():
        raise RuntimeError(
            "FAIL_CLOSED: detached verifier runtime did not emit a passing receipt\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    detached_runtime_receipt = load_json(detached_runtime_receipt_path)
    repo_local_report = build_public_verifier_report(root=root)
    detached_report = detached_runtime_receipt.get("public_verifier_report", {})
    parity = _parity_map(repo_local_report, detached_report if isinstance(detached_report, dict) else {})
    signoffs_ok = _verify_signoffs(list(package_manifest.get("release_signatures", [])), package_root_sha256)
    detached_checks = detached_runtime_receipt.get("checks", [])
    detached_checks_ok = all(str(row.get("status", "")).strip() == "PASS" for row in detached_checks if isinstance(row, dict))
    parity_ok = all(row["match"] for row in parity.values())
    status = "PASS" if (
        str(detached_runtime_receipt.get("status", "")).strip() == "PASS" and signoffs_ok and detached_checks_ok and parity_ok
    ) else "FAIL"

    return {
        "schema_id": "kt.wave3.detached_verifier_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
        "verifier_boundary": DETACHED_BOUNDARY,
        "package_manifest_ref": _rel(root, manifest_path),
        "package_sbom_ref": _rel(root, sbom_path),
        "detached_runtime_receipt_ref": _rel(root, detached_runtime_receipt_path),
        "detached_runtime_report_ref": _rel(root, detached_report_path),
        "package_root_sha256": package_root_sha256,
        "packaged_file_count": len(package_components),
        "signoffs_verified": signoffs_ok,
        "detached_checks_ok": detached_checks_ok,
        "detached_vs_repo_local_conclusion_parity": parity,
        "stronger_claim_not_made": [
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "externality_class_above_E1_claimed",
        ],
    }


def _build_claim_class_matrix(*, current_head_commit: str, detached_receipt: Dict[str, Any], claim_compiler_receipt: Dict[str, Any], canonical_run_status: str) -> Dict[str, Any]:
    status = "PASS" if canonical_run_status == "PASS" and detached_receipt["status"] == "PASS" and claim_compiler_receipt["status"] == "PASS" else "FAIL"
    return {
        "schema_id": "kt.wave3.claim_class_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": current_head_commit,
        "status": status,
        "dimensions": [
            {"dimension": "control_plane_truth", "claim_class": "CURRENT_HEAD_PROVEN"},
            {"dimension": "runtime_truth", "claim_class": "CURRENT_HEAD_PARTIALLY_PROVEN_MINIMUM_VIABLE_ORGANISM_RUN"},
            {"dimension": "verifier_truth", "claim_class": "CURRENT_HEAD_PROVEN_DETACHED_SAME_HOST_PACKAGED"},
            {"dimension": "challenge_survival", "claim_class": "NOT_EARNED"},
            {"dimension": "replayability", "claim_class": "E1_SAME_HOST_DETACHED_REPLAY"},
            {"dimension": "release_truth", "claim_class": "BOUNDED_CURRENT_HEAD_RELEASE_SURFACE"},
            {"dimension": "product_truth", "claim_class": "UNCHANGED_BOUNDED_PRODUCT_SURFACE"},
            {"dimension": "external_confirmation", "claim_class": "E1_SAME_HOST_DETACHED_REPLAY"},
        ],
        "forbidden_escalations": [
            "Do not narrate the detached verifier as E2, E3, or E4 externality.",
            "Do not narrate successful authenticated live provider inference.",
            "Do not narrate learned-router superiority or cutover.",
        ],
    }


def _build_bounded_output(*, current_head_commit: str, claim_compiler_receipt: Dict[str, Any], claim_class_matrix: Dict[str, Any]) -> Dict[str, Any]:
    status = "PASS" if claim_compiler_receipt["status"] == "PASS" and claim_class_matrix["status"] == "PASS" else "FAIL"
    return {
        "schema_id": "kt.wave3.bounded_output.v1",
        "generated_utc": utc_now_iso_z(),
        "compiled_head_commit": current_head_commit,
        "status": status,
        "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
        "bounded_summary": "Wave 3 proves one bounded minimum viable organism run on the canonical runtime path plus one packaged detached verifier path on the same host. It does not prove broader externality, successful authenticated remote inference, or learned-router superiority.",
        "allowed_current_claims": list(claim_compiler_receipt.get("allowed_current_claims", [])),
        "forbidden_current_claims": list(claim_compiler_receipt.get("forbidden_current_claims", []))
        + [
            "Do not claim independent hostile replay.",
            "Do not claim public challenge survival.",
            "Do not claim successful authenticated live provider inference on current head.",
            "Do not claim learned-router cutover or superiority.",
        ],
    }


def build_wave3_outputs(*, root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Dict[str, Any]]:
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    registry = load_runtime_registry()
    state_vault_path = registry.resolve_state_vault_jsonl_path()
    pre_replay = validate_state_vault_chain(state_vault_path)
    started = telemetry_now_ms()
    probe_rows = [_run_entry_probe(root, export_root, telemetry_path, spec) for spec in _expected_specs(_registry_hash())]
    canonical_run_status = "PASS" if all(row["status"] == "PASS" for row in probe_rows) else "FAIL"
    post_replay = validate_state_vault_chain(state_vault_path)

    detached_receipt = _build_detached_verifier(root, export_root)
    claim_compiler_receipt = build_claim_compiler_receipt(root=root, report_root_rel=REPORT_ROOT_REL, telemetry_path=telemetry_path)
    current_head_commit = _git_head(root)
    claim_class_matrix = _build_claim_class_matrix(
        current_head_commit=current_head_commit,
        detached_receipt=detached_receipt,
        claim_compiler_receipt=claim_compiler_receipt,
        canonical_run_status=canonical_run_status,
    )
    bounded_output = _build_bounded_output(
        current_head_commit=current_head_commit,
        claim_compiler_receipt=claim_compiler_receipt,
        claim_class_matrix=claim_class_matrix,
    )

    status = "PASS" if (
        canonical_run_status == "PASS"
        and detached_receipt["status"] == "PASS"
        and claim_compiler_receipt["status"] == "PASS"
        and claim_class_matrix["status"] == "PASS"
        and bounded_output["status"] == "PASS"
    ) else "FAIL"
    completed = telemetry_now_ms()

    main_receipt = {
        "schema_id": "kt.wave3.minimum_viable_civilization_run_pack.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "wave_id": WAVE_ID,
        "status": status,
        "scope_boundary": "Wave 3 only: one bounded minimum viable organism run, one bounded detached verifier path, and one bounded claim-compiler output.",
        "exact_end_to_end_path_exercised": [
            {"path_role": "ingress", "surface": "kt.entrypoint.invoke", "mode": "CANONICAL"},
            {"path_role": "router", "surface": "core.spine.run -> council.request", "mode": "STATIC_CANONICAL_BASELINE"},
            {"path_role": "adapter_or_provider", "surface": "core.spine.run -> council.plan -> adapter_invocation", "mode": "DRY_RUN_CANONICAL_ADAPTER_INVOCATION"},
            {"path_role": "organ_stack", "surface": "core.spine.run -> cognition.request -> cognition.plan", "mode": "BOUNDED_CANONICAL"},
            {"path_role": "organ_stack", "surface": "core.spine.run -> cognition.plan -> cognition.execute", "mode": "BOUNDED_CANONICAL"},
            {"path_role": "state_vault", "surface": "memory.replay.validate_state_vault_chain", "mode": "CANONICAL"},
            {"path_role": "verifier_pack", "surface": "tools.operator.public_verifier_detached_runtime", "mode": "TOOLCHAIN_PROVING_DETACHED_PACKAGED"},
            {"path_role": "claim_compiler", "surface": "tools.operator.claim_compiler.build_claim_compiler_receipt", "mode": "TOOLCHAIN_PROVING"},
            {"path_role": "bounded_output", "surface": BOUNDED_OUTPUT_REL, "mode": "TOOLCHAIN_PROVING"},
        ],
        "canonical_run": {
            "status": canonical_run_status,
            "steps": probe_rows,
            "state_vault_ref": _rel(root, state_vault_path),
            "state_vault_before": {"record_count": pre_replay.record_count, "head_hash": pre_replay.head_hash},
            "state_vault_after": {"record_count": post_replay.record_count, "head_hash": post_replay.head_hash},
            "state_vault_delta_records": post_replay.record_count - pre_replay.record_count,
            "state_vault_head_changed": pre_replay.head_hash != post_replay.head_hash,
            "adapter_provider_boundary": "Canonical run proves adapter invocation through the static DRY_RUN council execute lane. Successful authenticated live provider inference remains separately unproven and auth-bounded under C016.",
        },
        "detached_verifier_boundary": detached_receipt["verifier_boundary"],
        "detached_verifier_receipt_ref": DETACHED_VERIFIER_RECEIPT_REL,
        "claim_compiler_receipt_ref": CLAIM_COMPILER_RECEIPT_REL,
        "claim_class_matrix_ref": CLAIM_CLASS_MATRIX_REL,
        "bounded_output_ref": BOUNDED_OUTPUT_REL,
        "remaining_open_contradictions": list(OPEN_CONTRADICTIONS),
        "stronger_claim_not_made": [
            "learned_router_cutover_occurred",
            "router_superiority_claimed",
            "successful_authenticated_live_provider_inference_claimed",
            "externality_class_widened_above_E1",
            "product_or_commercial_language_widened",
            "wave4_challenge_or_public_hardening_executed",
        ],
        "timing_ms": {"start_ts": started, "end_ts": completed, "latency_ms": max(0, completed - started)},
    }

    emit_toolchain_telemetry(
        surface_id="tools.operator.wave3_minimum_viable_civilization_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="wave3.minimum_viable_civilization",
        start_ts=started,
        end_ts=completed,
        result_status=main_receipt["status"],
        policy_applied="wave3.minimum_viable_civilization",
        receipt_ref=MAIN_RECEIPT_REL,
        trace_id="wave3-minimum-viable-civilization",
        request_id="wave3.minimum_viable_civilization_validate",
        path=telemetry_path,
    )

    return {
        "main_receipt": main_receipt,
        "detached_receipt": detached_receipt,
        "claim_compiler_receipt": claim_compiler_receipt,
        "claim_class_matrix": claim_class_matrix,
        "bounded_output": bounded_output,
    }


def _append_unique(items: List[str], additions: Sequence[str]) -> List[str]:
    out = list(items)
    for item in additions:
        if item not in out:
            out.append(item)
    return out


def update_convergence_surfaces(*, root: Path, outputs: Dict[str, Dict[str, Any]]) -> None:
    if outputs["main_receipt"]["status"] != "PASS":
        return

    execution_path = (root / "KT_PROD_CLEANROOM" / "reports" / "kt_unified_convergence_execution_report_v2_1_1.json").resolve()
    gate_path = (root / "KT_PROD_CLEANROOM" / "reports" / "kt_unified_convergence_pass_fail_gate_matrix.json").resolve()
    truth_map_path = (root / "KT_PROD_CLEANROOM" / "reports" / "kt_unified_convergence_current_truth_map.json").resolve()
    runtime_map_path = (root / "KT_PROD_CLEANROOM" / "reports" / "kt_unified_convergence_runtime_reality_map.json").resolve()

    execution = load_json(execution_path)
    gate = load_json(gate_path)
    truth_map = load_json(truth_map_path)
    runtime_map = load_json(runtime_map_path)
    head = _git_head(root)

    execution["generated_utc"] = utc_now_iso_z()
    execution["current_git_head"] = head
    execution["highest_lawful_wave_reached"] = WAVE_ID
    execution["scope_executed"] = "WAVE_0_THROUGH_WAVE_3_ONLY"
    execution["blocked_by"] = ["USER_SCOPE_BOUNDARY_WAVE_3_ONLY"]
    execution["overall_status"] = "WAVE_3_COMPLETE_BOUNDED_NO_WAVE_4_AUTO_OPEN"
    execution["non_blocking_holds"] = [
        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
        "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE",
        "REMOTE_PROVIDER_HTTP_401_VISIBLE_AND_NOT_OVERCLAIMED_AWAY",
        "DIRTY_SENSITIVE_CURRENT_WORKTREE_CLEANROOM_SUITE_SKIPPED_BY_REQUEST",
        "OPERATOR_CLEAN_CLONE_SMOKE_SKIPPED_BY_REQUEST",
        "WAVE_4_REQUIRES_EXPLICIT_USER_APPROVAL",
    ]
    execution["executed_findings"] = _append_unique(
        execution.get("executed_findings", []),
        [
            "Wave 3 proves one bounded minimum viable organism run through the canonical entrypoint and spine using the static router baseline, a canonical DRY_RUN adapter invocation, bounded cognition planning/execution, and state-vault replay validation.",
            "Wave 3 proves one same-host packaged detached verifier path that reproduces the repo-local verifier conclusion without repo checkout context and without widening externality above E1.",
            "Wave 3 emits a bounded claim-class matrix and bounded output surface without widening product/commercial language, router claims, or live-provider-success claims.",
        ],
    )
    execution["next_lawful_actions"] = [
        "Hold after Wave 3 because Wave 4 still requires explicit user approval.",
        "If scope widens later, preserve the static router as canonical until learned-router promotion is separately earned from the Wave 2B comparison artifacts.",
        "If scope widens later, treat externality as still bounded at E1 same-host detached replay unless Wave 4 earns a higher class.",
    ]
    execution["stronger_claim_not_made"] = [item for item in execution.get("stronger_claim_not_made", []) if item != "minimum_viable_civilization_run_was_executed"]
    execution["outputs_produced"] = _append_unique(
        execution.get("outputs_produced", []),
        [MAIN_RECEIPT_REL, DETACHED_VERIFIER_RECEIPT_REL, CLAIM_COMPILER_RECEIPT_REL, CLAIM_CLASS_MATRIX_REL, BOUNDED_OUTPUT_REL, TOOLCHAIN_TELEMETRY_REL],
    )
    execution["remaining_open_contradictions"] = list(OPEN_CONTRADICTIONS)
    write_json_stable(execution_path, execution)

    gate["generated_utc"] = utc_now_iso_z()
    gate["current_git_head"] = head
    gate["highest_lawful_wave_reached"] = WAVE_ID
    gate["scope_executed"] = "WAVE_0_THROUGH_WAVE_3_ONLY"
    for row in gate.get("wave_statuses", []):
        if row.get("wave_id") == WAVE_ID:
            row.clear()
            row.update(
                {
                    "wave_id": WAVE_ID,
                    "status": "PASS",
                    "boundary_holds": [
                        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
                        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
                        "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE",
                        "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
                        "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
                    ],
                    "cleared_blockers": [
                        "minimum_viable_civilization_run_not_yet_executed",
                        "detached_verifier_not_yet_bound_to_wave3_scope",
                        "wave3_claim_class_outcome_not_yet_emitted",
                    ],
                    "completed_outputs": [
                        "kt_wave3_minimum_viable_civilization_run_pack",
                        "kt_wave3_detached_verifier_receipt",
                        "kt_wave3_claim_compiler_receipt",
                        "kt_wave3_claim_class_matrix",
                        "kt_wave3_bounded_output",
                    ],
                    "remaining_open_contradictions": list(OPEN_CONTRADICTIONS),
                }
            )
    write_json_stable(gate_path, gate)

    truth_map["generated_utc"] = utc_now_iso_z()
    truth_map["current_git_head"] = head
    truth_map.setdefault("source_surfaces", {})["current_head_wave3_minimum_viable_civilization_surface"] = MAIN_RECEIPT_REL
    truth_map["source_surfaces"]["current_head_wave3_detached_verifier_surface"] = DETACHED_VERIFIER_RECEIPT_REL
    truth_map["source_surfaces"]["current_head_wave3_claim_class_surface"] = CLAIM_CLASS_MATRIX_REL
    truth_map["source_surfaces"]["current_head_wave3_bounded_output_surface"] = BOUNDED_OUTPUT_REL
    truth_map["truth_partitions"]["current_head_runtime_truth"]["summary"] = (
        "Wave 2C realizes council, cognition, paradox, temporal, and multiverse as bounded direct-proof current-head surfaces. "
        "Wave 3 now proves one bounded minimum viable organism run through the canonical entrypoint and spine using the static router baseline, a canonical DRY_RUN adapter invocation, bounded cognition planning/execution, and state-vault replay validation. "
        "Learned routing remains blocked, the live provider seam remains auth-bounded, and repo-root import fragility remains open."
    )
    truth_map["truth_partitions"]["current_head_trust_and_provenance_truth"]["summary"] = (
        "Wave 1 machine-binds trust/provenance surfaces, Wave 2A binds real live provider execution to the frozen Adapter ABI with bounded failure artifacts, Wave 2B adds replayable shadow routing evidence without cutover, Wave 2C adds bounded organ proof packs, C017 proves canonical-spine carriage, FL3 refreshes the live law bundle, and Wave 3 now proves a same-host packaged detached verifier path plus bounded claim compilation on current head."
    )
    truth_map["truth_partitions"]["integrated_overall_truth"]["status"] = "current_head_partially_proven"
    truth_map["truth_partitions"]["integrated_overall_truth"]["summary"] = (
        "Integrated current-head truth now includes one bounded minimum viable organism run, one same-host packaged detached verifier path, and one bounded claim-class output. "
        "Overall truth remains bounded by the open externality ceiling, auth-bounded remote provider reality, and unresolved repo-root import fragility."
    )
    write_json_stable(truth_map_path, truth_map)

    runtime_map["generated_utc"] = utc_now_iso_z()
    runtime_map["current_git_head"] = head
    runtime_map["runtime_roots"]["minimum_viable_civilization_status"] = "PASS_WAVE_3_BOUNDED_CANONICAL_ORGANISM_RUN"
    runtime_map["runtime_roots"]["detached_verifier_status"] = "PASS_WAVE_3_SAME_HOST_PACKAGED_BOUNDARY"
    runtime_map["wave3_minimum_viable_civilization_lane"] = {
        "status": "PASS",
        "boundary_holds": [
            "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
            "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
            "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE",
            "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
            "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
        ],
        "evidence_refs": [MAIN_RECEIPT_REL, DETACHED_VERIFIER_RECEIPT_REL, CLAIM_COMPILER_RECEIPT_REL, CLAIM_CLASS_MATRIX_REL, BOUNDED_OUTPUT_REL],
        "canonical_path_summary": "kt.entrypoint.invoke -> core.spine.run council.request -> core.spine.run council.plan -> core.spine.run cognition.request -> core.spine.run cognition.plan -> state_vault replay",
        "detached_verifier_boundary": DETACHED_BOUNDARY,
        "externality_class": "E1_SAME_HOST_DETACHED_REPLAY",
    }
    write_json_stable(runtime_map_path, runtime_map)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 3 minimum viable civilization run and bounded detached verifier surfaces.")
    parser.add_argument("--receipt-output", default=MAIN_RECEIPT_REL)
    parser.add_argument("--detached-receipt-output", default=DETACHED_VERIFIER_RECEIPT_REL)
    parser.add_argument("--claim-compiler-output", default=CLAIM_COMPILER_RECEIPT_REL)
    parser.add_argument("--claim-class-matrix-output", default=CLAIM_CLASS_MATRIX_REL)
    parser.add_argument("--bounded-output", default=BOUNDED_OUTPUT_REL)
    parser.add_argument("--telemetry-output", default=TOOLCHAIN_TELEMETRY_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    parser.add_argument("--update-convergence-surfaces", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    receipt_path = Path(str(args.receipt_output)).expanduser()
    if not receipt_path.is_absolute():
        receipt_path = (root / receipt_path).resolve()
    detached_receipt_path = Path(str(args.detached_receipt_output)).expanduser()
    if not detached_receipt_path.is_absolute():
        detached_receipt_path = (root / detached_receipt_path).resolve()
    compiler_path = Path(str(args.claim_compiler_output)).expanduser()
    if not compiler_path.is_absolute():
        compiler_path = (root / compiler_path).resolve()
    matrix_path = Path(str(args.claim_class_matrix_output)).expanduser()
    if not matrix_path.is_absolute():
        matrix_path = (root / matrix_path).resolve()
    bounded_output_path = Path(str(args.bounded_output)).expanduser()
    if not bounded_output_path.is_absolute():
        bounded_output_path = (root / bounded_output_path).resolve()
    telemetry_path = Path(str(args.telemetry_output)).expanduser()
    if not telemetry_path.is_absolute():
        telemetry_path = (root / telemetry_path).resolve()
    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()

    outputs = build_wave3_outputs(root=root, export_root=export_root, telemetry_path=telemetry_path)
    write_json_stable(receipt_path, outputs["main_receipt"])
    write_json_stable(detached_receipt_path, outputs["detached_receipt"])
    write_json_stable(compiler_path, outputs["claim_compiler_receipt"])
    write_json_stable(matrix_path, outputs["claim_class_matrix"])
    write_json_stable(bounded_output_path, outputs["bounded_output"])

    if args.update_convergence_surfaces:
        update_convergence_surfaces(root=root, outputs=outputs)

    print(
        json.dumps(
            {
                "status": outputs["main_receipt"]["status"],
                "detached_verifier_status": outputs["detached_receipt"]["status"],
                "claim_compiler_status": outputs["claim_compiler_receipt"]["status"],
                "remaining_open_contradictions": outputs["main_receipt"]["remaining_open_contradictions"],
            },
            sort_keys=True,
        )
    )
    return 0 if outputs["main_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
