from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from cognition.cognitive_schemas import CognitiveRequestSchema, MODE_LIVE_REQUESTED as COGNITION_MODE_LIVE_REQUESTED
from core.runtime_registry import load_runtime_registry
from council.council_router import execute_council_request
from council.council_schemas import CouncilRequestSchema, MODE_LIVE_REQUESTED as COUNCIL_MODE_LIVE_REQUESTED
from memory.replay import validate_state_vault_chain
from schemas.runtime_context_schema import RUNTIME_CONTEXT_MAX_INPUT_BYTES
from schemas.schema_hash import sha256_text
from tools.operator.observability import emit_toolchain_telemetry, telemetry_now_ms
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/wave4_chaos_and_external_challenge"
WAVE_ID = "WAVE_4_CHAOS_AND_EXTERNAL_CHALLENGE"
WORK_ORDER_ID = "KT_UNIFIED_CONVERGENCE_MAX_POWER_CAMPAIGN_V2_1_1_FINAL"
OPEN_CONTRADICTIONS = [
    "C005_ROUTER_AMBITION_EXCEEDS_IMPLEMENTATION",
    "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED",
    "C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
    "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE",
]

MAIN_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave4_chaos_and_external_challenge_receipt.json"
CHAOS_MANIFEST_REL = f"{REPORT_ROOT_REL}/kt_wave4_chaos_manifest.json"
CHALLENGE_PROTOCOL_REL = f"{REPORT_ROOT_REL}/kt_wave4_challenge_protocol.json"
PUBLIC_CHALLENGE_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave4_public_challenge_receipt.json"
EXTERNALITY_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave4_externality_class_matrix.json"
CHALLENGE_DISPOSITIONS_REL = f"{REPORT_ROOT_REL}/kt_wave4_challenge_dispositions.json"
FORMAL_INVARIANTS_REL = f"{REPORT_ROOT_REL}/kt_wave4_formal_invariant_artifacts.json"
TOOLCHAIN_TELEMETRY_REL = f"{REPORT_ROOT_REL}/kt_wave4_chaos_telemetry.jsonl"

WAVE3_MAIN_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave3_minimum_viable_civilization_run_pack.json"
WAVE3_DETACHED_RECEIPT_REL = f"{REPORT_ROOT_REL}/kt_wave3_detached_verifier_receipt.json"
WAVE3_CLAIM_MATRIX_REL = f"{REPORT_ROOT_REL}/kt_wave3_claim_class_matrix.json"
WAVE3_BOUNDED_OUTPUT_REL = f"{REPORT_ROOT_REL}/kt_wave3_bounded_output.json"
WAVE3_CLAIM_COMPILER_REL = f"{REPORT_ROOT_REL}/kt_wave3_claim_compiler_receipt.json"

CHALLENGE_CHANNEL_ID = "SIGNED_JSON_BUNDLE_DOCUMENTED_CHANNEL_V1"
CHALLENGE_CHANNEL_BOUNDARY = (
    "Wave 4 opens a documented signed-submission challenge channel for the current-head bounded organism and the Wave 3 same-host packaged detached verifier path. "
    "It does not claim cross-host friendly replay, independent hostile replay, or public challenge survival."
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


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _registry_hash() -> str:
    from core.spine import _runtime_registry_hash

    return _runtime_registry_hash(load_runtime_registry())


def _emit_toolchain(path: Path, *, probe_id: str, receipt_ref: str, result_status: str) -> None:
    started = telemetry_now_ms()
    emit_toolchain_telemetry(
        surface_id=f"tools.operator.wave4.{probe_id}",
        zone="TOOLCHAIN_PROVING",
        event_type="wave4.challenge_probe",
        start_ts=started,
        end_ts=telemetry_now_ms(),
        result_status=result_status,
        policy_applied="wave4.chaos_and_external_challenge",
        receipt_ref=receipt_ref,
        trace_id=f"wave4-{probe_id}",
        request_id=f"wave4.{probe_id}",
        path=path,
    )


def _run_command(*, root: Path, cmd: Sequence[str]) -> Dict[str, Any]:
    proc = subprocess.run(
        list(cmd),
        cwd=str(root),
        env=_tool_env(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = proc.stdout or ""
    return {
        "command": " ".join(cmd),
        "rc": int(proc.returncode),
        "status": "PASS" if int(proc.returncode) == 0 else "FAIL",
        "observed": output.strip().splitlines()[-1] if output.strip() else "",
        "output_tail": output.strip().splitlines()[-20:],
    }


def _run_entry_probe(*, root: Path, export_root: Path, probe_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    probe_root = (export_root / probe_id).resolve()
    probe_root.mkdir(parents=True, exist_ok=True)
    artifact_root = (probe_root / "artifacts").resolve()
    payload_path = probe_root / "payload.json"
    output_path = probe_root / "entry_result.json"
    runtime_telemetry_path = probe_root / "runtime_telemetry.jsonl"
    payload_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
    env = _tool_env(root)
    proc = subprocess.run(
        [
            sys.executable,
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
    result: Dict[str, Any] = {
        "probe_id": probe_id,
        "rc": int(proc.returncode),
        "stdout": proc.stdout or "",
        "payload_ref": _rel(root, payload_path),
        "artifact_root_ref": _rel(root, artifact_root),
        "runtime_telemetry_ref": _rel(root, runtime_telemetry_path) if runtime_telemetry_path.exists() else "",
    }
    if output_path.exists():
        result["output_ref"] = _rel(root, output_path)
        result["output"] = load_json(output_path)
    return result


def _contains_forbidden_phrase(rows: Sequence[str], phrase: str) -> bool:
    lowered = phrase.lower()
    return any(lowered in str(row).lower() for row in rows)


def _oversize_input_probe(*, root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Any]:
    payload = {
        "probe_id": "wave4.oversize_input",
        "blob": "x" * (RUNTIME_CONTEXT_MAX_INPUT_BYTES + 512),
    }
    probe = _run_entry_probe(root=root, export_root=export_root, probe_id="oversize_input_fail_closed", payload=payload)
    stdout = str(probe.get("stdout", ""))
    output = probe.get("output", {})
    entry_result = output.get("entry_result", {}) if isinstance(output, dict) else {}
    entry_error = str(entry_result.get("error", "")).strip()
    entry_status = str(entry_result.get("status", "")).strip()
    passed = (
        int(probe.get("rc", 1)) == 0
        and str(output.get("status", "")).strip() == "PASS"
        and entry_status == "FAIL"
        and "envelope.input exceeds max_input_bytes" in entry_error
    )
    evidence_refs = [
        ref
        for ref in [
            probe.get("payload_ref", ""),
            probe.get("output_ref", ""),
            probe.get("runtime_telemetry_ref", ""),
        ]
        if ref
    ]
    row = {
        "probe_id": "oversize_input_fail_closed",
        "probe_class": "OVERSIZE_RUNTIME_CONTEXT",
        "surface": "kt.entrypoint.invoke -> core.spine.run",
        "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
        "expected_behavior": "fail_closed_rejection_before_schema_laundering",
        "observed_status": "FAIL_CLOSED" if entry_status == "FAIL" else "UNEXPECTED_PASS",
        "pass": passed,
        "finding_status": "BOUNDARY_HELD" if passed else "REPRODUCED_OPEN",
        "evidence_refs": evidence_refs,
        "details": {
            "max_input_bytes": RUNTIME_CONTEXT_MAX_INPUT_BYTES,
            "entry_status": entry_status,
            "entry_error": entry_error,
            "stdout_tail": stdout.strip().splitlines()[-20:],
        },
        "regression_binding_refs": [
            "KT_PROD_CLEANROOM/tests/operator/test_c017_spine_carriage_remediation.py",
            "KT_PROD_CLEANROOM/tests/operator/test_wave4_chaos_and_external_challenge.py",
        ],
    }
    _emit_toolchain(
        telemetry_path,
        probe_id=row["probe_id"],
        receipt_ref=row["evidence_refs"][0] if row["evidence_refs"] else MAIN_RECEIPT_REL,
        result_status="PASS" if row["pass"] else "FAIL",
    )
    return row


def _live_request_refusal_probe(*, root: Path, export_root: Path, telemetry_path: Path, organ: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    probe = _run_entry_probe(root=root, export_root=export_root, probe_id=f"{organ}_live_requested_refusal", payload=payload)
    output = probe.get("output", {})
    entry_result = output.get("entry_result", {}) if isinstance(output, dict) else {}
    slice_payload = entry_result.get(organ, {}) if isinstance(entry_result, dict) else {}
    refusal_code = str(slice_payload.get("refusal_code", "")).strip()
    passed = (
        int(probe.get("rc", 1)) == 0
        and str(entry_result.get("status", "")).strip() == "OK"
        and str(slice_payload.get("status", "")).strip() == "REFUSED"
        and bool(refusal_code)
    )
    evidence_refs = [ref for ref in [probe.get("payload_ref", ""), probe.get("output_ref", ""), probe.get("runtime_telemetry_ref", "")] if ref]
    row = {
        "probe_id": f"{organ}_live_requested_refusal",
        "probe_class": f"{organ.upper()}_LIVE_REQUEST_REFUSAL",
        "surface": f"kt.entrypoint.invoke -> core.spine.run -> {organ}.request",
        "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
        "expected_behavior": "governed_refusal_without_silent_live_enablement",
        "observed_status": str(slice_payload.get("status", "")).strip() or ("FAIL_CLOSED" if int(probe.get("rc", 0)) != 0 else "UNKNOWN"),
        "pass": passed,
        "finding_status": "BOUNDARY_HELD" if passed else "REPRODUCED_OPEN",
        "evidence_refs": evidence_refs,
        "details": {
            "entry_status": str(entry_result.get("status", "")).strip(),
            "refusal_code": refusal_code,
            "stdout_tail": str(probe.get("stdout", "")).strip().splitlines()[-20:],
        },
        "regression_binding_refs": [
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/council/tests/test_council_router.py"
            if organ == "council"
            else "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/cognition/tests/test_cognitive_engine.py",
            "KT_PROD_CLEANROOM/tests/operator/test_wave4_chaos_and_external_challenge.py",
        ],
    }
    _emit_toolchain(telemetry_path, probe_id=row["probe_id"], receipt_ref=evidence_refs[0] if evidence_refs else MAIN_RECEIPT_REL, result_status="PASS" if row["pass"] else "FAIL")
    return row


def _remote_provider_auth_probe(*, root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Any]:
    export_path = (export_root / "remote_provider_auth").resolve()
    export_path.mkdir(parents=True, exist_ok=True)
    telemetry_file = export_path / "runtime_telemetry.jsonl"
    original_env = {name: os.environ.get(name) for name in ("KT_PROVIDERS_ENABLED", "KT_EXECUTION_LANE", "KT_NODE_ID", "KT_RUNTIME_TELEMETRY_PATH")}
    os.environ["KT_PROVIDERS_ENABLED"] = "1"
    os.environ["KT_EXECUTION_LANE"] = "LIVE_HASHED"
    os.environ["KT_NODE_ID"] = "wave4-chaos"
    os.environ["KT_RUNTIME_TELEMETRY_PATH"] = str(telemetry_file.resolve())
    try:
        outcome = execute_council_request(
            {
                "mode": "LIVE_HASHED",
                "request_type": "analysis",
                "provider_id": "openrouter",
                "model": "openai/gpt-4.1-mini",
                "prompt": "Reply with the single token OK.",
                "trace_id": "wave4-openrouter-auth-boundary",
                "export_root": str(export_path),
            }
        )
    finally:
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    receipt_ref = str(outcome.get("receipt_ref", "")).strip()
    failure_ref = str(outcome.get("failure_artifact_ref", "")).strip()
    receipt_payload: Dict[str, Any] = {}
    http_status = 0
    if receipt_ref and Path(receipt_ref).exists():
        receipt_payload = load_json(Path(receipt_ref))
        http_status = int(receipt_payload.get("transport", {}).get("http_status", 0))
    status = str(outcome.get("status", "")).strip()
    passed = status in {"FAIL_CLOSED", "OK"} and bool(receipt_ref or failure_ref)
    evidence_refs = []
    if receipt_ref:
        evidence_refs.append(_rel(root, Path(receipt_ref)))
    if failure_ref:
        evidence_refs.append(_rel(root, Path(failure_ref)))
    if telemetry_file.exists():
        evidence_refs.append(_rel(root, telemetry_file))
    row = {
        "probe_id": "remote_provider_auth_boundary",
        "probe_class": "REMOTE_PROVIDER_AUTH_BOUNDARY",
        "surface": "council.council_router.execute_council_request",
        "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
        "expected_behavior": "successful_authenticated_inference_or_fail_closed_auth_boundary",
        "observed_status": status or "UNKNOWN",
        "pass": passed,
        "finding_status": "BOUNDARY_HELD" if passed else "REPRODUCED_OPEN",
        "evidence_refs": evidence_refs,
        "details": {
            "adapter_id": str(outcome.get("adapter_id", "")).strip(),
            "http_status": http_status,
            "error": str(outcome.get("error", "")).strip(),
            "receipt_hash": str(outcome.get("receipt_hash", "")).strip(),
            "contradiction_effect": "C016_MAY_NARROW_IF_AUTHENTICATED_SUCCESS_OBSERVED" if status == "OK" else "C016_REMAINS_OPEN",
        },
        "regression_binding_refs": [
            "KT_PROD_CLEANROOM/tools/operator/wave2a_adapter_activation_validate.py",
            "KT_PROD_CLEANROOM/tests/operator/test_wave4_chaos_and_external_challenge.py",
        ],
    }
    _emit_toolchain(telemetry_path, probe_id=row["probe_id"], receipt_ref=evidence_refs[0] if evidence_refs else MAIN_RECEIPT_REL, result_status="PASS" if row["pass"] else "FAIL")
    return row


def _build_chaos_manifest(*, probes: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    successful_findings = [row for row in probes if not bool(row.get("pass"))]
    return {
        "schema_id": "kt.wave4.chaos_manifest.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not successful_findings else "FAIL",
        "scope_boundary": "Wave 4 chaos probes current-head organism boundaries without router cutover, product widening, or externality escalation.",
        "probe_classes_run": [str(row.get("probe_class", "")).strip() for row in probes],
        "probe_rows": list(probes),
        "successful_findings_count": len(successful_findings),
        "successful_finding_ids": [str(row.get("probe_id", "")).strip() for row in successful_findings],
        "stronger_claim_not_made": [
            "broad_external_capability_confirmed",
            "learned_router_superiority_claimed",
            "product_or_commercial_language_widened",
            "externality_class_above_E1_claimed",
        ],
        "evidence_refs": [row["evidence_refs"][0] for row in probes if isinstance(row.get("evidence_refs"), list) and row.get("evidence_refs")],
    }


def _build_challenge_protocol(*, current_head: str, wave3_detached: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.wave4.challenge_protocol.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "compiled_head_commit": current_head,
        "wave_id": WAVE_ID,
        "challenge_channel_used": CHALLENGE_CHANNEL_ID,
        "challenge_channel_kind": "DOCUMENTED_SIGNED_SUBMISSION_CHANNEL",
        "channel_boundary": CHALLENGE_CHANNEL_BOUNDARY,
        "submission_modes": ["SIGNED_JSON_BUNDLE", "PLAIN_JSON_WITH_ARTIFACT_REFS"],
        "required_submission_fields": [
            "submission_id",
            "reporter_alias",
            "challenge_class",
            "claimed_boundary_or_kill_condition",
            "reproduction_steps",
            "evidence_refs",
            "environment_metadata",
            "observed_result",
            "expected_result",
        ],
        "challenge_classes": [
            {"challenge_class": "INTERNAL_HOSTILE_PROBE", "externality_class": "E0_INTERNAL_SELF_ISSUED_ONLY", "status": "RUNNABLE"},
            {"challenge_class": "SAME_HOST_PACKAGED_DETACHED_REPLAY", "externality_class": "E1_SAME_HOST_DETACHED_REPLAY", "status": "RUNNABLE"},
            {"challenge_class": "CROSS_HOST_FRIENDLY_REPLAY", "externality_class": "E2_CROSS_HOST_FRIENDLY_REPLAY", "status": "NOT_EARNED"},
            {"challenge_class": "INDEPENDENT_HOSTILE_REPLAY", "externality_class": "E3_INDEPENDENT_HOSTILE_REPLAY", "status": "NOT_EARNED"},
            {"challenge_class": "PUBLIC_CHALLENGE_SURVIVAL", "externality_class": "E4_PUBLIC_CHALLENGE_SURVIVAL", "status": "NOT_EARNED"},
        ],
        "auditor_paths": [
            {
                "path_id": "WAVE3_DETACHED_VERIFIER_PACKAGED_PATH",
                "path_kind": "SAME_HOST_PACKAGED_DETACHED_REPLAY",
                "status": "RUNNABLE",
                "externality_class": wave3_detached.get("externality_class", "E1_SAME_HOST_DETACHED_REPLAY"),
                "scope_boundary": str(wave3_detached.get("verifier_boundary", "")).strip(),
                "receipt_ref": WAVE3_DETACHED_RECEIPT_REL,
                "organism_ref": WAVE3_MAIN_RECEIPT_REL,
            }
        ],
        "kill_conditions": [
            {"kill_condition_id": "CANONICAL_ORGANISM_FAILS_TO_REFUSE_LIVE_REQUESTED_COUNCIL", "severity": "KILL"},
            {"kill_condition_id": "CANONICAL_ORGANISM_FAILS_TO_REFUSE_LIVE_REQUESTED_COGNITION", "severity": "KILL"},
            {"kill_condition_id": "OVERSIZE_RUNTIME_CONTEXT_DOES_NOT_FAIL_CLOSED", "severity": "KILL"},
            {"kill_condition_id": "CLAIM_OR_EXTERNALITY_BOUNDARY_BREACH", "severity": "KILL"},
        ],
        "challenge_window_status": "OPEN_NO_EXTERNAL_FINDINGS_YET",
        "wave3_dependency_refs": [WAVE3_MAIN_RECEIPT_REL, WAVE3_DETACHED_RECEIPT_REL, WAVE3_CLAIM_MATRIX_REL, WAVE3_BOUNDED_OUTPUT_REL],
        "stronger_claim_not_made": [
            "cross_host_friendly_replay_confirmed",
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "externality_class_above_E1_claimed",
        ],
    }


def _build_externality_matrix(*, wave3_detached: Dict[str, Any], protocol: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_id": "kt.wave4.externality_matrix.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS",
        "earned_classes": [
            {
                "surface_id": "wave4.internal_chaos",
                "earned_class": "E0_INTERNAL_SELF_ISSUED_ONLY",
                "evidence_ref": CHAOS_MANIFEST_REL,
                "claim_boundary": "Internal hostile probes do not upgrade external confirmation.",
            },
            {
                "surface_id": "wave3.detached_verifier",
                "earned_class": str(wave3_detached.get("externality_class", "E1_SAME_HOST_DETACHED_REPLAY")).strip(),
                "evidence_ref": WAVE3_DETACHED_RECEIPT_REL,
                "claim_boundary": str(wave3_detached.get("verifier_boundary", "")).strip(),
            },
        ],
        "not_earned_classes": [
            "E2_CROSS_HOST_FRIENDLY_REPLAY",
            "E3_INDEPENDENT_HOSTILE_REPLAY",
            "E4_PUBLIC_CHALLENGE_SURVIVAL",
        ],
        "challenge_channel_used": str(protocol.get("challenge_channel_used", "")).strip(),
        "hard_rule_reaffirmed": "Same-host detached replay may never be narrated as independent hostile confirmation.",
    }


def _build_dispositions(*, chaos_manifest: Dict[str, Any], protocol: Dict[str, Any]) -> Dict[str, Any]:
    findings = [row for row in chaos_manifest.get("probe_rows", []) if not bool(row.get("pass"))]
    dispositions = []
    for row in chaos_manifest.get("probe_rows", []):
        dispositions.append(
            {
                "finding_id": str(row.get("probe_id", "")).strip(),
                "challenge_class": str(row.get("probe_class", "")).strip(),
                "status": "CLOSED_BOUNDARY_HELD" if bool(row.get("pass")) else "REPRODUCED_OPEN",
                "disposition": "ACKNOWLEDGED_INFORMATIONAL" if bool(row.get("pass")) else "REPRODUCED_OPEN",
                "externality_class": str(row.get("externality_class", "")).strip(),
                "evidence_refs": list(row.get("evidence_refs", [])),
                "regression_binding_refs": list(row.get("regression_binding_refs", [])),
            }
        )
    return {
        "schema_id": "kt.wave4.challenge_dispositions.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if not findings else "FAIL",
        "challenge_channel_used": str(protocol.get("challenge_channel_used", "")).strip(),
        "successful_findings_count": len(findings),
        "successful_findings": [
            {
                "finding_id": str(row.get("probe_id", "")).strip(),
                "challenge_class": str(row.get("probe_class", "")).strip(),
                "evidence_refs": list(row.get("evidence_refs", [])),
            }
            for row in findings
        ],
        "regression_ingestions": [
            {
                "finding_id": str(row.get("probe_id", "")).strip(),
                "regression_binding_refs": list(row.get("regression_binding_refs", [])),
            }
            for row in findings
        ],
        "disposition_rows": dispositions,
        "stronger_claim_not_made": [
            "absence_of_findings_proves_absence",
            "public_challenge_survival_confirmed",
            "externality_class_above_E1_claimed",
        ],
    }


def _build_formal_invariants(
    *,
    root: Path,
    wave3_claim_matrix: Dict[str, Any],
    wave3_bounded_output: Dict[str, Any],
    wave3_detached: Dict[str, Any],
    protocol: Dict[str, Any],
    public_challenge_receipt: Dict[str, Any],
) -> Dict[str, Any]:
    trust_zone = _run_command(root=root, cmd=["python", "-m", "tools.operator.trust_zone_validate"])
    firewall = _run_command(root=root, cmd=["python", "-m", "tools.operator.toolchain_runtime_firewall_validate"])
    state_vault = validate_state_vault_chain(load_runtime_registry().resolve_state_vault_jsonl_path())
    dimensions = {
        str(row.get("dimension", "")).strip(): str(row.get("claim_class", "")).strip()
        for row in wave3_claim_matrix.get("dimensions", [])
        if isinstance(row, dict)
    }
    forbidden_rows = list(wave3_bounded_output.get("forbidden_current_claims", []))
    allowed_rows = list(wave3_bounded_output.get("allowed_current_claims", []))

    checks = [
        {
            "check_id": "claim_compiler_monotonicity",
            "status": "PASS"
            if all(
                [
                    "independent hostile replay" in " ".join(forbidden_rows).lower(),
                    "public challenge survival" in " ".join(forbidden_rows).lower(),
                    ("learned-router" in " ".join(forbidden_rows).lower()) or ("learned router" in " ".join(forbidden_rows).lower()),
                    not _contains_forbidden_phrase(allowed_rows, "independent hostile replay"),
                    not _contains_forbidden_phrase(allowed_rows, "public challenge survival"),
                    not _contains_forbidden_phrase(allowed_rows, "learned-router"),
                    not _contains_forbidden_phrase(allowed_rows, "successful authenticated live provider inference"),
                ]
            )
            else "FAIL",
            "refs": [WAVE3_CLAIM_COMPILER_REL, WAVE3_BOUNDED_OUTPUT_REL],
        },
        {
            "check_id": "externality_class_consistency",
            "status": "PASS"
            if all(
                [
                    dimensions.get("external_confirmation") == "E1_SAME_HOST_DETACHED_REPLAY",
                    dimensions.get("replayability") == "E1_SAME_HOST_DETACHED_REPLAY",
                    str(wave3_bounded_output.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
                    str(wave3_detached.get("externality_class", "")).strip() == "E1_SAME_HOST_DETACHED_REPLAY",
                ]
            )
            else "FAIL",
            "refs": [WAVE3_CLAIM_MATRIX_REL, WAVE3_BOUNDED_OUTPUT_REL, WAVE3_DETACHED_RECEIPT_REL],
        },
        {
            "check_id": "challenge_channel_does_not_self_upgrade_externality",
            "status": "PASS"
            if (
                str(public_challenge_receipt.get("challenge_window_status", "")).strip() == "OPEN_NO_EXTERNAL_FINDINGS_YET"
                and "cross_host_friendly_replay_confirmed" in protocol.get("stronger_claim_not_made", [])
                and "public_challenge_survival_confirmed" in protocol.get("stronger_claim_not_made", [])
            )
            else "FAIL",
            "refs": [CHALLENGE_PROTOCOL_REL, PUBLIC_CHALLENGE_RECEIPT_REL, EXTERNALITY_MATRIX_REL],
        },
        {
            "check_id": "toolchain_runtime_firewall_preserved",
            "status": "PASS" if trust_zone["status"] == "PASS" and firewall["status"] == "PASS" else "FAIL",
            "refs": [
                "KT_PROD_CLEANROOM/tools/operator/trust_zone_validate.py",
                "KT_PROD_CLEANROOM/tools/operator/toolchain_runtime_firewall_validate.py",
            ],
        },
        {
            "check_id": "state_vault_chain_valid_after_chaos",
            "status": "PASS" if state_vault.record_count > 0 and bool(state_vault.head_hash) else "FAIL",
            "refs": ["KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/_runtime_artifacts/state_vault.jsonl"],
        },
    ]
    return {
        "schema_id": "kt.wave4.formal_invariant_artifacts.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if all(str(row.get("status", "")).strip() == "PASS" for row in checks) else "FAIL",
        "checks": checks,
        "validator_runs": [trust_zone, firewall],
        "state_vault_after_chaos": {
            "record_count": state_vault.record_count,
            "head_hash": state_vault.head_hash,
        },
        "stronger_claim_not_made": [
            "full_unbounded_formal_proof_claimed",
            "independent_hostile_replay_claimed",
            "public_challenge_survival_claimed",
        ],
    }


def build_wave4_outputs(*, root: Path, export_root: Path, telemetry_path: Path) -> Dict[str, Dict[str, Any]]:
    export_root.mkdir(parents=True, exist_ok=True)
    if telemetry_path.exists():
        telemetry_path.unlink()

    wave3_detached = load_json((root / WAVE3_DETACHED_RECEIPT_REL).resolve())
    wave3_claim_matrix = load_json((root / WAVE3_CLAIM_MATRIX_REL).resolve())
    wave3_bounded_output = load_json((root / WAVE3_BOUNDED_OUTPUT_REL).resolve())
    current_head = _git_head(root)
    registry_hash = _registry_hash()
    started = telemetry_now_ms()

    council_live_payload = CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "wave4.council.live_request",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_LIVE_REQUESTED,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 128,
            "total_token_cap": 256,
            "input_hash": sha256_text("wave4 council live request"),
        }
    ).to_dict()
    cognition_live_payload = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "wave4.cognition.live_request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_LIVE_REQUESTED,
            "input_hash": sha256_text("wave4 cognition live request"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("wave4.trace"), "artifact_id": "wave4.trace"}],
        }
    ).to_dict()

    probes = [
        _oversize_input_probe(root=root, export_root=export_root, telemetry_path=telemetry_path),
        _live_request_refusal_probe(root=root, export_root=export_root, telemetry_path=telemetry_path, organ="council", payload=council_live_payload),
        _live_request_refusal_probe(root=root, export_root=export_root, telemetry_path=telemetry_path, organ="cognition", payload=cognition_live_payload),
        _remote_provider_auth_probe(root=root, export_root=export_root, telemetry_path=telemetry_path),
    ]

    chaos_manifest = _build_chaos_manifest(probes=probes)
    challenge_protocol = _build_challenge_protocol(current_head=current_head, wave3_detached=wave3_detached)
    externality_matrix = _build_externality_matrix(wave3_detached=wave3_detached, protocol=challenge_protocol)
    challenge_dispositions = _build_dispositions(chaos_manifest=chaos_manifest, protocol=challenge_protocol)
    public_challenge_receipt = {
        "schema_id": "kt.wave4.public_challenge_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": "PASS" if chaos_manifest["status"] == "PASS" and challenge_dispositions["status"] == "PASS" else "FAIL",
        "compiled_head_commit": current_head,
        "challenge_channel_used": CHALLENGE_CHANNEL_ID,
        "challenge_window_status": "OPEN_NO_EXTERNAL_FINDINGS_YET",
        "scope_boundary": CHALLENGE_CHANNEL_BOUNDARY,
        "successful_findings_count": int(challenge_dispositions["successful_findings_count"]),
        "successful_findings_ref": CHALLENGE_DISPOSITIONS_REL,
        "externality_ceiling_after_wave4": "E1_SAME_HOST_DETACHED_REPLAY",
        "exact_probe_classes_run": list(chaos_manifest["probe_classes_run"]),
        "stronger_claim_not_made": [
            "same_host_or_internal_evidence_narrated_as_E2_or_E3",
            "public_challenge_survival_confirmed",
            "product_or_prestige_language_widened",
        ],
    }
    formal_invariants = _build_formal_invariants(
        root=root,
        wave3_claim_matrix=wave3_claim_matrix,
        wave3_bounded_output=wave3_bounded_output,
        wave3_detached=wave3_detached,
        protocol=challenge_protocol,
        public_challenge_receipt=public_challenge_receipt,
    )

    status = "PASS" if all(
        row["status"] == "PASS"
        for row in [chaos_manifest, challenge_protocol, public_challenge_receipt, externality_matrix, challenge_dispositions, formal_invariants]
    ) else "FAIL"
    completed = telemetry_now_ms()
    remaining_open = list(OPEN_CONTRADICTIONS)
    remote_probe = next(row for row in probes if row["probe_id"] == "remote_provider_auth_boundary")
    if str(remote_probe.get("observed_status", "")).strip() == "OK":
        remaining_open = [row for row in remaining_open if row != "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE"]

    main_receipt = {
        "schema_id": "kt.wave4.chaos_and_external_challenge_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "work_order_id": WORK_ORDER_ID,
        "wave_id": WAVE_ID,
        "status": status,
        "scope_boundary": "Wave 4 only: hostile probes, typed challenge protocol, bounded formal invariants, and typed externality handling without router/product/externality widening.",
        "chaos_manifest_ref": CHAOS_MANIFEST_REL,
        "challenge_protocol_ref": CHALLENGE_PROTOCOL_REL,
        "public_challenge_receipt_ref": PUBLIC_CHALLENGE_RECEIPT_REL,
        "externality_class_matrix_ref": EXTERNALITY_MATRIX_REL,
        "challenge_dispositions_ref": CHALLENGE_DISPOSITIONS_REL,
        "formal_invariant_artifacts_ref": FORMAL_INVARIANTS_REL,
        "exact_probe_classes_run": list(chaos_manifest["probe_classes_run"]),
        "challenge_channel_used": CHALLENGE_CHANNEL_ID,
        "externality_classes_earned": ["E0_INTERNAL_SELF_ISSUED_ONLY", "E1_SAME_HOST_DETACHED_REPLAY"],
        "successful_findings_count": int(challenge_dispositions["successful_findings_count"]),
        "successful_findings": list(challenge_dispositions["successful_findings"]),
        "regression_ingestions": list(challenge_dispositions["regression_ingestions"]),
        "remaining_open_contradictions": remaining_open,
        "stronger_claim_not_made": [
            "learned_router_cutover_occurred",
            "independent_hostile_replay_confirmed",
            "public_challenge_survival_confirmed",
            "product_or_commercial_language_widened",
            "externality_class_above_E1_claimed",
        ],
        "timing_ms": {"start_ts": started, "end_ts": completed, "latency_ms": max(0, completed - started)},
    }
    emit_toolchain_telemetry(
        surface_id="tools.operator.wave4_chaos_and_external_challenge_validate",
        zone="TOOLCHAIN_PROVING",
        event_type="wave4.chaos_and_external_challenge",
        start_ts=started,
        end_ts=completed,
        result_status=main_receipt["status"],
        policy_applied="wave4.chaos_and_external_challenge",
        receipt_ref=MAIN_RECEIPT_REL,
        trace_id="wave4-chaos-and-external-challenge",
        request_id="wave4.chaos_and_external_challenge_validate",
        path=telemetry_path,
    )
    return {
        "main_receipt": main_receipt,
        "chaos_manifest": chaos_manifest,
        "challenge_protocol": challenge_protocol,
        "public_challenge_receipt": public_challenge_receipt,
        "externality_matrix": externality_matrix,
        "challenge_dispositions": challenge_dispositions,
        "formal_invariants": formal_invariants,
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

    execution_path = (root / "KT_PROD_CLEANROOM/reports/kt_unified_convergence_execution_report_v2_1_1.json").resolve()
    gate_path = (root / "KT_PROD_CLEANROOM/reports/kt_unified_convergence_pass_fail_gate_matrix.json").resolve()
    truth_map_path = (root / "KT_PROD_CLEANROOM/reports/kt_unified_convergence_current_truth_map.json").resolve()
    runtime_map_path = (root / "KT_PROD_CLEANROOM/reports/kt_unified_convergence_runtime_reality_map.json").resolve()
    contradiction_path = (root / "KT_PROD_CLEANROOM/reports/kt_unified_convergence_contradiction_table.json").resolve()

    execution = load_json(execution_path)
    gate = load_json(gate_path)
    truth_map = load_json(truth_map_path)
    runtime_map = load_json(runtime_map_path)
    contradiction_table = load_json(contradiction_path)
    head = _git_head(root)
    remaining_open = list(outputs["main_receipt"]["remaining_open_contradictions"])

    execution["generated_utc"] = utc_now_iso_z()
    execution["current_git_head"] = head
    execution["highest_lawful_wave_reached"] = WAVE_ID
    execution["scope_executed"] = "WAVE_0_THROUGH_WAVE_4_ONLY"
    execution["blocked_by"] = ["USER_SCOPE_BOUNDARY_WAVE_4_ONLY"]
    execution["overall_status"] = "WAVE_4_COMPLETE_BOUNDED_NO_WAVE_5_AUTO_OPEN"
    execution["non_blocking_holds"] = [
        "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
        "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
        "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE" if "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" in remaining_open else "REMOTE_PROVIDER_AUTH_BOUNDARY_NARROWED_BY_SUCCESSFUL_AUTHENTICATED_PROBE",
        "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
        "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
        "PUBLIC_CHALLENGE_SURVIVAL_NOT_EARNED",
        "WAVE_5_REQUIRES_EXPLICIT_USER_APPROVAL",
    ]
    execution["executed_findings"] = _append_unique(
        execution.get("executed_findings", []),
        [
            "Wave 4 runs hostile probes against the current-head bounded organism path and verifies fail-closed behavior on oversize runtime-context input plus governed live-request refusals for council and cognition.",
            "Wave 4 opens a documented signed challenge channel and types the externality ladder honestly: internal hostile probes remain E0 and the detached verifier remains bounded at E1 same-host packaged replay.",
            "Wave 4 adds bounded invariant checks for claim-compiler monotonicity, externality consistency, toolchain/runtime firewall preservation, and post-chaos state-vault integrity without widening router, product, or externality claims.",
        ],
    )
    execution["next_lawful_actions"] = [
        "Hold after Wave 4 because Wave 5 still requires explicit user approval.",
        "If scope widens later, preserve externality at E1 unless a higher class is actually earned.",
        "If scope widens later, keep the static router canonical until learned-router promotion is separately earned.",
    ]
    execution["outputs_produced"] = _append_unique(
        execution.get("outputs_produced", []),
        [MAIN_RECEIPT_REL, CHAOS_MANIFEST_REL, CHALLENGE_PROTOCOL_REL, PUBLIC_CHALLENGE_RECEIPT_REL, EXTERNALITY_MATRIX_REL, CHALLENGE_DISPOSITIONS_REL, FORMAL_INVARIANTS_REL, TOOLCHAIN_TELEMETRY_REL],
    )
    execution["remaining_open_contradictions"] = remaining_open
    write_json_stable(execution_path, execution)

    gate["generated_utc"] = utc_now_iso_z()
    gate["current_git_head"] = head
    gate["highest_lawful_wave_reached"] = WAVE_ID
    gate["scope_executed"] = "WAVE_0_THROUGH_WAVE_4_ONLY"
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
                        "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
                        "PUBLIC_CHALLENGE_SURVIVAL_NOT_EARNED",
                        "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
                        "REMOTE_PROVIDER_AUTH_DID_NOT_YIELD_SUCCESSFUL_CURRENT_HEAD_INFERENCE" if "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" in remaining_open else "REMOTE_PROVIDER_AUTH_BOUNDARY_NARROWED_BY_SUCCESSFUL_AUTHENTICATED_PROBE",
                    ],
                    "cleared_blockers": [
                        "wave4_chaos_lane_absent",
                        "typed_challenge_protocol_absent",
                        "wave4_formal_invariant_artifacts_absent",
                    ],
                    "completed_outputs": [
                        "kt_wave4_chaos_manifest",
                        "kt_wave4_challenge_protocol",
                        "kt_wave4_public_challenge_receipt",
                        "kt_wave4_externality_class_matrix",
                        "kt_wave4_challenge_dispositions",
                        "kt_wave4_formal_invariant_artifacts",
                    ],
                    "remaining_open_contradictions": remaining_open,
                }
            )
    write_json_stable(gate_path, gate)

    truth_map["generated_utc"] = utc_now_iso_z()
    truth_map["current_git_head"] = head
    truth_map["source_surfaces"]["current_head_wave4_chaos_surface"] = CHAOS_MANIFEST_REL
    truth_map["source_surfaces"]["current_head_wave4_challenge_protocol_surface"] = CHALLENGE_PROTOCOL_REL
    truth_map["source_surfaces"]["current_head_wave4_public_challenge_surface"] = PUBLIC_CHALLENGE_RECEIPT_REL
    truth_map["source_surfaces"]["current_head_wave4_externality_surface"] = EXTERNALITY_MATRIX_REL
    truth_map["source_surfaces"]["current_head_wave4_formal_invariant_surface"] = FORMAL_INVARIANTS_REL
    truth_map["truth_partitions"]["current_head_trust_and_provenance_truth"]["summary"] = (
        "Wave 1 machine-binds trust/provenance surfaces, Wave 2A binds real live provider execution to the frozen Adapter ABI with bounded failure artifacts, Wave 2B adds replayable shadow routing evidence without cutover, Wave 2C adds bounded organ proof packs, C017 proves canonical-spine carriage, FL3 refreshes the live law bundle, Wave 3 proves a same-host packaged detached verifier path plus bounded claim compilation, and Wave 4 now adds hostile current-head probes, typed challenge protocol, and bounded invariant checks without widening externality above E1."
    )
    truth_map["truth_partitions"]["integrated_overall_truth"]["summary"] = (
        "Integrated current-head truth now includes one bounded minimum viable organism run, one same-host packaged detached verifier path, one bounded claim-class output, and one bounded Wave 4 hostile-probe/challenge layer. Overall truth remains bounded by the open externality ceiling, auth-bounded remote provider reality unless separately narrowed, and unresolved repo-root import fragility."
    )
    write_json_stable(truth_map_path, truth_map)

    runtime_map["generated_utc"] = utc_now_iso_z()
    runtime_map["current_git_head"] = head
    runtime_map["runtime_roots"]["wave4_chaos_and_challenge_status"] = "PASS_BOUNDED_TYPED_CHALLENGE_LAYER"
    runtime_map["wave4_chaos_and_external_challenge_lane"] = {
        "status": "PASS",
        "boundary_holds": [
            "CANONICAL_STATIC_ROUTER_RETAINS_AUTHORITY",
            "LEARNED_ROUTER_CUTOVER_NOT_EARNED",
            "EXTERNALITY_CEILING_REMAINS_BOUNDED_AT_E1",
            "PUBLIC_CHALLENGE_SURVIVAL_NOT_EARNED",
            "REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED",
        ],
        "evidence_refs": [CHAOS_MANIFEST_REL, CHALLENGE_PROTOCOL_REL, PUBLIC_CHALLENGE_RECEIPT_REL, EXTERNALITY_MATRIX_REL, CHALLENGE_DISPOSITIONS_REL, FORMAL_INVARIANTS_REL],
        "externality_classes_earned": ["E0_INTERNAL_SELF_ISSUED_ONLY", "E1_SAME_HOST_DETACHED_REPLAY"],
        "challenge_channel_used": CHALLENGE_CHANNEL_ID,
    }
    write_json_stable(runtime_map_path, runtime_map)

    contradiction_table["generated_utc"] = utc_now_iso_z()
    contradiction_table["current_git_head"] = head
    for row in contradiction_table.get("rows", []):
        if row.get("contradiction_id") == "C006_EXTERNALITY_CEILING_REMAINS_BOUNDED":
            row["evidence_refs"] = [
                EXTERNALITY_MATRIX_REL,
                PUBLIC_CHALLENGE_RECEIPT_REL,
                WAVE3_DETACHED_RECEIPT_REL,
            ]
            row["state"] = "OPEN_TYPED_WAVE_4_E0_E1_ONLY"
            row["summary"] = "Wave 4 adds hostile internal probes and a typed signed challenge channel, but only E0 internal hostile evidence and E1 same-host packaged detached replay are earned. Cross-host friendly replay, independent hostile replay, and public challenge survival remain unearned."
        if row.get("contradiction_id") == "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" and "C016_REMOTE_PROVIDER_AUTH_ONLY_FAIL_CLOSED_OUTCOMES_VISIBLE" not in remaining_open:
            row["state"] = "NARROWED_WAVE_4_AUTHENTICATED_SUCCESS_OBSERVED"
            row["summary"] = "Wave 4 observed at least one successful authenticated live provider response on the bounded current-head lane, so the old auth-only contradiction is narrowed. Broader externality and runtime superiority remain unearned."
            row["resolution_receipts"] = _append_unique(row.get("resolution_receipts", []), [CHAOS_MANIFEST_REL, PUBLIC_CHALLENGE_RECEIPT_REL])
    write_json_stable(contradiction_path, contradiction_table)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Wave 4 chaos and external challenge on the bounded current-head organism.")
    parser.add_argument("--receipt-output", default=MAIN_RECEIPT_REL)
    parser.add_argument("--chaos-output", default=CHAOS_MANIFEST_REL)
    parser.add_argument("--protocol-output", default=CHALLENGE_PROTOCOL_REL)
    parser.add_argument("--public-challenge-output", default=PUBLIC_CHALLENGE_RECEIPT_REL)
    parser.add_argument("--externality-output", default=EXTERNALITY_MATRIX_REL)
    parser.add_argument("--dispositions-output", default=CHALLENGE_DISPOSITIONS_REL)
    parser.add_argument("--formal-output", default=FORMAL_INVARIANTS_REL)
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
    chaos_path = Path(str(args.chaos_output)).expanduser()
    if not chaos_path.is_absolute():
        chaos_path = (root / chaos_path).resolve()
    protocol_path = Path(str(args.protocol_output)).expanduser()
    if not protocol_path.is_absolute():
        protocol_path = (root / protocol_path).resolve()
    public_challenge_path = Path(str(args.public_challenge_output)).expanduser()
    if not public_challenge_path.is_absolute():
        public_challenge_path = (root / public_challenge_path).resolve()
    externality_path = Path(str(args.externality_output)).expanduser()
    if not externality_path.is_absolute():
        externality_path = (root / externality_path).resolve()
    dispositions_path = Path(str(args.dispositions_output)).expanduser()
    if not dispositions_path.is_absolute():
        dispositions_path = (root / dispositions_path).resolve()
    formal_path = Path(str(args.formal_output)).expanduser()
    if not formal_path.is_absolute():
        formal_path = (root / formal_path).resolve()
    telemetry_path = Path(str(args.telemetry_output)).expanduser()
    if not telemetry_path.is_absolute():
        telemetry_path = (root / telemetry_path).resolve()
    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()

    outputs = build_wave4_outputs(root=root, export_root=export_root, telemetry_path=telemetry_path)
    write_json_stable(receipt_path, outputs["main_receipt"])
    write_json_stable(chaos_path, outputs["chaos_manifest"])
    write_json_stable(protocol_path, outputs["challenge_protocol"])
    write_json_stable(public_challenge_path, outputs["public_challenge_receipt"])
    write_json_stable(externality_path, outputs["externality_matrix"])
    write_json_stable(dispositions_path, outputs["challenge_dispositions"])
    write_json_stable(formal_path, outputs["formal_invariants"])

    if args.update_convergence_surfaces:
        update_convergence_surfaces(root=root, outputs=outputs)

    print(
        json.dumps(
            {
                "status": outputs["main_receipt"]["status"],
                "challenge_channel_used": outputs["main_receipt"]["challenge_channel_used"],
                "externality_classes_earned": outputs["main_receipt"]["externality_classes_earned"],
                "successful_findings_count": outputs["main_receipt"]["successful_findings_count"],
                "remaining_open_contradictions": outputs["main_receipt"]["remaining_open_contradictions"],
            },
            sort_keys=True,
        )
    )
    return 0 if outputs["main_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
