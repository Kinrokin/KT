from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cognition.cognitive_engine import CognitiveEngine
from cognition.cognitive_schemas import CognitivePlanSchema, CognitiveRequestSchema, MODE_DRY_RUN as COGNITION_MODE_DRY_RUN
from core.claim_compiler import compile_runtime_claims
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from core.invariants_gate import CONSTITUTION_VERSION_HASH
from council.council_router import CouncilRouter
from council.council_schemas import CouncilPlanSchema, CouncilRequestSchema, MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN
from memory.replay import validate_state_vault_chain
from schemas.runtime_context_schema import RUNTIME_CONTEXT_SCHEMA_ID, RUNTIME_CONTEXT_SCHEMA_VERSION_HASH
from schemas.schema_hash import sha256_text
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/w2_mvcr"
MVCR_RECEIPT_REL = f"{REPORT_ROOT_REL}/mvcr_current_head_receipt.json"
PUBLIC_VERIFIER_KIT_REL = f"{REPORT_ROOT_REL}/public_verifier_kit.json"
USEFUL_OUTPUT_REL = f"{REPORT_ROOT_REL}/useful_output_benchmark.json"
PROVIDER_PATH_REL = f"{REPORT_ROOT_REL}/provider_path_integrity_receipt.json"


def _tool_env(root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _git_head(root: Path) -> str:
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _base_context() -> Dict[str, Any]:
    return {
        "constitution_version_hash": CONSTITUTION_VERSION_HASH,
        "envelope": {"input": ""},
        "schema_id": RUNTIME_CONTEXT_SCHEMA_ID,
        "schema_version_hash": RUNTIME_CONTEXT_SCHEMA_VERSION_HASH,
    }


def _registry_hash() -> str:
    return _runtime_registry_hash(load_runtime_registry())


def _rel(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _expected_specs(registry_hash: str) -> List[Dict[str, Any]]:
    council_request = CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w2.mvcr.council.request",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_DRY_RUN,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 128,
            "total_token_cap": 256,
            "input_hash": sha256_text("w2 mvcr council input"),
        }
    )
    council_plan = CouncilRouter.plan(context=_base_context(), request=council_request).to_dict()
    council_result = CouncilRouter.execute(context=_base_context(), plan=CouncilPlanSchema.from_dict(council_plan)).to_dict()

    cognition_request = CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w2.mvcr.cognition.request",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("w2 mvcr cognition input"),
            "max_steps": 4,
            "max_branching": 1,
            "max_depth": 4,
            "artifact_refs": [{"artifact_hash": sha256_text("w2.mvcr.trace"), "artifact_id": "memory.trace"}],
        }
    )
    cognition_plan = CognitiveEngine.plan(context=_base_context(), request=cognition_request).to_dict()
    cognition_result = CognitiveEngine.execute(context=_base_context(), plan=CognitivePlanSchema.from_dict(cognition_plan)).to_dict()

    return [
        {
            "step_id": "planner",
            "path_role": "planner",
            "payload": cognition_request.to_dict(),
            "slice_key": "cognition",
            "expected": {
                "status": cognition_plan["status"],
                "plan_hash": cognition_plan["plan_hash"],
                "request_hash": cognition_plan["request_hash"],
                "steps": len(cognition_plan["steps"]),
            },
        },
        {
            "step_id": "router",
            "path_role": "router",
            "payload": council_request.to_dict(),
            "slice_key": "council",
            "expected": {
                "status": council_plan["status"],
                "plan_hash": council_plan["plan_hash"],
                "request_hash": council_plan["request_hash"],
            },
        },
        {
            "step_id": "adapter_or_provider",
            "path_role": "adapter_or_provider",
            "payload": CouncilPlanSchema.from_dict(council_plan).to_dict(),
            "slice_key": "council",
            "expected": {
                "status": council_result["status"],
                "plan_hash": council_result["plan_hash"],
                "result_hash": council_result["result_hash"],
            },
        },
        {
            "step_id": "organ_stack",
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


def _run_entry_probe(root: Path, export_root: Path, spec: Dict[str, Any]) -> Dict[str, Any]:
    probe_root = (export_root / "canonical_run" / spec["step_id"]).resolve()
    probe_root.mkdir(parents=True, exist_ok=True)
    artifact_root = (probe_root / "artifacts").resolve()
    payload_path = probe_root / "payload.json"
    output_path = probe_root / "entry_result.json"
    runtime_telemetry_path = probe_root / "runtime_telemetry.jsonl"

    payload_path.write_text(json.dumps(spec["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
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
        env=_tool_env(root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: MVCR canonical entry probe failed for {spec['step_id']}: {proc.stdout}")

    probe_payload = json.loads(output_path.read_text(encoding="utf-8"))
    entry_result = dict(probe_payload["entry_result"])
    runtime_slice = entry_result.get(str(spec["slice_key"]), {})
    comparison = {key: runtime_slice.get(key) == value for key, value in spec["expected"].items()}
    comparison_pass = str(entry_result.get("status", "")).strip() == "OK" and all(comparison.values())

    return {
        "step_id": spec["step_id"],
        "path_role": spec["path_role"],
        "status": "PASS" if comparison_pass else "FAIL",
        "comparison": comparison,
        "entry_result_status": entry_result.get("status", ""),
        "result_record_count": entry_result.get("record_count", 0),
        "result_head_hash": entry_result.get("head_hash", ""),
        "artifact_refs": {
            "artifact_root_ref": _rel(root, artifact_root),
            "payload_ref": _rel(root, payload_path),
            "entry_result_ref": _rel(root, output_path),
            "runtime_telemetry_ref": _rel(root, runtime_telemetry_path) if runtime_telemetry_path.exists() else "",
        },
    }


def build_mvcr_receipt(*, root: Path, export_root: Path) -> Dict[str, Any]:
    registry = load_runtime_registry()
    state_vault_path = registry.resolve_state_vault_jsonl_path()
    pre_replay = validate_state_vault_chain(state_vault_path)

    probe_rows = [_run_entry_probe(root, export_root, spec) for spec in _expected_specs(_registry_hash())]
    post_replay = validate_state_vault_chain(state_vault_path)

    public_verifier_kit = load_json(root / PUBLIC_VERIFIER_KIT_REL)
    useful_output = load_json(root / USEFUL_OUTPUT_REL)
    provider_path_integrity = load_json(root / PROVIDER_PATH_REL)
    runtime_claim_compilation = compile_runtime_claims(
        root=root,
        useful_output_benchmark=useful_output,
        provider_path_integrity=provider_path_integrity,
    )

    remaining_forbidden_claims: List[str] = []
    for item in runtime_claim_compilation.get("forbidden_current_claims", []):
        text = str(item).strip()
        if text and text not in remaining_forbidden_claims:
            remaining_forbidden_claims.append(text)
    for item in (
        "Do not claim router superiority.",
        "Do not claim multi-lobe execution.",
        "Do not claim frontier, SOTA, or beyond-SOTA standing.",
    ):
        if item not in remaining_forbidden_claims:
            remaining_forbidden_claims.append(item)

    canonical_run_status = "PASS" if all(row["status"] == "PASS" for row in probe_rows) else "FAIL"
    verifier_pack_status = str(public_verifier_kit.get("status", "")).strip().upper()
    state_vault_delta = int(post_replay.record_count) - int(pre_replay.record_count)
    status = "PASS" if (
        canonical_run_status == "PASS"
        and verifier_pack_status == "PASS"
        and runtime_claim_compilation["status"] == "PASS"
        and state_vault_delta > 0
    ) else "FAIL"

    return {
        "schema_id": "kt.w2.mvcr_current_head_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": _git_head(root),
        "status": status,
        "claim_boundary": "W2 MVCR proves one bounded current-head sacred path only. It does not widen externality, comparative, commercial, router, or prestige claims.",
        "exact_end_to_end_path_exercised": [
            {"path_role": "ingress", "surface": "kt.entrypoint.invoke", "mode": "CANONICAL"},
            {"path_role": "planner", "surface": "core.spine.run -> cognition.request -> cognition.plan", "mode": "BOUNDED_CANONICAL"},
            {"path_role": "router", "surface": "core.spine.run -> council.request -> council.plan", "mode": "STATIC_CANONICAL_BASELINE"},
            {"path_role": "adapter_or_provider", "surface": "core.spine.run -> council.plan -> council.execute", "mode": "DRY_RUN_CANONICAL_ADAPTER_INVOCATION"},
            {"path_role": "organ_stack", "surface": "core.spine.run -> cognition.plan -> cognition.execute", "mode": "BOUNDED_CANONICAL"},
            {"path_role": "memory_or_state_vault", "surface": "memory.replay.validate_state_vault_chain", "mode": "CANONICAL"},
            {"path_role": "verifier_pack", "surface": PUBLIC_VERIFIER_KIT_REL, "mode": "BOUNDED_E1_READY"},
            {"path_role": "claim_compiler", "surface": "core.claim_compiler.compile_runtime_claims", "mode": "BOUNDED_RUNTIME_VOCABULARY_GATE"},
            {"path_role": "bounded_output", "surface": MVCR_RECEIPT_REL, "mode": "BOUNDED_CURRENT_HEAD_RECEIPT"},
        ],
        "probe_matrix": probe_rows,
        "canonical_run_status": canonical_run_status,
        "state_vault_ref": _rel(root, state_vault_path),
        "state_vault_before": {"record_count": pre_replay.record_count, "head_hash": pre_replay.head_hash},
        "state_vault_after": {"record_count": post_replay.record_count, "head_hash": post_replay.head_hash},
        "state_vault_delta_records": state_vault_delta,
        "verifier_pack_status": public_verifier_kit.get("status", ""),
        "verifier_pack_ref": PUBLIC_VERIFIER_KIT_REL,
        "verifier_pack_boundary": public_verifier_kit.get("claim_boundary", ""),
        "runtime_claim_compilation": runtime_claim_compilation,
        "bounded_output": {
            "status": "PASS" if runtime_claim_compilation["status"] == "PASS" and verifier_pack_status == "PASS" else "FAIL",
            "summary": "One bounded sacred path now executes on current head with state-vault receipts, bounded verifier support, and bounded claim compilation.",
            "allowed_current_claims": list(runtime_claim_compilation.get("allowed_current_claims", [])),
        },
        "remaining_forbidden_claims": remaining_forbidden_claims,
        "next_lawful_move": "W3_UNIVERSAL_ADAPTER_AND_CIVILIZATION_LOOP",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the current-head minimum viable civilization run on the canonical W2 sacred path.")
    parser.add_argument("--receipt-output", default=MVCR_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    receipt_output = Path(str(args.receipt_output)).expanduser()
    if not receipt_output.is_absolute():
        receipt_output = (root / receipt_output).resolve()
    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()
    export_root.mkdir(parents=True, exist_ok=True)

    receipt = build_mvcr_receipt(root=root, export_root=export_root)
    write_json_stable(receipt_output, receipt)

    print(
        json.dumps(
            {
                "canonical_run_status": receipt["canonical_run_status"],
                "status": receipt["status"],
                "state_vault_delta_records": receipt["state_vault_delta_records"],
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
