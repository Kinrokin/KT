from __future__ import annotations

import os
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_CLEANROOM_ROOT = Path(__file__).resolve().parents[2]
_SRC_ROOT = _CLEANROOM_ROOT / "04_PROD_TEMPLE_V2" / "src"
for _path in (str(_CLEANROOM_ROOT), str(_SRC_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from cognition.cognitive_schemas import CognitiveRequestSchema, MODE_DRY_RUN as COGNITION_MODE_DRY_RUN
from core.runtime_registry import load_runtime_registry
from core.spine import _runtime_registry_hash
from council.council_schemas import CouncilRequestSchema, MODE_DRY_RUN as COUNCIL_MODE_DRY_RUN
from schemas.schema_hash import sha256_text
from tools.operator.runtime_boundary_integrity import build_runtime_boundary_integrity_receipt
from tools.operator.titanium_common import load_json, repo_root, utc_now_iso_z, write_json_stable
from tools.operator.trust_zone_validate import validate_trust_zones


DEFAULT_REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
DEFAULT_EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/w1_single_spine"

CANONICAL_ENTRY_MODULE = "kt.entrypoint"
CANONICAL_ENTRY_CALLABLE = "invoke"
CANONICAL_SPINE_MODULE = "core.spine"
CANONICAL_SPINE_CALLABLE = "run"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def _git_head(root: Path) -> str:
    try:
        return _git(root, "rev-parse", "HEAD")
    except Exception:  # noqa: BLE001
        return ""


def _module_ref(module_name: str, callable_name: str) -> str:
    return f"KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/{module_name.replace('.', '/')}.py::{callable_name}"


def _module_file_ref(module_name: str) -> str:
    return f"KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/{module_name.replace('.', '/')}.py"


def _build_cognition_probe_payload(*, registry_hash: str) -> Dict[str, Any]:
    return CognitiveRequestSchema.from_dict(
        {
            "schema_id": CognitiveRequestSchema.SCHEMA_ID,
            "schema_version_hash": CognitiveRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w1.canonical_spine.cognition",
            "runtime_registry_hash": registry_hash,
            "mode": COGNITION_MODE_DRY_RUN,
            "input_hash": sha256_text("w1 canonical spine cognition request"),
            "max_steps": 3,
            "max_branching": 1,
            "max_depth": 3,
            "artifact_refs": [],
        }
    ).to_dict()


def _build_council_probe_payload(*, registry_hash: str) -> Dict[str, Any]:
    return CouncilRequestSchema.from_dict(
        {
            "schema_id": CouncilRequestSchema.SCHEMA_ID,
            "schema_version_hash": CouncilRequestSchema.SCHEMA_VERSION_HASH,
            "request_id": "w1.canonical_spine.council",
            "runtime_registry_hash": registry_hash,
            "mode": COUNCIL_MODE_DRY_RUN,
            "provider_ids": ["dry_run"],
            "fanout_cap": 1,
            "per_call_token_cap": 128,
            "total_token_cap": 256,
            "input_hash": sha256_text("w1 canonical spine council request"),
        }
    ).to_dict()


def _build_probe_spec_matrix(*, registry_hash: str) -> List[Dict[str, Any]]:
    return [
        {
            "probe_id": "cognition_request",
            "payload": _build_cognition_probe_payload(registry_hash=registry_hash),
            "summary_key": "cognition",
            "required_status": "OK",
        },
        {
            "probe_id": "council_request",
            "payload": _build_council_probe_payload(registry_hash=registry_hash),
            "summary_key": "council",
            "required_status": "OK",
        },
    ]


def _build_canonical_scope_manifest_receipt(*, root: Path) -> Dict[str, Any]:
    canonical_scope = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "canonical_scope_manifest.json")
    trust_zone_registry = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "trust_zone_registry.json")
    runtime_boundary_contract = load_json(root / "KT_PROD_CLEANROOM" / "governance" / "runtime_boundary_contract.json")
    runtime_registry = load_json(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json")

    zones = {str(zone.get("zone_id", "")).strip().upper(): zone for zone in trust_zone_registry.get("zones", []) if isinstance(zone, dict)}
    canonical_zone = zones.get("CANONICAL", {})
    toolchain_zone = zones.get("TOOLCHAIN_PROVING", {})

    expected_callable_refs = [
        _module_ref(CANONICAL_ENTRY_MODULE, CANONICAL_ENTRY_CALLABLE),
        _module_ref(CANONICAL_SPINE_MODULE, CANONICAL_SPINE_CALLABLE),
    ]
    expected_file_refs = [
        _module_file_ref(CANONICAL_ENTRY_MODULE),
        _module_file_ref(CANONICAL_SPINE_MODULE),
    ]

    checks: List[Dict[str, Any]] = []
    failures: List[str] = []

    def add_check(name: str, condition: bool, **payload: Any) -> None:
        checks.append({"check": name, "status": "PASS" if condition else "FAIL", **payload})
        if not condition:
            failures.append(name)

    registry_entry_ok = runtime_registry.get("canonical_entry", {}) == {
        "module": CANONICAL_ENTRY_MODULE,
        "callable": CANONICAL_ENTRY_CALLABLE,
    }
    add_check(
        "runtime_registry_declares_expected_canonical_entry",
        registry_entry_ok,
        actual=runtime_registry.get("canonical_entry"),
    )

    registry_spine_ok = runtime_registry.get("canonical_spine", {}) == {
        "module": CANONICAL_SPINE_MODULE,
        "callable": CANONICAL_SPINE_CALLABLE,
    }
    add_check(
        "runtime_registry_declares_expected_canonical_spine",
        registry_spine_ok,
        actual=runtime_registry.get("canonical_spine"),
    )

    add_check(
        "canonical_scope_manifest_declares_callable_lane",
        canonical_scope.get("claim_bearing_runtime_path") == expected_callable_refs,
        actual=canonical_scope.get("claim_bearing_runtime_path"),
        expected=expected_callable_refs,
    )

    add_check(
        "canonical_zone_declares_file_lane",
        canonical_zone.get("claim_bearing_runtime_path") == expected_file_refs,
        actual=canonical_zone.get("claim_bearing_runtime_path"),
        expected=expected_file_refs,
    )

    add_check(
        "runtime_boundary_contract_declares_entry_ref",
        runtime_boundary_contract.get("canonical_entry_ref") == expected_file_refs[0]
        and runtime_boundary_contract.get("canonical_entry_callable") == f"{CANONICAL_ENTRY_MODULE}.{CANONICAL_ENTRY_CALLABLE}",
        actual={
            "canonical_entry_ref": runtime_boundary_contract.get("canonical_entry_ref"),
            "canonical_entry_callable": runtime_boundary_contract.get("canonical_entry_callable"),
        },
    )

    add_check(
        "runtime_boundary_contract_declares_spine_ref",
        runtime_boundary_contract.get("canonical_spine_ref") == expected_file_refs[1]
        and runtime_boundary_contract.get("canonical_spine_callable") == f"{CANONICAL_SPINE_MODULE}.{CANONICAL_SPINE_CALLABLE}",
        actual={
            "canonical_spine_ref": runtime_boundary_contract.get("canonical_spine_ref"),
            "canonical_spine_callable": runtime_boundary_contract.get("canonical_spine_callable"),
        },
    )

    expected_support_refs = {
        "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
        "KT_PROD_CLEANROOM/tools/operator/wave3_canonical_entry_probe.py",
    }
    actual_support_refs = {str(item).strip() for item in canonical_scope.get("claim_bearing_runtime_support_refs", []) if str(item).strip()}
    add_check(
        "canonical_scope_manifest_declares_runtime_support_refs",
        expected_support_refs.issubset(actual_support_refs),
        actual=sorted(actual_support_refs),
        expected=sorted(expected_support_refs),
    )

    forbidden_side_paths = [str(item).strip() for item in canonical_scope.get("forbidden_live_side_paths", []) if str(item).strip()]
    forbidden_noncanonical = [
        str(item).strip() for item in runtime_boundary_contract.get("forbidden_noncanonical_live_execution_globs", []) if str(item).strip()
    ]
    add_check(
        "forbidden_side_paths_match_runtime_boundary_contract",
        forbidden_side_paths == forbidden_noncanonical,
        actual=forbidden_side_paths,
        expected=forbidden_noncanonical,
    )

    add_check(
        "toolchain_proving_claim_upgrade_forbidden",
        bool(toolchain_zone.get("live_execution_claim_upgrade_forbidden")) is True,
        actual=toolchain_zone.get("live_execution_claim_upgrade_forbidden"),
    )

    add_check(
        "single_spine_rule_declared_in_all_governance_surfaces",
        all(
            bool(str(value).strip())
            for value in (
                canonical_scope.get("single_spine_runtime_rule"),
                trust_zone_registry.get("single_spine_runtime_rule"),
                runtime_boundary_contract.get("claim_bearing_runtime_rule"),
            )
        ),
        actual={
            "canonical_scope": canonical_scope.get("single_spine_runtime_rule"),
            "trust_zone_registry": trust_zone_registry.get("single_spine_runtime_rule"),
            "runtime_boundary_contract": runtime_boundary_contract.get("claim_bearing_runtime_rule"),
        },
    )

    status = "PASS" if not failures else "FAIL"
    return {
        "schema_id": "kt.operator.canonical_scope_manifest_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": _git_head(root),
        "canonical_callable_lane": expected_callable_refs,
        "canonical_file_lane": expected_file_refs,
        "checks": checks,
        "failures": failures,
        "claim_boundary": (
            "Only kt.entrypoint.invoke may carry claim-bearing runtime requests into core.spine.run; governance, toolchain, and documentary surfaces may observe but may not upgrade runtime claims."
        ),
        "authority_refs": [
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
        ],
    }


def _build_runtime_boundary_receipt(*, root: Path, report_root_rel: str) -> Dict[str, Any]:
    receipt = build_runtime_boundary_integrity_receipt(root=root, report_root_rel=report_root_rel)
    return {
        "schema_id": "kt.operator.runtime_boundary_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": receipt["status"],
        "validated_head_sha": receipt.get("validated_head_sha", ""),
        "runtime_boundary_verdict": receipt.get("runtime_boundary_verdict", ""),
        "runtime_boundary_claim_admissible": bool(receipt.get("runtime_boundary_claim_admissible")),
        "runtime_boundary_claim_boundary": receipt.get("runtime_boundary_claim_boundary", ""),
        "canonical_runtime_roots": list(receipt.get("canonical_runtime_roots", [])),
        "compatibility_allowlist_roots": list(receipt.get("compatibility_allowlist_roots", [])),
        "checks": list(receipt.get("checks", [])),
        "failures": list(receipt.get("failures", [])),
        "authority_refs": list(receipt.get("authority_refs", [])),
        "report_root": report_root_rel,
    }


def _run_canonical_entry_probes(*, root: Path, export_root: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    registry_hash = _runtime_registry_hash(load_runtime_registry())
    failures: List[str] = []
    rows: List[Dict[str, Any]] = []
    cleanroom_root = root / "KT_PROD_CLEANROOM"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(cleanroom_root) + os.pathsep + str(cleanroom_root / "04_PROD_TEMPLE_V2" / "src")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

    for spec in _build_probe_spec_matrix(registry_hash=registry_hash):
        probe_root = (export_root / spec["probe_id"]).resolve()
        probe_root.mkdir(parents=True, exist_ok=True)
        payload_path = probe_root / "payload.json"
        output_path = probe_root / "entry_result.json"
        payload_path.write_text(json.dumps(spec["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "tools.operator.wave3_canonical_entry_probe",
                "--payload-file",
                str(payload_path),
                "--artifact-root",
                str(probe_root / "artifacts"),
                "--output",
                str(output_path),
            ],
            cwd=str(cleanroom_root),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if proc.returncode != 0:
            failures.append(f"{spec['probe_id']}_probe_cli_failed")
            rows.append(
                {
                    "probe_id": spec["probe_id"],
                    "status": "FAIL",
                    "artifact_root": (probe_root / "artifacts").as_posix(),
                    "entry_result_status": "FAIL",
                    "record_count": None,
                    "head_hash": "",
                    "organ_key": spec["summary_key"],
                    "organ_status": "",
                    "observed_summary": {"stdout": proc.stdout},
                }
            )
            continue

        result = json.loads(output_path.read_text(encoding="utf-8"))
        entry_result = dict(result.get("entry_result", {}))
        organ_summary = dict(entry_result.get(spec["summary_key"], {}))
        row = {
            "probe_id": spec["probe_id"],
            "status": "PASS",
            "artifact_root": result.get("artifact_root", ""),
            "entry_result_status": entry_result.get("status", ""),
            "record_count": entry_result.get("record_count"),
            "head_hash": entry_result.get("head_hash", ""),
            "organ_key": spec["summary_key"],
            "organ_status": organ_summary.get("status", ""),
            "observed_summary": organ_summary,
        }
        if entry_result.get("status") != "OK":
            row["status"] = "FAIL"
            failures.append(f"{spec['probe_id']}_entry_result_not_ok")
        if organ_summary.get("status") != spec["required_status"]:
            row["status"] = "FAIL"
            failures.append(f"{spec['probe_id']}_organ_status_not_{str(spec['required_status']).lower()}")
        if not isinstance(entry_result.get("record_count"), int) or int(entry_result["record_count"]) <= 0:
            row["status"] = "FAIL"
            failures.append(f"{spec['probe_id']}_record_count_not_positive")
        if not isinstance(entry_result.get("head_hash"), str) or len(str(entry_result.get("head_hash", ""))) != 64:
            row["status"] = "FAIL"
            failures.append(f"{spec['probe_id']}_head_hash_invalid")
        rows.append(row)

    return rows, failures


def build_single_spine_receipts(
    *,
    root: Path,
    report_root_rel: str = DEFAULT_REPORT_ROOT_REL,
    export_root: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    resolved_export_root = (export_root or (root / DEFAULT_EXPORT_ROOT_REL)).resolve()
    resolved_export_root.mkdir(parents=True, exist_ok=True)

    canonical_scope_receipt = _build_canonical_scope_manifest_receipt(root=root)
    runtime_boundary_receipt = _build_runtime_boundary_receipt(root=root, report_root_rel=report_root_rel)
    trust_zone_report = validate_trust_zones(root=root)
    probe_rows, probe_failures = _run_canonical_entry_probes(root=root, export_root=resolved_export_root)

    failures: List[str] = []
    if canonical_scope_receipt["status"] != "PASS":
        failures.append("canonical_scope_manifest_receipt_failed")
    if runtime_boundary_receipt["status"] != "PASS":
        failures.append("runtime_boundary_receipt_failed")
    if trust_zone_report["status"] != "PASS":
        failures.append("trust_zone_validation_failed")
    failures.extend(probe_failures)

    status = "PASS" if not failures else "FAIL"
    single_spine_path_receipt = {
        "schema_id": "kt.operator.single_spine_path_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": _git_head(root),
        "canonical_entry_callable": f"{CANONICAL_ENTRY_MODULE}.{CANONICAL_ENTRY_CALLABLE}",
        "canonical_spine_callable": f"{CANONICAL_SPINE_MODULE}.{CANONICAL_SPINE_CALLABLE}",
        "claim_boundary": "The only claim-bearing live execution lane is kt.entrypoint.invoke -> core.spine.run. Toolchain probes may observe and package this lane but may never become runtime truth surfaces.",
        "canonical_scope_manifest_receipt_ref": f"{report_root_rel}/canonical_scope_manifest_receipt.json",
        "runtime_boundary_receipt_ref": f"{report_root_rel}/runtime_boundary_receipt.json",
        "trust_zone_validation_status": trust_zone_report.get("status", "FAIL"),
        "trust_zone_failures": list(trust_zone_report.get("failures", [])),
        "probe_matrix": probe_rows,
        "failures": failures,
        "remaining_forbidden_claims": [
            "E2_or_higher_externality",
            "cross_host_replay",
            "hostile_or_independent_verification",
            "router_superiority",
            "multi_lobe_execution",
            "frontier_or_sota_language",
        ],
        "next_lawful_move": "W2_RUNTIME_ORGAN_REALIZATION_AND_MVCR",
        "authority_refs": [
            "KT_PROD_CLEANROOM/governance/canonical_scope_manifest.json",
            "KT_PROD_CLEANROOM/governance/trust_zone_registry.json",
            "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json",
            "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
            "KT_PROD_CLEANROOM/tools/operator/wave3_canonical_entry_probe.py",
        ],
    }

    return {
        "canonical_scope_manifest_receipt": canonical_scope_receipt,
        "runtime_boundary_receipt": runtime_boundary_receipt,
        "single_spine_path_receipt": single_spine_path_receipt,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate W1 single-spine law and canonical live execution path.")
    parser.add_argument(
        "--canonical-scope-output",
        default=f"{DEFAULT_REPORT_ROOT_REL}/canonical_scope_manifest_receipt.json",
    )
    parser.add_argument(
        "--runtime-boundary-output",
        default=f"{DEFAULT_REPORT_ROOT_REL}/runtime_boundary_receipt.json",
    )
    parser.add_argument(
        "--single-spine-output",
        default=f"{DEFAULT_REPORT_ROOT_REL}/single_spine_path_receipt.json",
    )
    parser.add_argument(
        "--export-root",
        default=DEFAULT_EXPORT_ROOT_REL,
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()

    canonical_scope_output = Path(str(args.canonical_scope_output)).expanduser()
    if not canonical_scope_output.is_absolute():
        canonical_scope_output = (root / canonical_scope_output).resolve()

    runtime_boundary_output = Path(str(args.runtime_boundary_output)).expanduser()
    if not runtime_boundary_output.is_absolute():
        runtime_boundary_output = (root / runtime_boundary_output).resolve()

    single_spine_output = Path(str(args.single_spine_output)).expanduser()
    if not single_spine_output.is_absolute():
        single_spine_output = (root / single_spine_output).resolve()

    export_root = Path(str(args.export_root)).expanduser()
    if not export_root.is_absolute():
        export_root = (root / export_root).resolve()

    receipts = build_single_spine_receipts(root=root, report_root_rel=DEFAULT_REPORT_ROOT_REL, export_root=export_root)
    write_json_stable(canonical_scope_output, receipts["canonical_scope_manifest_receipt"])
    write_json_stable(runtime_boundary_output, receipts["runtime_boundary_receipt"])
    write_json_stable(single_spine_output, receipts["single_spine_path_receipt"])

    summary = {
        "canonical_scope_status": receipts["canonical_scope_manifest_receipt"]["status"],
        "runtime_boundary_status": receipts["runtime_boundary_receipt"]["status"],
        "single_spine_status": receipts["single_spine_path_receipt"]["status"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipts["single_spine_path_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
