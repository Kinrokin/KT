from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from tools.operator.b02_runtime_unify_validate import build_b02_runtime_unify_outputs
from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


REPORT_ROOT_REL = "KT_PROD_CLEANROOM/reports"
EXPORT_ROOT_REL = "KT_PROD_CLEANROOM/exports/b02_runtime_unify_t2"

B02_T1_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_receipt.json"
B02_T2_SPINE_EXCLUSIVITY_REL = f"{REPORT_ROOT_REL}/b02_spine_exclusivity_receipt.json"
B02_T2_DEPENDENCY_TRUTH_REL = f"{REPORT_ROOT_REL}/b02_dependency_truth_receipt.json"
B02_T2_PATH_HARDENING_REL = f"{REPORT_ROOT_REL}/b02_multi_organ_path_hardening_receipt.json"
B02_T2_RECEIPT_REL = f"{REPORT_ROOT_REL}/b02_runtime_unify_t2_receipt.json"


def _resolve(root: Path, raw: str) -> Path:
    path = Path(str(raw)).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (root / path).resolve()


def _git_head(root: Path) -> str:
    import subprocess

    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def _status(payload: Mapping[str, Any]) -> str:
    return str(payload.get("status", "")).strip().upper()


def _is_pass(payload: Mapping[str, Any]) -> bool:
    return _status(payload) == "PASS"


def _load_runtime_registry(root: Path) -> Dict[str, Any]:
    path = root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "docs" / "RUNTIME_REGISTRY.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _src_root(root: Path) -> Path:
    return root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"


def _module_name_from_path(src_root: Path, path: Path) -> str:
    rel = path.relative_to(src_root)
    if rel.name == "__init__.py":
        return ".".join(rel.with_suffix("").parts[:-1])
    return ".".join(rel.with_suffix("").parts)


def _runtime_py_files(root: Path, runtime_roots: Sequence[str]) -> List[Path]:
    src_root = _src_root(root)
    paths: List[Path] = []
    for runtime_root in runtime_roots:
        base = src_root / runtime_root
        if base.exists():
            paths.extend(sorted(base.rglob("*.py")))
    return sorted(paths, key=lambda item: item.as_posix())


def _internal_import_targets(node: ast.AST) -> List[str]:
    targets: List[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            name = str(alias.name or "").strip()
            if name:
                targets.append(name)
    elif isinstance(node, ast.ImportFrom):
        module = str(node.module or "").strip()
        if module:
            targets.append(module)
    return targets


def build_b02_spine_exclusivity_receipt(*, root: Path, head: str, runtime_registry: Mapping[str, Any]) -> Dict[str, Any]:
    src_root = _src_root(root)
    runtime_roots = [str(item).strip() for item in runtime_registry.get("runtime_import_roots", []) if str(item).strip()]
    canonical_entry_module = str(runtime_registry.get("canonical_entry", {}).get("module", "")).strip()
    canonical_spine_module = str(runtime_registry.get("canonical_spine", {}).get("module", "")).strip()
    canonical_entry_path = src_root / Path(canonical_entry_module.replace(".", "/") + ".py")

    spine_import_rows: List[Dict[str, Any]] = []
    for path in _runtime_py_files(root, runtime_roots):
        module_name = _module_name_from_path(src_root, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        imports_spine = False
        imports_core_root = False
        for node in ast.walk(tree):
            for target in _internal_import_targets(node):
                if target == canonical_spine_module or target.startswith(f"{canonical_spine_module}."):
                    imports_spine = True
                if target == "core" or target.startswith("core."):
                    imports_core_root = True
        if imports_spine or imports_core_root:
            spine_import_rows.append(
                {
                    "module": module_name,
                    "path_ref": path.relative_to(root).as_posix(),
                    "imports_spine_module": imports_spine,
                    "imports_core_root": imports_core_root,
                    "allowed": module_name == canonical_entry_module or module_name.startswith("core."),
                }
            )

    offending_modules = [row for row in spine_import_rows if not row["allowed"]]
    checks = [
        {
            "check_id": "canonical_entry_is_declared_and_exists",
            "pass": bool(canonical_entry_module) and canonical_entry_path.exists(),
        },
        {
            "check_id": "no_non_entry_runtime_module_imports_spine_or_core_root",
            "pass": not offending_modules,
        },
        {
            "check_id": "only_entrypoint_is_expected_to_cross_into_spine_as_claim_ingress",
            "pass": any(row["module"] == canonical_entry_module for row in spine_import_rows),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.spine_exclusivity_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 2 proves runtime-root spine ingress exclusivity only. It does not ratify promotion civilization or widen runtime claims.",
        "canonical_entry_module": canonical_entry_module,
        "canonical_spine_module": canonical_spine_module,
        "spine_import_rows": spine_import_rows,
        "offending_runtime_modules": offending_modules,
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim promotion civilization is ratified.",
            "Do not claim runtime unification is complete.",
        ],
    }


def build_b02_dependency_truth_receipt(*, root: Path, head: str, runtime_registry: Mapping[str, Any]) -> Dict[str, Any]:
    src_root = _src_root(root)
    runtime_roots = [str(item).strip() for item in runtime_registry.get("runtime_import_roots", []) if str(item).strip()]
    organs_by_root = {str(k).strip(): str(v).strip() for k, v in runtime_registry.get("organs_by_root", {}).items() if str(k).strip()}
    import_truth_matrix = {
        str(k).strip(): {str(item).strip() for item in v if str(item).strip()}
        for k, v in runtime_registry.get("import_truth_matrix", {}).items()
        if str(k).strip()
    }

    violations: List[Dict[str, Any]] = []
    observed_edges: List[Tuple[str, str, str]] = []
    for path in _runtime_py_files(root, runtime_roots):
        module_name = _module_name_from_path(src_root, path)
        importer_top = module_name.split(".", 1)[0]
        importer_organ = organs_by_root.get(importer_top, "")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            for target in _internal_import_targets(node):
                top = target.split(".", 1)[0]
                if top not in runtime_roots:
                    continue
                imported_organ = organs_by_root.get(top, "")
                if not importer_organ or not imported_organ:
                    violations.append(
                        {
                            "module": module_name,
                            "path_ref": path.relative_to(root).as_posix(),
                            "target": target,
                            "reason": "missing organ mapping",
                        }
                    )
                    continue
                observed_edges.append((module_name, importer_organ, imported_organ))
                allowed = import_truth_matrix.get(importer_organ, set())
                if imported_organ not in allowed:
                    violations.append(
                        {
                            "module": module_name,
                            "path_ref": path.relative_to(root).as_posix(),
                            "target": target,
                            "importer_organ": importer_organ,
                            "imported_organ": imported_organ,
                            "reason": "import truth matrix violation",
                        }
                    )

    critical_organs = {
        "Temporal Engine",
        "Paradox Engine",
        "Multiverse Engine",
        "Receipts / Ledger",
        "Crucible Engine",
        "Council Router Engine",
    }
    critical_edges = [
        {"module": module, "importer_organ": importer_organ, "imported_organ": imported_organ}
        for module, importer_organ, imported_organ in observed_edges
        if importer_organ in critical_organs or imported_organ in critical_organs
    ]

    checks = [
        {
            "check_id": "no_runtime_import_truth_matrix_violations",
            "pass": not violations,
        },
        {
            "check_id": "critical_organs_have_observed_dependency_edges",
            "pass": bool(critical_edges),
        },
        {
            "check_id": "critical_runtime_organs_remain_within_declared_dependency_matrix",
            "pass": not violations,
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.dependency_truth_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 2 proves runtime import/dependency truth against the declared registry matrix only.",
        "critical_dependency_edges": critical_edges,
        "violations": violations,
        "checks": checks,
    }


def build_b02_multi_organ_path_hardening_receipt(
    *,
    head: str,
    b02_t1_outputs: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    c017_receipt = b02_t1_outputs["c017_spine_carriage_receipt"]
    useful_output = b02_t1_outputs["useful_output_benchmark"]
    provider_path = b02_t1_outputs["provider_path_integrity_receipt"]
    path_agreement = b02_t1_outputs["b02_runtime_path_agreement_receipt"]

    c017_probe_ids = [
        str(row.get("probe_id", "")).strip()
        for row in c017_receipt.get("carriage_matrix", [])
        if isinstance(row, dict) and str(row.get("status", "")).strip().upper() == "PASS"
    ]
    expected_probe_ids = {
        "paradox_trigger",
        "temporal_fork",
        "temporal_replay",
        "multiverse_evaluation",
        "cognition_request",
        "cognition_plan",
        "council_request",
        "council_plan",
    }
    useful_output_checks = {
        str(row.get("benchmark_id", "")).strip(): bool(row.get("pass"))
        for row in useful_output.get("rows", [])
        if isinstance(row, dict) and str(row.get("benchmark_id", "")).strip()
    }

    checks = [
        {
            "check_id": "c017_multi_organ_probe_set_passes",
            "pass": expected_probe_ids.issubset(set(c017_probe_ids)),
        },
        {
            "check_id": "c017_oversize_guard_still_fail_closed",
            "pass": (
                str(c017_receipt.get("oversize_guard", {}).get("status", "")).strip().upper() == "PASS"
                and bool(c017_receipt.get("oversize_guard", {}).get("message_match"))
            ),
        },
        {
            "check_id": "useful_output_hardening_rows_pass",
            "pass": all(
                useful_output_checks.get(benchmark_id, False)
                for benchmark_id in (
                    "canonical_council_plan_probe",
                    "canonical_cognition_plan_probe",
                    "canonical_cognition_execute_probe",
                    "same_host_live_hashed_success_witness_present",
                    "same_host_live_hashed_resilience_witness_present",
                    "useful_output_evidence_stronger_than_ceremonial_path_evidence",
                )
            ),
        },
        {
            "check_id": "same_host_provider_path_stays_narrow_and_passes",
            "pass": (
                _is_pass(provider_path)
                and sorted(str(item).strip() for item in provider_path.get("same_host_live_hashed_provider_ids", []) if str(item).strip())
                == ["openai", "openrouter"]
            ),
        },
        {
            "check_id": "t1_path_agreement_remains_pass",
            "pass": _is_pass(path_agreement),
        },
    ]
    status = "PASS" if all(bool(row["pass"]) for row in checks) else "FAIL"
    return {
        "schema_id": "kt.b02.multi_organ_path_hardening_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "scope_boundary": "B02 tranche 2 hardens runtime-path agreement beyond the narrow happy-path slice by requiring the bounded multi-organ c017 probe set and useful-output witness set to agree on current head.",
        "observed_c017_probe_ids": c017_probe_ids,
        "checks": checks,
        "forbidden_claims_remaining": [
            "Do not claim generalized multi-organ superiority.",
            "Do not claim router, lobe, or civilization ratification.",
        ],
    }


def build_b02_runtime_unify_t2_outputs(
    *,
    root: Path,
    export_root: Path,
    c017_telemetry_path: Path,
    w1_telemetry_path: Path,
) -> Dict[str, Dict[str, Any]]:
    head = _git_head(root)
    export_root.mkdir(parents=True, exist_ok=True)
    runtime_registry = _load_runtime_registry(root)
    b02_t1_outputs = build_b02_runtime_unify_outputs(
        root=root,
        export_root=(export_root / "t1_refresh").resolve(),
        c017_telemetry_path=c017_telemetry_path,
        w1_telemetry_path=w1_telemetry_path,
    )
    exclusivity = build_b02_spine_exclusivity_receipt(root=root, head=head, runtime_registry=runtime_registry)
    dependency_truth = build_b02_dependency_truth_receipt(root=root, head=head, runtime_registry=runtime_registry)
    path_hardening = build_b02_multi_organ_path_hardening_receipt(head=head, b02_t1_outputs=b02_t1_outputs)

    t2_receipt = build_b02_runtime_unify_t2_receipt(
        head=head,
        b02_t1_receipt=b02_t1_outputs["b02_runtime_unify_receipt"],
        exclusivity=exclusivity,
        dependency_truth=dependency_truth,
        path_hardening=path_hardening,
    )

    return {
        **b02_t1_outputs,
        "b02_spine_exclusivity_receipt": exclusivity,
        "b02_dependency_truth_receipt": dependency_truth,
        "b02_multi_organ_path_hardening_receipt": path_hardening,
        "b02_runtime_unify_t2_receipt": t2_receipt,
    }


def build_b02_runtime_unify_t2_receipt(
    *,
    head: str,
    b02_t1_receipt: Mapping[str, Any],
    exclusivity: Mapping[str, Any],
    dependency_truth: Mapping[str, Any],
    path_hardening: Mapping[str, Any],
) -> Dict[str, Any]:
    status = "PASS" if all(_is_pass(payload) for payload in (b02_t1_receipt, exclusivity, dependency_truth, path_hardening)) else "FAIL"
    return {
        "schema_id": "kt.b02.runtime_unify_t2_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "current_git_head": head,
        "status": status,
        "tranche_id": "B02_GATE_B_RUNTIME_UNIFY_T2",
        "scope_boundary": "Second counted B02 tranche only. This tranche strengthens spine exclusivity, import/dependency truth, and broader bounded path agreement without opening Gate C.",
        "entry_gate_status": bool(b02_t1_receipt.get("entry_gate_status")),
        "exit_gate_status": False,
        "earned_current_head_claims": [
            "No alternative claim-bearing runtime ingress remains across declared runtime roots beyond the canonical entrypoint/spine lane.",
            "Runtime import/dependency behavior matches the declared runtime registry truth matrix on current head.",
            "Bounded multi-organ carriage and useful-output agreement now extends beyond the tranche-1 happy path while remaining under the same bounded ceilings.",
        ],
        "component_refs": [
            B02_T1_RECEIPT_REL,
            B02_T2_SPINE_EXCLUSIVITY_REL,
            B02_T2_DEPENDENCY_TRUTH_REL,
            B02_T2_PATH_HARDENING_REL,
        ],
        "forbidden_claims_remaining": [
            "Do not claim B02 is complete.",
            "Do not claim Gate C is open.",
            "Do not widen civilization, externality, product, or prestige language.",
        ],
        "next_lawful_move": "CONTINUE_B02_RUNTIME_UNIFICATION_BEFORE_GATE_C",
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute B02 runtime-unification tranche 2 on current head.")
    parser.add_argument("--c017-telemetry-output", default=f"{REPORT_ROOT_REL}/kt_c017_spine_carriage_telemetry.jsonl")
    parser.add_argument("--w1-telemetry-output", default=f"{REPORT_ROOT_REL}/w1_runtime_realization_telemetry.jsonl")
    parser.add_argument("--spine-exclusivity-output", default=B02_T2_SPINE_EXCLUSIVITY_REL)
    parser.add_argument("--dependency-truth-output", default=B02_T2_DEPENDENCY_TRUTH_REL)
    parser.add_argument("--path-hardening-output", default=B02_T2_PATH_HARDENING_REL)
    parser.add_argument("--receipt-output", default=B02_T2_RECEIPT_REL)
    parser.add_argument("--export-root", default=EXPORT_ROOT_REL)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    outputs = build_b02_runtime_unify_t2_outputs(
        root=root,
        export_root=_resolve(root, str(args.export_root)),
        c017_telemetry_path=_resolve(root, str(args.c017_telemetry_output)),
        w1_telemetry_path=_resolve(root, str(args.w1_telemetry_output)),
    )

    write_json_stable(_resolve(root, str(args.spine_exclusivity_output)), outputs["b02_spine_exclusivity_receipt"])
    write_json_stable(_resolve(root, str(args.dependency_truth_output)), outputs["b02_dependency_truth_receipt"])
    write_json_stable(_resolve(root, str(args.path_hardening_output)), outputs["b02_multi_organ_path_hardening_receipt"])
    write_json_stable(_resolve(root, str(args.receipt_output)), outputs["b02_runtime_unify_t2_receipt"])

    summary = {
        "status": outputs["b02_runtime_unify_t2_receipt"]["status"],
        "entry_gate_status": outputs["b02_runtime_unify_t2_receipt"]["entry_gate_status"],
        "exit_gate_status": outputs["b02_runtime_unify_t2_receipt"]["exit_gate_status"],
        "next_lawful_move": outputs["b02_runtime_unify_t2_receipt"]["next_lawful_move"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if outputs["b02_runtime_unify_t2_receipt"]["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
