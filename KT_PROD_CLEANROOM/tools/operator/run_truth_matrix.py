from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable
from tools.operator.truth_authority import resolve_truth_head_context


def _git(*, root: Path, args: Sequence[str]) -> str:
    return subprocess.check_output(["git", *args], cwd=str(root), text=True).strip()


def _env(*, root: Path) -> Dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src") + os.pathsep + str(root / "KT_PROD_CLEANROOM")
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _run(*, root: Path, cmd: Sequence[str], env: Dict[str, str]) -> Tuple[int, str]:
    proc = subprocess.run(list(cmd), cwd=str(root), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return int(proc.returncode), proc.stdout or ""


def _pytest_cmd(*args: str) -> List[str]:
    return ["python", "-m", "pytest", "-p", "pytest_cov", *args]


def _live_provider_env_present() -> bool:
    names = (
        "OPENAI_API_KEY",
        "OPENAI_API_KEYS",
        "OPENROUTER_API_KEY",
        "OPENROUTER_API_KEYS",
    )
    return any(str(os.environ.get(name, "")).strip() for name in names)


def _record(
    *,
    out: List[Dict[str, Any]],
    check_id: str,
    scope: str,
    critical: bool,
    dirty_sensitive: bool,
    command: str,
    rc: int,
    output: str,
    summary: str,
) -> None:
    observed = output.strip().splitlines()[-1] if output.strip() else ""
    if rc == 0:
        observed = summary
    row: Dict[str, Any] = {
        "check_id": check_id,
        "scope": scope,
        "critical": bool(critical),
        "dirty_sensitive": bool(dirty_sensitive),
        "status": "PASS" if rc == 0 else "FAIL",
        "summary": summary,
        "command": command,
        "observed": observed,
    }
    if rc != 0:
        row["output_tail"] = output.strip().splitlines()[-20:]
    out.append(row)


def _clean_clone_operator_smoke(*, root: Path) -> Dict[str, Any]:
    tmp_dir = Path(tempfile.mkdtemp(prefix="kt_truth_matrix_clone_"))
    try:
        clone_dir = tmp_dir / "repo"
        subprocess.check_call(["git", "clone", str(root), str(clone_dir)], cwd=str(tmp_dir))
        env = _env(root=clone_dir)
        coverage_dir = tmp_dir / "coverage"
        coverage_dir.mkdir(parents=True, exist_ok=True)
        env["COVERAGE_FILE"] = str((coverage_dir / "operator_clean_clone_smoke.coverage").resolve())
        head = _git(root=clone_dir, args=["rev-parse", "HEAD"])
        rc, out = _run(
            root=clone_dir,
            cmd=_pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
            ),
            env=env,
        )
        return {"rc": rc, "output": out, "head_sha": head}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def build_live_validation_index(*, root: Path, skip_clean_clone: bool, skip_dirty_sensitive: bool) -> Dict[str, Any]:
    env = _env(root=root)
    checks: List[Dict[str, Any]] = []
    constitution_report = str((Path(tempfile.gettempdir()) / "kt_constitution_guard_report.md").resolve())
    coverage_dir = (root / "KT_PROD_CLEANROOM" / "reports" / ".wave_coverage").resolve()
    coverage_dir.mkdir(parents=True, exist_ok=True)

    commands = [
        (
            "constitutional_guard",
            "canonical_runtime",
            True,
            False,
            ["python", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tools/check_constitution.py", "--report", constitution_report],
            "constitutional guard passes with canonical runtime scope enforced",
        ),
        (
            "runtime_suite",
            "canonical_runtime",
            True,
            False,
            _pytest_cmd("-q", "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests"),
            "runtime suite passed",
        ),
        (
            "critical_governance_regression_suite",
            "core_truth_repair",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_invariants_gate.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_no_network_dry_run.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
                "KT_PROD_CLEANROOM/tools/verification/tests/test_reconcile_and_schemas.py",
            ),
            "critical regression suite passed",
        ),
        (
            "lane_policy_repair_suite",
            "governance_lanes",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic16_admission_gates.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic15_tournament_runner.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic15_merge_evaluator.py",
            ),
            "lane-aware governance gate suite passed",
        ),
        (
            "law_bundle_integrity",
            "law_surface",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_law_bundle_integrity.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_fl3_meta_evaluator.py",
            ),
            "law bundle integrity suite passed",
        ),
        (
            "trust_zone_validator",
            "boundary_purification",
            True,
            False,
            ["python", "-m", "tools.operator.trust_zone_validate"],
            "trust-zone validator passed",
        ),
        (
            "package_import_canon",
            "boundary_purification",
            True,
            False,
            ["python", "-m", "tools.operator.package_import_canon"],
            "package/import canon validator passed",
        ),
        (
            "toolchain_runtime_firewall",
            "boundary_purification",
            True,
            False,
            ["python", "-m", "tools.operator.toolchain_runtime_firewall_validate"],
            "toolchain/runtime firewall validator passed",
        ),
        (
            "interface_freeze_validator",
            "boundary_purification",
            True,
            False,
            ["python", "-m", "tools.operator.interface_freeze_validate"],
            "interface freeze validator passed",
        ),
        (
            "claim_compiler_boundary_suite",
            "claim_surface",
            True,
            False,
            _pytest_cmd("-q", "KT_PROD_CLEANROOM/tests/operator/test_claim_compiler.py"),
            "claim compiler boundary suite passed",
        ),
        (
            "wave1_trust_surface_matrix",
            "trust_stack_generalization",
            True,
            False,
            ["python", "-m", "tools.operator.wave1_trust_surface_matrix"],
            "wave1 trust surface matrix passed",
        ),
        (
            "wave1_observability_validate",
            "trust_stack_generalization",
            True,
            False,
            ["python", "-m", "tools.operator.wave1_observability_validate"],
            "wave1 observability validation passed",
        ),
        (
            "wave1_provider_resilience_validate",
            "trust_stack_generalization",
            True,
            False,
            ["python", "-m", "tools.operator.wave1_provider_resilience_validate"],
            "wave1 provider resilience validation passed",
        ),
        (
            "wave1_ci_repro_strategy",
            "trust_stack_generalization",
            True,
            False,
            ["python", "-m", "tools.operator.wave1_ci_reproducibility_strategy"],
            "wave1 ci/local reproducibility strategy passed",
        ),
        (
            "wave1_targeted_suite",
            "trust_stack_generalization",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_provider_resilience.py",
                "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/tests/test_runtime_observability.py",
                "KT_PROD_CLEANROOM/tests/operator/test_wave1_toolchain_observability.py",
                "KT_PROD_CLEANROOM/tests/operator/test_wave1_trust_and_repro.py",
            ),
            "wave1 targeted suite passed",
        ),
        (
            "wave2b_router_shadow_validate",
            "router_shadow",
            True,
            False,
            ["python", "-m", "tools.operator.wave2b_router_shadow_validate"],
            "wave2b router shadow validation passed",
        ),
        (
            "wave2b_targeted_suite",
            "router_shadow",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/operator/test_wave2b_router_shadow.py",
                "KT_PROD_CLEANROOM/tests/fl3/test_epic19_router_hat_demo.py",
            ),
            "wave2b targeted suite passed",
        ),
        (
            "wave2c_organ_contract_suite",
            "organ_realization",
            True,
            False,
            ["python", "-m", "tools.operator.wave2c_organ_contract_suite"],
            "wave2c organ contract suite passed",
        ),
        (
            "wave2c_organ_realization_validate",
            "organ_realization",
            True,
            False,
            ["python", "-m", "tools.operator.wave2c_organ_realization_validate"],
            "wave2c organ realization validation passed",
        ),
        (
            "wave2c_targeted_suite",
            "organ_realization",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/operator/test_wave2c_organ_realization.py",
            ),
            "wave2c targeted suite passed",
        ),
        (
            "c017_spine_carriage_validate",
            "spine_carriage_remediation",
            True,
            False,
            ["python", "-m", "tools.operator.c017_spine_carriage_validate"],
            "c017 spine carriage remediation validation passed",
        ),
        (
            "c017_targeted_suite",
            "spine_carriage_remediation",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/operator/test_c017_spine_carriage_remediation.py",
            ),
            "c017 targeted suite passed",
        ),
        (
            "wave4_chaos_and_external_challenge_validate",
            "chaos_and_external_challenge",
            True,
            False,
            ["python", "-m", "tools.operator.wave4_chaos_and_external_challenge_validate"],
            "wave4 chaos and external challenge validation passed",
        ),
        (
            "wave4_targeted_suite",
            "chaos_and_external_challenge",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/operator/test_wave4_chaos_and_external_challenge.py",
            ),
            "wave4 targeted suite passed",
        ),
        (
            "wave5_final_readjudication_validate",
            "final_readjudication",
            True,
            False,
            ["python", "-m", "tools.operator.wave5_final_readjudication_and_tier_ruling_validate"],
            "wave5 final readjudication validation passed",
        ),
        (
            "wave5_targeted_suite",
            "final_readjudication",
            True,
            False,
            _pytest_cmd(
                "-q",
                "KT_PROD_CLEANROOM/tests/operator/test_wave5_final_readjudication_and_tier_ruling.py",
            ),
            "wave5 targeted suite passed",
        ),
    ]

    if _live_provider_env_present():
        commands.extend(
            [
                (
                    "wave2a_provider_contract_suite",
                    "adapter_activation",
                    True,
                    False,
                    ["python", "-m", "tools.operator.wave2a_provider_contract_suite"],
                    "wave2a provider contract suite passed",
                ),
                (
                    "wave2a_adapter_activation_validate",
                    "adapter_activation",
                    True,
                    False,
                    ["python", "-m", "tools.operator.wave2a_adapter_activation_validate"],
                    "wave2a adapter activation validation passed",
                ),
            ]
        )
    else:
        checks.append(
            {
                "check_id": "wave2a_provider_contract_suite",
                "scope": "adapter_activation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "SKIP",
                "summary": "wave2a provider contract suite skipped because live provider credentials are absent",
                "command": "python -m tools.operator.wave2a_provider_contract_suite",
            }
        )
        checks.append(
            {
                "check_id": "wave2a_adapter_activation_validate",
                "scope": "adapter_activation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "SKIP",
                "summary": "wave2a adapter activation validation skipped because live provider credentials are absent",
                "command": "python -m tools.operator.wave2a_adapter_activation_validate",
            }
        )

    commands.append(
        (
            "current_worktree_cleanroom_suite",
            "active_repo_validation",
            True,
            True,
            _pytest_cmd("-q", "KT_PROD_CLEANROOM/tests", "-q", "-ra", "--maxfail=100"),
            "current-worktree cleanroom suite passed",
        )
    )

    for check_id, scope, critical, dirty_sensitive, cmd, success_summary in commands:
        if skip_dirty_sensitive and dirty_sensitive:
            checks.append(
                {
                    "check_id": check_id,
                    "scope": scope,
                    "critical": critical,
                    "dirty_sensitive": dirty_sensitive,
                    "status": "SKIP",
                    "summary": "dirty-sensitive check skipped by request",
                    "command": " ".join(cmd),
                }
            )
            continue
        check_env = dict(env)
        if list(cmd[:4]) == ["python", "-m", "pytest", "-p"]:
            check_env["COVERAGE_FILE"] = str((coverage_dir / f"{check_id}.coverage").resolve())
        rc, out = _run(root=root, cmd=cmd, env=check_env)
        _record(
            out=checks,
            check_id=check_id,
            scope=scope,
            critical=critical,
            dirty_sensitive=dirty_sensitive,
            command=" ".join(cmd),
            rc=rc,
            output=out,
            summary=success_summary if rc == 0 else success_summary.replace("passed", "failed"),
        )

    if skip_clean_clone:
        checks.append(
            {
                "check_id": "operator_clean_clone_smoke",
                "scope": "clean_clone_validation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "SKIP",
                "summary": "operator clean-clone smoke skipped by request",
                "command": "git clone <repo> <tmp> && python -m pytest -q KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
            }
        )
    else:
        clean_clone = _clean_clone_operator_smoke(root=root)
        checks.append(
            {
                "check_id": "operator_clean_clone_smoke",
                "scope": "clean_clone_validation",
                "critical": True,
                "dirty_sensitive": False,
                "status": "PASS" if int(clean_clone["rc"]) == 0 else "FAIL",
                "summary": "operator clean-clone smoke passed" if int(clean_clone["rc"]) == 0 else "operator clean-clone smoke failed",
                "command": "git clone <repo> <tmp> && python -m pytest -q KT_PROD_CLEANROOM/tests/fl3/test_hat_demo_guardrails.py KT_PROD_CLEANROOM/tests/fl3/test_operator_cli.py",
                "observed": str(clean_clone["output"]).strip().splitlines()[-1] if str(clean_clone["output"]).strip() else "",
                "context": {"clean_clone_head_sha": str(clean_clone["head_sha"]).strip()},
            }
        )

    dirty_lines = subprocess.check_output(["git", "status", "--short"], cwd=str(root), text=True).splitlines()
    head_sha = _git(root=root, args=["rev-parse", "HEAD"])
    truth_head_context = resolve_truth_head_context(root=root, live_head=head_sha, dirty_lines=dirty_lines)
    return {
        "schema_id": "kt.operator.live_validation_index.v1",
        "generated_utc": utc_now_iso_z(),
        "branch_ref": _git(root=root, args=["rev-parse", "--abbrev-ref", "HEAD"]),
        "worktree": {
            "git_dirty": bool(dirty_lines),
            "head_sha": head_sha,
            "validated_subject_head_sha": str(truth_head_context.get("validated_subject_head_sha", "")).strip() or head_sha,
            "publication_carrier_head_sha": str(truth_head_context.get("publication_carrier_head_sha", "")).strip(),
            "head_relation": str(truth_head_context.get("head_relation", "")).strip() or "HEAD_IS_SUBJECT",
            "subject_git_dirty": bool(truth_head_context.get("subject_git_dirty")),
            "publication_carrier_dirty": bool(truth_head_context.get("publication_carrier_only_dirty")),
            "dirty_files": [line.strip() for line in dirty_lines if line.strip()],
            "subject_dirty_files": list(truth_head_context.get("subject_dirty_files", [])),
            "publication_carrier_dirty_files": list(truth_head_context.get("publication_carrier_dirty_files", [])),
            "publication_carrier_delta_files": list(truth_head_context.get("publication_carrier_delta_files", [])),
        },
        "checks": checks,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run the canonical truth matrix and write a live validation index.")
    ap.add_argument("--out", default="KT_PROD_CLEANROOM/reports/live_validation_index.json")
    ap.add_argument("--skip-clean-clone", action="store_true")
    ap.add_argument("--skip-dirty-sensitive", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    out_path = Path(str(args.out)).expanduser()
    if not out_path.is_absolute():
        out_path = (root / out_path).resolve()
    index = build_live_validation_index(
        root=root,
        skip_clean_clone=bool(args.skip_clean_clone),
        skip_dirty_sensitive=bool(args.skip_dirty_sensitive),
    )
    write_json_stable(out_path, index)
    critical_fails = [
        row
        for row in index.get("checks", [])
        if isinstance(row, dict) and bool(row.get("critical")) and str(row.get("status", "")).strip().upper() == "FAIL"
    ]
    print(json.dumps({"critical_failures": len(critical_fails), "head_sha": index["worktree"]["head_sha"]}, sort_keys=True, ensure_ascii=True))
    return 0 if not critical_fails else 2


if __name__ == "__main__":
    raise SystemExit(main())
