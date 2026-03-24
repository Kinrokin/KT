from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.operator.titanium_common import repo_root, utc_now_iso_z, write_json_stable


DEFAULT_OUTPUT_REL = "KT_PROD_CLEANROOM/reports/kt_wave0_5_package_import_canon_receipt.json"
CONTEXT_IDS: Tuple[str, ...] = ("repo_root", "cleanroom_root", "editable_install")
COMPARE_KEYS: Tuple[str, ...] = (
    "canonical_entry",
    "canonical_spine",
    "entrypoint_module_file",
    "runtime_registry_path",
    "spine_module_file",
    "state_vault_path",
)
QUERY = """
import importlib
import json
from pathlib import Path

from core.runtime_registry import load_runtime_registry, runtime_registry_path

entry = importlib.import_module("kt.entrypoint")
spine = importlib.import_module("core.spine")
registry = load_runtime_registry()
payload = {
    "canonical_entry": {"module": registry.canonical_entry.module, "callable": registry.canonical_entry.callable},
    "canonical_spine": {"module": registry.canonical_spine.module, "callable": registry.canonical_spine.callable},
    "entrypoint_module_file": Path(entry.__file__).resolve().as_posix(),
    "runtime_registry_path": runtime_registry_path().resolve().as_posix(),
    "spine_module_file": Path(spine.__file__).resolve().as_posix(),
    "state_vault_path": registry.resolve_state_vault_jsonl_path().resolve().as_posix(),
}
print(json.dumps(payload, sort_keys=True, ensure_ascii=True))
""".strip()


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _context_settings(*, root: Path, context_id: str) -> Tuple[Path, str]:
    cleanroom_root = (root / "KT_PROD_CLEANROOM").resolve()
    runtime_src = (cleanroom_root / "04_PROD_TEMPLE_V2" / "src").resolve()
    if context_id == "repo_root":
        return root.resolve(), os.pathsep.join((str(runtime_src), str(cleanroom_root)))
    if context_id == "cleanroom_root":
        return cleanroom_root, os.pathsep.join((str(runtime_src), str(cleanroom_root)))
    raise RuntimeError(f"FAIL_CLOSED: unknown package/import canon context: {context_id}")


def _venv_python(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


@contextlib.contextmanager
def _editable_install_context(*, root: Path) -> Any:  # noqa: ANN401
    cleanroom_root = (root / "KT_PROD_CLEANROOM").resolve()
    with tempfile.TemporaryDirectory(prefix="kt_pkg_canon_") as temp_dir:
        temp_root = Path(temp_dir).resolve()
        venv_root = temp_root / "venv"
        probe_cwd = temp_root / "probe"
        probe_cwd.mkdir(parents=True, exist_ok=True)

        # Use host site packages only for build tooling so editable-install proof
        # stays offline and does not depend on network fetches for wheel/setuptools.
        venv.EnvBuilder(with_pip=True, clear=True, system_site_packages=True).create(venv_root)
        python_exe = _venv_python(venv_root)

        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")

        proc = subprocess.run(
            [
                str(python_exe),
                "-m",
                "pip",
                "install",
                "--quiet",
                "--no-deps",
                "--no-build-isolation",
                "-e",
                str(cleanroom_root),
            ],
            cwd=str(root),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"FAIL_CLOSED: editable install context failed: {(proc.stdout or '').strip()}")
        yield {
            "python_executable": python_exe,
            "cwd": probe_cwd,
            "pythonpath": "",
        }


def _capture_context(*, root: Path, context_id: str, editable_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if context_id == "editable_install":
        if editable_context is None:
            raise RuntimeError("FAIL_CLOSED: editable install context missing")
        cwd = Path(str(editable_context["cwd"])).resolve()
        pythonpath = str(editable_context.get("pythonpath", ""))
        python_executable = str(editable_context["python_executable"])
    else:
        cwd, pythonpath = _context_settings(root=root, context_id=context_id)
        python_executable = sys.executable

    env = dict(os.environ)
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    else:
        env.pop("PYTHONPATH", None)
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    proc = subprocess.run(
        [python_executable, "-c", QUERY],
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"FAIL_CLOSED: package/import canon context {context_id} failed: {(proc.stdout or '').strip()}")
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"FAIL_CLOSED: package/import canon context {context_id} emitted no JSON")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"FAIL_CLOSED: package/import canon context {context_id} emitted invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"FAIL_CLOSED: package/import canon context {context_id} emitted non-object payload")
    payload["context_id"] = context_id
    payload["context_cwd"] = cwd.as_posix()
    payload["context_pythonpath"] = pythonpath.replace("\\", "/")
    return payload


def build_package_import_canon_receipt(*, root: Path, editable_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if editable_context is None:
        with _editable_install_context(root=root) as live_editable_context:
            return build_package_import_canon_receipt(root=root, editable_context=dict(live_editable_context))

    observed = {
        context_id: _capture_context(root=root, context_id=context_id, editable_context=editable_context)
        for context_id in CONTEXT_IDS
    }
    repo_payload = observed["repo_root"]
    cleanroom_payload = observed["cleanroom_root"]
    editable_payload = observed["editable_install"]

    mismatches: List[Dict[str, Any]] = []
    for key in COMPARE_KEYS:
        repo_value = repo_payload.get(key)
        cleanroom_value = cleanroom_payload.get(key)
        editable_value = editable_payload.get(key)
        if repo_value != cleanroom_value or repo_value != editable_value:
            mismatches.append(
                {
                    "field": key,
                    "repo_root": repo_value,
                    "cleanroom_root": cleanroom_value,
                    "editable_install": editable_value,
                }
            )

    editable_pythonpath_clean = editable_payload.get("context_pythonpath", "") == ""

    checks = [
        {
            "check": "canonical_contexts_captured",
            "status": "PASS",
            "contexts": list(CONTEXT_IDS),
        },
        {
            "check": "editable_install_uses_no_pythonpath_override",
            "status": "PASS" if editable_pythonpath_clean else "FAIL",
            "observed_pythonpath": editable_payload.get("context_pythonpath", ""),
        },
        {
            "check": "declared_canonical_import_lane_parity",
            "status": "PASS" if (not mismatches and editable_pythonpath_clean) else "FAIL",
            "compared_keys": list(COMPARE_KEYS),
            "mismatches": mismatches,
        },
    ]
    status = "PASS" if (not mismatches and editable_pythonpath_clean) else "FAIL"
    return {
        "schema_id": "kt.operator.package_import_canon_receipt.v1",
        "generated_utc": utc_now_iso_z(),
        "status": status,
        "validated_head_sha": _git_head(root),
        "claim_boundary": "This receipt proves parity for the declared canonical runtime import lane across repo-root, cleanroom-root, and isolated editable-install contexts only. The editable-install proof uses local host build tooling without a PYTHONPATH override, closes the 'folder not package' attack for the canonical runtime lane, and does not prove wheel/sdist distribution, hermetic packaging, or repo-wide import cleanliness.",
        "contexts": observed,
        "checks": checks,
        "closed_or_narrowed_blockers": ["C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED"] if status == "PASS" else [],
        "open_blockers_preserved": [] if status == "PASS" else ["C007_REPO_ROOT_IMPORT_FRAGILITY_VISIBLE_AND_UNFIXED"],
        "stronger_claim_not_made": [
            "wheel_or_sdist_distribution_proven",
            "all_tests_and_tools_use_the_package_canon",
            "runtime_capability_or_externality_upgraded_by_package_canon",
        ],
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Validate package-root and repo-root parity for the declared canonical runtime import lane.")
    ap.add_argument("--output", default=DEFAULT_OUTPUT_REL)
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    root = repo_root()
    output = Path(str(args.output)).expanduser()
    if not output.is_absolute():
        output = (root / output).resolve()
    receipt = build_package_import_canon_receipt(root=root)
    write_json_stable(output, receipt)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0 if receipt["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
