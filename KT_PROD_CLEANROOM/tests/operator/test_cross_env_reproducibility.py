from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.cross_env_reproducibility import build_probe_matrix, compute_probe_payload


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "kt@example.test"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "KT Test"], cwd=root, check=True, capture_output=True)


def _seed_minimal_ws5_repo(root: Path) -> None:
    _write_json(root / "KT_PROD_CLEANROOM/reports/kt_determinism_preflight_receipt.json", {"status": "PASS"})
    _write_json(root / "KT_PROD_CLEANROOM/reports/kt_canonical_runner_manifest.json", {"status": "PASS"})
    _write_text(root / "KT_PROD_CLEANROOM/governance/closure_foundation/kt_determinism_contract.json", "{}\n")
    _write_text(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json", "{}\n")
    _write_text(root / "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json", "{}\n")
    _write_text(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py", "def invoke(x):\n    return x\n")
    _write_text(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py", "def run(x):\n    return x\n")
    _write_text(root / "KT_PROD_CLEANROOM/tools/operator/kt_cli.py", "print('ok')\n")
    _write_text(root / "KT_PROD_CLEANROOM/exports/_truth/current/current_bundle_manifest.json", "{}\n")
    _write_text(root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/authority_bundle.json", "{}\n")
    _write_text(root / "KT_PROD_CLEANROOM/reports/cryptographic_publication/in_toto_statement.json", "{}\n")


def test_compute_probe_payload_is_deterministic_for_same_repo(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_ws5_repo(root)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    first = compute_probe_payload(
        root,
        environment_id="windows_current",
        environment_class="windows",
        platform_name="Windows",
        python_version="3.10.11",
        interpreter="python.exe",
        probe_kind="python",
    )
    second = compute_probe_payload(
        root,
        environment_id="windows_current",
        environment_class="windows",
        platform_name="Windows",
        python_version="3.10.11",
        interpreter="python.exe",
        probe_kind="python",
    )

    assert first["critical_hashes"] == second["critical_hashes"]


def test_build_probe_matrix_allows_environment_variation_but_not_hash_mismatch() -> None:
    shared_hashes = {
        "runner_bundle_sha256": "a" * 64,
        "truth_current_bundle_manifest_sha256": "b" * 64,
        "publication_authority_bundle_sha256": "c" * 64,
        "publication_in_toto_statement_sha256": "d" * 64,
    }
    probes = [
        {
            "environment_id": "windows_current",
            "environment_class": "windows",
            "probe_kind": "python",
            "platform": "Windows",
            "python_version": "3.10.11",
            "interpreter": "python.exe",
            "critical_hashes": dict(shared_hashes),
        },
        {
            "environment_id": "windows_py311",
            "environment_class": "third_controlled_environment",
            "probe_kind": "python",
            "platform": "Windows",
            "python_version": "3.11.0",
            "interpreter": "python.exe",
            "critical_hashes": dict(shared_hashes),
        },
        {
            "environment_id": "linux_wsl",
            "environment_class": "linux",
            "probe_kind": "shell",
            "platform": "Linux",
            "python_version": "absent",
            "interpreter": "sh",
            "critical_hashes": dict(shared_hashes),
        },
    ]
    summary = build_probe_matrix(probes)
    assert not summary["missing_required_environment_classes"]
    assert not summary["mismatched_bundle_ids"]

    probes[2]["critical_hashes"]["publication_authority_bundle_sha256"] = "e" * 64
    summary = build_probe_matrix(probes)
    assert "publication_authority_bundle_sha256" in summary["mismatched_bundle_ids"]
