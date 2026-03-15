from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.determinism_preflight import build_hash_critical_bundle, build_runner_manifest


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


def _seed_minimal_ws4_repo(root: Path) -> None:
    _write_json(
        root / "KT_PROD_CLEANROOM/governance/closure_foundation/kt_determinism_contract.json",
        {
            "required_controls": [
                "canonical_runner_image_hash",
                "os_profile_matrix",
                "python_and_tool_versions_pinned",
                "canonical_json_serialization",
                "canonical_file_ordering",
                "normalized_path_separators",
                "explicit_newline_policy",
                "SOURCE_DATE_EPOCH_or_equivalent_timestamp_control",
                "deterministic_archive_creation",
                "network_policy_for_build_and_bundle",
            ],
            "minimum_environments": ["linux", "windows", "third_controlled_environment"],
            "serialization_rules": {
                "json": "canonical_json_serialization",
                "canonical_file_ordering": "byte-stable sorted relative paths",
                "explicit_newline_policy": "LF_ONLY",
            },
            "timestamp_policy": {"control": "SOURCE_DATE_EPOCH_or_equivalent_timestamp_control"},
            "network_policy_for_build_and_bundle": {"default_mode": "OFFLINE_REQUIRED"},
            "runner_constraints": {"same_environment_rerun_required": True},
            "path_policy": {"normalized_path_separators": True},
        },
    )
    _write_json(
        root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/docs/RUNTIME_REGISTRY.json",
        {
            "canonical_entry": {"module": "kt.entrypoint", "callable": "invoke"},
            "canonical_spine": {"module": "core.spine", "callable": "run"},
        },
    )
    _write_json(root / "KT_PROD_CLEANROOM/governance/runtime_boundary_contract.json", {"ok": True})
    _write_json(root / "KT_PROD_CLEANROOM/reports/kt_archive_externalization_receipt.json", {"status": "PASS"})
    _write_text(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/kt/entrypoint.py", "def invoke(context):\n    return context\n")
    _write_text(root / "KT_PROD_CLEANROOM/04_PROD_TEMPLE_V2/src/core/spine.py", "def run(context):\n    return context\n")
    _write_text(root / "KT_PROD_CLEANROOM/tools/operator/kt_cli.py", "print('ok')\n")
    _write_text(root / "run_kt_e2e.sh", "#!/usr/bin/env bash\nexit 0\n")
    _write_text(root / "REPO_CANON.md", "# canon\n")


def test_build_runner_manifest_pins_canonical_runner_hash(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_ws4_repo(root)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    manifest = build_runner_manifest(root)

    assert manifest["runner_id"] == "kt_cli_safe_run_v1"
    assert manifest["canonical_runner_command"][:3] == ["python", "-m", "tools.operator.kt_cli"]
    assert manifest["canonical_runtime_entry"]["module"] == "kt.entrypoint"
    assert manifest["canonical_runtime_spine"]["module"] == "core.spine"
    assert str(manifest["runner_identity"]["image_hash"]).startswith("sha256:")


def test_hash_critical_bundle_is_same_environment_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _init_repo(root)
    _seed_minimal_ws4_repo(root)
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=root, check=True, capture_output=True)

    manifest = build_runner_manifest(root)
    first = build_hash_critical_bundle(manifest)
    second = build_hash_critical_bundle(manifest)

    assert first["bundle_sha256"] == second["bundle_sha256"]
    assert first["payload"]["timestamp_control"]["env_var"] == "SOURCE_DATE_EPOCH"
