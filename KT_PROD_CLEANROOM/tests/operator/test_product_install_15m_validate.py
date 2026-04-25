from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_product_install_15m_cli_compiles_bounded_product_plane(tmp_path: Path) -> None:
    root = _repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    deployment_profiles_path = tmp_path / "deployment_profiles.json"
    product_install_path = tmp_path / "product_install_15m_receipt.json"
    operator_handoff_path = tmp_path / "operator_handoff_receipt.json"
    standards_mapping_path = tmp_path / "standards_mapping_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.product_install_15m_validate",
            "--deployment-profiles-output",
            str(deployment_profiles_path),
            "--product-install-output",
            str(product_install_path),
            "--operator-handoff-output",
            str(operator_handoff_path),
            "--standards-mapping-output",
            str(standards_mapping_path),
        ],
        cwd=str(root),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["status"] == "PASS"
    assert payload["deployment_profile_count"] == 3
    assert payload["local_install_to_pass_fail_minutes"] == 15
    assert payload["standards_mapping_status"] == "PASS"

    deployment_profiles = json.loads(deployment_profiles_path.read_text(encoding="utf-8"))
    product_install = json.loads(product_install_path.read_text(encoding="utf-8"))
    operator_handoff = json.loads(operator_handoff_path.read_text(encoding="utf-8"))
    standards_mapping = json.loads(standards_mapping_path.read_text(encoding="utf-8"))

    assert deployment_profiles["status"] == "ACTIVE"
    assert deployment_profiles["schema_id"] == "kt.deployment_profiles.v2"
    assert deployment_profiles["product_profile_count"] == 3
    assert {row["profile_id"] for row in deployment_profiles["profiles"]} == {
        "local_verifier_mode",
        "team_pilot_mode",
        "regulated_workflow_mode",
    }

    assert product_install["status"] == "PASS"
    assert product_install["local_profile_install_to_pass_fail_minutes"] == 15
    assert "python -m tools.operator.public_verifier" in product_install["installation_entrypoints"]
    assert "python -m tools.operator.public_verifier_detached_validate" in product_install["installation_entrypoints"]

    assert operator_handoff["status"] == "PASS"
    assert "KT_PROD_CLEANROOM/product/one_page_product_truth_surface.md" in operator_handoff["handoff_bundle_refs"]
    assert operator_handoff["independent_operator_target_minutes"] == 15

    assert standards_mapping["status"] == "PASS"
    assert standards_mapping["matrix_count"] == 3
