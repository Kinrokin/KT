from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.operator.post_wave5_c006_trust_prep_validate import build_post_wave5_c006_trust_prep_receipt  # noqa: E402
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_post_wave5_c006_trust_prep_receipt_preserves_e1_ceiling() -> None:
    receipt = build_post_wave5_c006_trust_prep_receipt(root=repo_root())

    assert receipt["status"] == "PASS"
    assert receipt["c006_status"] == "OPEN_PREPARED_NOT_PROMOTED"
    assert receipt["current_externality_ceiling"] == "E1_SAME_HOST_DETACHED_REPLAY"
    assert "E2_CROSS_HOST_FRIENDLY_REPLAY" in receipt["not_yet_earned"]
    assert any(row["check"] == "same_host_live_provider_success_does_not_raise_externality" and row["status"] == "PASS" for row in receipt["checks"])


def test_post_wave5_c006_trust_prep_cli_writes_receipt(tmp_path: Path) -> None:
    root = repo_root()
    output_path = tmp_path / "c006_prep.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")

    proc = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.post_wave5_c006_trust_prep_validate",
            "--output",
            str(output_path),
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
    assert output_path.exists()
