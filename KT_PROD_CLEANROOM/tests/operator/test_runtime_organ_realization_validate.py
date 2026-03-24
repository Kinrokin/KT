from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tools.operator.runtime_organ_realization_validate import build_runtime_organ_realization_outputs  # noqa: E402
from tools.operator.titanium_common import repo_root  # noqa: E402


def test_runtime_organ_realization_outputs_capture_new_bounded_behavior() -> None:
    root = repo_root()
    outputs = build_runtime_organ_realization_outputs(root=root)

    runtime_receipt = outputs["runtime_receipt"]
    grades = outputs["practical_grade_receipt"]
    cognition = outputs["cognition_pack"]
    temporal = outputs["temporal_pack"]
    multiverse = outputs["multiverse_pack"]
    paradox = outputs["paradox_pack"]

    assert runtime_receipt["status"] == "PASS"
    assert grades["status"] == "PASS"
    assert "placeholder-organ" in runtime_receipt["attack_weakened"]

    cognition_check_ids = {row["check_id"] for row in cognition["checks"]}
    assert cognition_check_ids == {
        "cognition_plan_varies_with_artifact_semantics",
        "cognition_execute_not_legacy_hash_prefix_scoring",
    }
    assert all(row["pass"] for row in cognition["checks"])
    assert "semantic" in cognition["bounded_summary"].lower()

    temporal_check = temporal["checks"][0]
    assert temporal_check["check_id"] == "temporal_positive_budget_yields_nonzero_steps"
    assert temporal_check["pass"] is True
    assert temporal_check["steps_executed"] > 0

    multiverse_check = multiverse["checks"][0]
    assert multiverse_check["check_id"] == "multiverse_coherence_is_task_dependent"
    assert multiverse_check["pass"] is True
    assert multiverse_check["close_coherence"] > multiverse_check["wide_coherence"]

    paradox_check = paradox["checks"][0]
    assert paradox_check["check_id"] == "paradox_task_type_changes_with_context_and_condition"
    assert paradox_check["pass"] is True
    assert paradox_check["observed_task_types"] == [
        "POLICY_EVIDENCE_CONFLICT_V1",
        "REQUEST_OUTPUT_CONFLICT_V1",
        "SELF_REFERENCE_GUARD_V1",
        "LOOP_BUDGET_GUARD_V1",
    ]


def test_runtime_organ_realization_cli_writes_outputs(tmp_path: Path) -> None:
    root = repo_root()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    cognition_path = tmp_path / "cognition.json"
    paradox_path = tmp_path / "paradox.json"
    temporal_path = tmp_path / "temporal.json"
    multiverse_path = tmp_path / "multiverse.json"
    runtime_path = tmp_path / "runtime.json"
    grade_path = tmp_path / "grade.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.runtime_organ_realization_validate",
            "--cognition-output",
            str(cognition_path),
            "--paradox-output",
            str(paradox_path),
            "--temporal-output",
            str(temporal_path),
            "--multiverse-output",
            str(multiverse_path),
            "--runtime-output",
            str(runtime_path),
            "--grade-output",
            str(grade_path),
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
    for path in (
        cognition_path,
        paradox_path,
        temporal_path,
        multiverse_path,
        runtime_path,
        grade_path,
    ):
        assert path.exists()
