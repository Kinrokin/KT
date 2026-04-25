from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tools.operator import benchmark_constitution_validate as benchmark
from tools.operator import w3_externality_and_comparative_proof_validate as w3

OVERLAY_REFS = [
    "KT_PROD_CLEANROOM/tools/operator/benchmark_constitution_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _clean_clone(tmp_path: Path) -> Path:
    root = _repo_root()
    clone_root = tmp_path / "repo"
    subprocess.run(
        ["git", "clone", "--quiet", str(root), str(clone_root)],
        cwd=str(tmp_path),
        check=True,
    )
    for ref in OVERLAY_REFS:
        src = root / ref
        dst = clone_root / ref
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return clone_root


def test_tracked_counted_receipt_single_path_barrier_passes_on_current_repo() -> None:
    root = _repo_root()
    barrier = benchmark.build_tracked_counted_receipt_single_path_barrier(root=root)
    receipt = w3.build_tracked_counted_receipt_single_path_enforcement_receipt(root=root)

    assert barrier["status"] == "PASS"
    assert barrier["allowed_wrapper_refs"] == [
        "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    ]
    assert barrier["unexpected_owner_hits"] == []
    assert barrier["detected_wrapper_owner_refs"] == barrier["allowed_wrapper_refs"]
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T20_TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_ARTIFACT_ONLY"
    assert receipt["tracked_counted_receipt_single_path_barrier"]["status"] == "PASS"


def test_unsanctioned_operator_owner_fails_tracked_counted_receipt_single_path_barrier(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    rogue = root / "KT_PROD_CLEANROOM/tools/operator/rogue_tracked_counted_receipt_owner.py"
    rogue.write_text(
        "\n".join(
            [
                "from tools.operator.benchmark_constitution_validate import evaluate_tracked_counted_receipt_carrier_overread",
                "",
                "def run(payload, current_head):",
                "    return evaluate_tracked_counted_receipt_carrier_overread(",
                "        tracked_receipt_ref='KT_PROD_CLEANROOM/reports/t10_receipt_final_head_authority_alignment_receipt.json',",
                "        tracked_payload=payload,",
                "        allowed_roles=['COUNTED_T11_T10_FINAL_HEAD_AUTHORITY_ALIGNMENT_ARTIFACT_ONLY'],",
                "        current_head=current_head,",
                "    )",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    barrier = benchmark.build_tracked_counted_receipt_single_path_barrier(root=root)

    assert barrier["status"] == "FAIL"
    assert barrier["unexpected_owner_hits"] == [
        {
            "owner_ref": "KT_PROD_CLEANROOM/tools/operator/rogue_tracked_counted_receipt_owner.py",
            "matched_tokens": ["evaluate_tracked_counted_receipt_carrier_overread"],
        }
    ]


def test_w3_cli_emits_t20_receipt_with_explicit_output(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t20_receipt_path = tmp_path / "tracked_counted_receipt_single_path_enforcement_receipt.json"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.operator.w3_externality_and_comparative_proof_validate",
            "--e2-output",
            str(e2_path),
            "--capability-atlas-output",
            str(atlas_path),
            "--canonical-delta-output",
            str(canonical_delta_path),
            "--advancement-delta-output",
            str(advancement_delta_path),
            "--emit-tracked-counted-receipt-single-path-enforcement-receipt",
            "--tracked-counted-receipt-single-path-enforcement-output",
            str(t20_receipt_path),
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
    assert payload["tracked_counted_receipt_single_path_enforcement_status"] == "PASS"

    receipt = json.loads(t20_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T20_TRACKED_COUNTED_RECEIPT_SINGLE_PATH_ENFORCEMENT_ARTIFACT_ONLY"
    assert receipt["tracked_counted_receipt_single_path_barrier"]["status"] == "PASS"
    assert receipt["tracked_counted_receipt_single_path_barrier"]["unexpected_owner_hits"] == []
