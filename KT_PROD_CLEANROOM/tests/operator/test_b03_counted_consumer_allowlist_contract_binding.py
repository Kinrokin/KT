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
    "KT_PROD_CLEANROOM/tools/operator/final_current_head_adjudication_validate.py",
    "KT_PROD_CLEANROOM/tools/operator/w3_externality_and_comparative_proof_validate.py",
    "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json",
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


def test_counted_consumer_allowlist_contract_binding_passes_on_current_repo() -> None:
    root = _repo_root()
    barrier = benchmark.build_documentary_carrier_guard_single_path_barrier(root=root)
    receipt = w3.build_counted_consumer_allowlist_contract_binding_receipt(root=root)

    assert barrier["status"] == "PASS"
    assert barrier["counted_consumer_allowlist_contract_ref"] == "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json"
    assert barrier["allowed_consumer_refs"] == barrier["detected_counted_consumer_refs"]
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T15_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_ARTIFACT_ONLY"
    assert receipt["counted_consumer_allowlist_contract_ref"] == "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json"
    assert receipt["allowlist_contract"]["sanctioned_counted_consumer_refs"] == barrier["detected_counted_consumer_refs"]


def test_uncontracted_new_counted_consumer_fails_binding(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    rogue = root / "KT_PROD_CLEANROOM/tools/operator/rogue_counted_consumer.py"
    rogue.write_text(
        "\n".join(
            [
                "from tools.operator.benchmark_constitution_validate import evaluate_documentary_carrier_fail_closed_consumer_guard",
                "",
                "def run(root):",
                "    return evaluate_documentary_carrier_fail_closed_consumer_guard(",
                "        root=root,",
                "        consumer_id='rogue_counted_consumer',",
                "    )",
                "",
            ]
        ),
        encoding="utf-8",
    )

    barrier = benchmark.build_documentary_carrier_guard_single_path_barrier(root=root)

    assert barrier["status"] == "FAIL"
    assert "KT_PROD_CLEANROOM/tools/operator/rogue_counted_consumer.py" in barrier["detected_counted_consumer_refs"]
    assert "KT_PROD_CLEANROOM/tools/operator/rogue_counted_consumer.py" not in barrier["allowed_consumer_refs"]
    assert any(
        check["check_id"] == "counted_consumer_allowlist_matches_detected_runtime_owner_set" and not check["pass"]
        for check in barrier["checks"]
    )


def test_w3_cli_emits_t15_receipt_with_explicit_opt_in_only(tmp_path: Path) -> None:
    root = _clean_clone(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "KT_PROD_CLEANROOM") + os.pathsep + str(root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src")
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

    e2_path = tmp_path / "e2.json"
    atlas_path = tmp_path / "atlas.json"
    canonical_delta_path = tmp_path / "canonical_delta.json"
    advancement_delta_path = tmp_path / "advancement_delta.json"
    t15_receipt_path = tmp_path / "counted_consumer_allowlist_contract_binding_receipt.json"

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
            "--emit-counted-consumer-allowlist-contract-binding-receipt",
            "--counted-consumer-allowlist-contract-binding-output",
            str(t15_receipt_path),
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
    assert payload["documentary_carrier_consumer_status"] == "PASS"

    receipt = json.loads(t15_receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"
    assert receipt["receipt_role"] == "COUNTED_T15_COUNTED_CONSUMER_ALLOWLIST_CONTRACT_BINDING_ARTIFACT_ONLY"
    assert receipt["counted_consumer_allowlist_contract_ref"] == "KT_PROD_CLEANROOM/governance/counted_consumer_allowlist_contract.json"
    assert receipt["single_path_barrier"]["status"] == "PASS"
