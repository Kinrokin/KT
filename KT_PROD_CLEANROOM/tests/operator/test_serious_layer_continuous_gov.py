from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tools.operator.serious_layer.common import Pins
from tools.operator.serious_layer.continuous_gov_serious_v1 import run_continuous_gov_serious


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _mk_run_dir(*, runs_root: Path, name: str, pins: dict, bundle_root_hash: str, secret_pass: bool) -> Path:
    run_dir = (runs_root / "KT_OPERATOR" / name).resolve()
    (run_dir / "delivery").mkdir(parents=True, exist_ok=True)
    (run_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "hashes").mkdir(parents=True, exist_ok=True)
    run_dir.joinpath("verdict.txt").write_text("KT_CERTIFY_PASS\n", encoding="utf-8", newline="\n")

    _write_json(
        run_dir / "delivery" / "delivery_manifest.json",
        {"schema_id": "kt.delivery_manifest.unbound.v1", "lane": "certify.canonical_hmac", "pins": pins},
    )
    _write_json(
        run_dir / "evidence" / "run_protocol.json",
        {"schema_id": "kt.run_protocol.unbound.v1", "lane_id": "KT_OPERATOR_CERTIFY", "bundle_root_hash": bundle_root_hash},
    )
    _write_json(
        run_dir / "delivery" / "delivery_lint_report.json",
        {"schema_id": "kt.delivery_lint.unbound.v1", "status": "PASS"},
    )
    _write_json(
        run_dir / "evidence" / "secret_scan_report.json",
        {"schema_id": "kt.secret_scan.unbound.v1", "status": "PASS" if secret_pass else "FAIL"},
    )
    run_dir.joinpath("evidence", "replay.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
    run_dir.joinpath("evidence", "replay.ps1").write_text("exit 0\n", encoding="utf-8", newline="\n")
    run_dir.joinpath("hashes", "dummy.sha256").write_text("0" * 64 + "\n", encoding="utf-8", newline="\n")
    return run_dir


def test_serious_continuous_gov_pass_window() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo_root = Path(td) / "repo"
        runs_root = repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs"
        pins = {
            "sealed_commit": "s",
            "law_bundle_hash": "l",
            "suite_registry_id": "r",
            "determinism_expected_root_hash": "d",
        }

        baseline_dir = _mk_run_dir(runs_root=runs_root, name="BASELINE", pins=pins, bundle_root_hash="a" * 64, secret_pass=True)
        current_dir = _mk_run_dir(runs_root=runs_root, name="CURRENT", pins=pins, bundle_root_hash="a" * 64, secret_pass=True)

        out_dir = repo_root / "OUT"
        res = run_continuous_gov_serious(
            repo_root=repo_root,
            out_dir=out_dir,
            pins=Pins(
                sealed_tag="T",
                sealed_commit="C",
                law_bundle_hash="L",
                suite_registry_id="R",
                determinism_expected_root_hash="D",
                head_git_sha="H",
            ),
            baseline_run=baseline_dir.as_posix(),
            window=current_dir.as_posix(),
            thresholds_json="",
        )
        assert res["status"] == "PASS"
        assert (out_dir / "drift_report.json").exists()
        assert (out_dir / "regression_gate.json").exists()


def test_serious_continuous_gov_blocks_on_gpis_drop() -> None:
    with tempfile.TemporaryDirectory() as td:
        repo_root = Path(td) / "repo"
        runs_root = repo_root / "KT_PROD_CLEANROOM" / "exports" / "_runs"
        pins = {
            "sealed_commit": "s",
            "law_bundle_hash": "l",
            "suite_registry_id": "r",
            "determinism_expected_root_hash": "d",
        }

        baseline_dir = _mk_run_dir(runs_root=runs_root, name="BASELINE", pins=pins, bundle_root_hash="a" * 64, secret_pass=True)
        current_dir = _mk_run_dir(runs_root=runs_root, name="CURRENT", pins=pins, bundle_root_hash="a" * 64, secret_pass=False)

        out_dir = repo_root / "OUT"
        res = run_continuous_gov_serious(
            repo_root=repo_root,
            out_dir=out_dir,
            pins=Pins(
                sealed_tag="T",
                sealed_commit="C",
                law_bundle_hash="L",
                suite_registry_id="R",
                determinism_expected_root_hash="D",
                head_git_sha="H",
            ),
            baseline_run=baseline_dir.as_posix(),
            window=current_dir.as_posix(),
            thresholds_json=json.dumps({"gpis_block_min": 95}),
        )
        assert res["status"] == "HOLD"
        gate = json.loads((out_dir / "regression_gate.json").read_text(encoding="utf-8"))
        assert gate["status"] == "BLOCK"

