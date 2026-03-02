from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "04_PROD_TEMPLE_V2" / "src"
sys.path.insert(0, str(SRC_ROOT))
sys.path.insert(0, str(ROOT))

from schemas.fl3_delivery_pack_manifest_schema import FL3_DELIVERY_PACK_MANIFEST_SCHEMA_VERSION_HASH
from schemas.fl3_schema_common import sha256_hex_of_obj
from schemas.fl3_secret_scan_summary_schema import FL3_SECRET_SCAN_SUMMARY_SCHEMA_VERSION_HASH
from tools.training.fl3_factory.manifests import sha256_file
from tools.verification.seal_mode_test_roots import write_root


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [
            str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"),
            str(repo_root / "KT_PROD_CLEANROOM"),
        ]
    )
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    env["KT_SEAL_MODE"] = "1"
    return env


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _make_minimal_delivery_pack(*, pack_root: Path, run_id: str) -> None:
    pack_root.mkdir(parents=True, exist_ok=True)

    # Secret scan summary (schema-bound; summary_id must match canonical hash surface).
    secret_summary: dict = {
        "schema_id": "kt.secret_scan_summary.v1",
        "schema_version_hash": FL3_SECRET_SCAN_SUMMARY_SCHEMA_VERSION_HASH,
        "summary_id": "",
        "report_hash": "0" * 64,
        "status": "PASS",
        "total_findings": 0,
        "high_confidence_findings": 0,
        "run_id": run_id,
        "lane_id": "DELIVERY_PACK",
        "created_at": "2026-03-02T00:00:00Z",
    }
    secret_summary["summary_id"] = sha256_hex_of_obj(secret_summary, drop_keys={"created_at", "summary_id"})
    _write_json(pack_root / "secret_scan_summary.json", secret_summary)

    # Delivery pack manifest (schema-bound; delivery_pack_id must match canonical hash surface).
    files = [
        {
            "path": "secret_scan_summary.json",
            "sha256": sha256_file(pack_root / "secret_scan_summary.json"),
            "bytes": int((pack_root / "secret_scan_summary.json").stat().st_size),
            "redacted": False,
        }
    ]
    manifest: dict = {
        "schema_id": "kt.delivery_pack_manifest.v1",
        "schema_version_hash": FL3_DELIVERY_PACK_MANIFEST_SCHEMA_VERSION_HASH,
        "delivery_pack_id": "",
        "run_id": run_id,
        "bundle_root_hash": "0" * 64,
        "run_protocol_json_hash": "1" * 64,
        "redaction_rules_version": "v1",
        "files": files,
        "created_at": "2026-03-02T00:00:00Z",
        "notes": None,
    }
    manifest["delivery_pack_id"] = sha256_hex_of_obj(manifest, drop_keys={"created_at", "delivery_pack_id"})
    _write_json(pack_root / "delivery_pack_manifest.json", manifest)


def _make_delivery_lane(*, run_dir: Path, lane_label: str) -> None:
    (run_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (run_dir / "delivery").mkdir(parents=True, exist_ok=True)
    (run_dir / "hashes").mkdir(parents=True, exist_ok=True)

    _write_json(run_dir / "evidence" / "secret_scan_report.json", {"status": "PASS"})
    (run_dir / "evidence" / "replay.sh").write_text("#!/usr/bin/env bash\necho OK\n", encoding="utf-8")
    (run_dir / "evidence" / "replay.ps1").write_text("Write-Host OK\n", encoding="utf-8")
    _write_json(run_dir / "delivery" / "delivery_lint_report.json", {"status": "PASS"})

    pack_root = (run_dir / "delivery" / f"KT_DELIVERY_{lane_label}").resolve()
    _make_minimal_delivery_pack(pack_root=pack_root, run_id=f"RUN_{lane_label}")

    _write_json(
        run_dir / "delivery" / "delivery_manifest.json",
        {
            "schema_id": "kt.operator.delivery_manifest.unbound.v1",
            "delivery_dir": pack_root.as_posix(),
            "delivery_zip": {"path": (run_dir / "delivery" / "dummy.zip").as_posix(), "sha256": "2" * 64},
        },
    )
    (run_dir / "hashes" / "dummy.zip.sha256").write_text("2" * 64 + "\n", encoding="utf-8")


def test_authority_grade_passes_with_explicit_runs(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "authority_grade" / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)

    status_run = root / "status"
    readiness_run = root / "readiness"
    canonical_run = root / "canonical"
    books_run = root / "books"
    delta1_run = root / "delta1"
    delta2_run = root / "delta2"
    forge_run = root / "forge"

    for r in (status_run, readiness_run, canonical_run, books_run, delta1_run, delta2_run, forge_run):
        r.mkdir(parents=True, exist_ok=False)

    (status_run / "verdict.txt").write_text("KT_STATUS_PASS ok\n", encoding="utf-8")
    (readiness_run / "verdict.txt").write_text("KT_READINESS_PASS grade=A score=100 ok\n", encoding="utf-8")
    (canonical_run / "verdict.txt").write_text("KT_CERTIFY_PASS cmd=certify lane=canonical_hmac ok\n", encoding="utf-8")
    (books_run / "verdict.txt").write_text("KT_BOOKS_SUITE_PASS ok\n", encoding="utf-8")
    (delta1_run / "verdict.txt").write_text("KT_DELTA_PROOF_PASS ok\n", encoding="utf-8")
    (delta2_run / "verdict.txt").write_text("KT_DELTA_PROOF_PASS ok\n", encoding="utf-8")
    (forge_run / "verdict.txt").write_text("KT_FORGE_PASS ok\n", encoding="utf-8")

    _make_delivery_lane(run_dir=canonical_run, lane_label="canonical")
    _make_delivery_lane(run_dir=books_run, lane_label="books")
    _make_delivery_lane(run_dir=delta1_run, lane_label="delta1")
    _make_delivery_lane(run_dir=delta2_run, lane_label="delta2")
    _make_delivery_lane(run_dir=forge_run, lane_label="forge")

    out_run = root / "out"
    out_run.mkdir(parents=True, exist_ok=False)

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.authority_grade",
            "--profile",
            "v1",
            "--run-root",
            str(out_run),
            "--status-run",
            str(status_run),
            "--readiness-run",
            str(readiness_run),
            "--canonical-run",
            str(canonical_run),
            "--books-run",
            str(books_run),
            "--delta1-run",
            str(delta1_run),
            "--delta2-run",
            str(delta2_run),
            "--forge-run",
            str(forge_run),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr
    assert (out_run / "reports" / "authority_grade.json").exists()
    verdict = (out_run / "verdict.txt").read_text(encoding="utf-8").strip()
    assert verdict.startswith("KT_AUTHORITY_GRADE_A"), verdict


def test_authority_grade_blocks_on_missing_delivery_artifacts(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "authority_grade_fail" / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)

    status_run = root / "status"
    readiness_run = root / "readiness"
    canonical_run = root / "canonical"
    books_run = root / "books"
    delta1_run = root / "delta1"
    delta2_run = root / "delta2"
    forge_run = root / "forge"
    for r in (status_run, readiness_run, canonical_run, books_run, delta1_run, delta2_run, forge_run):
        r.mkdir(parents=True, exist_ok=False)

    (status_run / "verdict.txt").write_text("KT_STATUS_PASS ok\n", encoding="utf-8")
    (readiness_run / "verdict.txt").write_text("KT_READINESS_PASS grade=A score=100 ok\n", encoding="utf-8")
    (canonical_run / "verdict.txt").write_text("KT_CERTIFY_PASS cmd=certify lane=canonical_hmac ok\n", encoding="utf-8")
    (books_run / "verdict.txt").write_text("KT_BOOKS_SUITE_PASS ok\n", encoding="utf-8")
    (delta1_run / "verdict.txt").write_text("KT_DELTA_PROOF_PASS ok\n", encoding="utf-8")
    (delta2_run / "verdict.txt").write_text("KT_DELTA_PROOF_PASS ok\n", encoding="utf-8")
    (forge_run / "verdict.txt").write_text("KT_FORGE_PASS ok\n", encoding="utf-8")

    # Make only canonical delivery lane, then intentionally omit a required replay wrapper.
    _make_delivery_lane(run_dir=canonical_run, lane_label="canonical")
    (canonical_run / "evidence" / "replay.sh").unlink()

    _make_delivery_lane(run_dir=books_run, lane_label="books")
    _make_delivery_lane(run_dir=delta1_run, lane_label="delta1")
    _make_delivery_lane(run_dir=delta2_run, lane_label="delta2")
    _make_delivery_lane(run_dir=forge_run, lane_label="forge")

    out_run = root / "out"
    out_run.mkdir(parents=True, exist_ok=False)

    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.authority_grade",
            "--profile",
            "v1",
            "--run-root",
            str(out_run),
            "--status-run",
            str(status_run),
            "--readiness-run",
            str(readiness_run),
            "--canonical-run",
            str(canonical_run),
            "--books-run",
            str(books_run),
            "--delta1-run",
            str(delta1_run),
            "--delta2-run",
            str(delta2_run),
            "--forge-run",
            str(forge_run),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 2, p.stdout + "\n" + p.stderr
    report = json.loads((out_run / "reports" / "authority_grade.json").read_text(encoding="utf-8"))
    assert report.get("grade") == "B"
    assert any("DELIVERY_INTEGRITY_FAIL:S0_canonical_hmac" in str(b) for b in report.get("blockers", []))
