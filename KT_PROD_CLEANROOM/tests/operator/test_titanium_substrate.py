from __future__ import annotations

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

from tools.canonicalize.kt_canonicalize import canonicalize_json_text
from tools.verification.seal_mode_test_roots import write_root


def _py_env(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(repo_root / "KT_PROD_CLEANROOM" / "04_PROD_TEMPLE_V2" / "src"), str(repo_root / "KT_PROD_CLEANROOM")])
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    env["KT_SEAL_MODE"] = "1"
    return env


def test_canonicalizer_normalizes_newlines() -> None:
    assert canonicalize_json_text({"text": "line1\r\nline2\rline3"}) == '{"text":"line1\\nline2\\nline3"}'


def test_program_catalog_and_source_integrity_pass(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)
    env = _py_env(repo_root)

    p1 = subprocess.run(
        ["python", "-m", "tools.operator.program_catalog_verify", "--run-root", str(root / "catalog"), "--strict"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p1.returncode == 0, p1.stdout + "\n" + p1.stderr

    p2 = subprocess.run(
        ["python", "-m", "tools.operator.source_integrity", "verify", "--run-root", str(root / "source")],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p2.returncode == 0, p2.stdout + "\n" + p2.stderr


def test_governance_manifest_verify_fails_closed_without_signatures(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"gov_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)
    env = _py_env(repo_root)
    manifest = json.loads((repo_root / "KT_PROD_CLEANROOM" / "governance" / "governance_manifest.json").read_text(encoding="utf-8"))
    signatures = manifest.get("signatures", [])
    if isinstance(signatures, list):
        for row in signatures:
            if isinstance(row, dict) and str(row.get("signer", "")).strip() == "OP1":
                row["path"] = "KT_PROD_CLEANROOM/governance/missing.sig.OP1"
    manifest_path = root / "governance_manifest_missing_sig.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.governance_manifest_verify",
            "--manifest",
            str(manifest_path),
            "--run-root",
            str(root / "gov"),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode != 0
    assert (root / "gov" / "reports" / "errortaxonomy.json").exists()


def test_bindingloop_verify_passes_on_consistent_payload_hashes(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"binding_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_target = root / "subject"
    (run_target / "delivery").mkdir(parents=True, exist_ok=False)
    (run_target / "evidence").mkdir(parents=True, exist_ok=True)

    constitutional_payload = {"constitution_epoch": 1}
    worm_payload = {"artifacts": ["a", "b"]}
    delivery_payload = {"schema_id": "kt.operator.delivery_manifest.unbound.v1"}

    def payload_sha(obj: dict) -> str:
        from tools.canonicalize.kt_canonicalize import sha256_hex
        from tools.canonicalize.kt_canonicalize import canonicalize_bytes

        return sha256_hex(canonicalize_bytes(obj))

    constitutional = dict(constitutional_payload)
    worm = dict(worm_payload)
    delivery = dict(delivery_payload)

    constitutional["delivery_manifest_payload_sha256"] = payload_sha(delivery_payload)
    worm["constitutional_snapshot_payload_sha256"] = payload_sha(constitutional_payload)
    delivery["worm_manifest_payload_sha256"] = payload_sha(worm_payload)

    (run_target / "evidence" / "constitutional_snapshot.json").write_text(json.dumps(constitutional, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_target / "evidence" / "worm_manifest.json").write_text(json.dumps(worm, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_target / "delivery" / "delivery_manifest.json").write_text(json.dumps(delivery, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)
    p = subprocess.run(
        ["python", "-m", "tools.operator.bindingloop_verify", "--run-dir", str(run_target), "--run-root", str(root / "binding")],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr


def test_bindingloop_verify_fails_on_mutated_delivery_manifest(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"binding_fail_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_target = root / "subject"
    (run_target / "delivery").mkdir(parents=True, exist_ok=False)
    (run_target / "evidence").mkdir(parents=True, exist_ok=True)

    constitutional_payload = {"constitution_epoch": 1}
    worm_payload = {"artifacts": ["a", "b"]}
    delivery_payload = {"schema_id": "kt.operator.delivery_manifest.unbound.v1"}

    def payload_sha(obj: dict) -> str:
        from tools.canonicalize.kt_canonicalize import canonicalize_bytes
        from tools.canonicalize.kt_canonicalize import sha256_hex

        return sha256_hex(canonicalize_bytes(obj))

    constitutional = dict(constitutional_payload)
    worm = dict(worm_payload)
    delivery = dict(delivery_payload)

    constitutional["delivery_manifest_payload_sha256"] = payload_sha(delivery_payload)
    worm["constitutional_snapshot_payload_sha256"] = payload_sha(constitutional_payload)
    delivery["worm_manifest_payload_sha256"] = payload_sha(worm_payload)
    delivery["tampered"] = True

    (run_target / "evidence" / "constitutional_snapshot.json").write_text(json.dumps(constitutional, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_target / "evidence" / "worm_manifest.json").write_text(json.dumps(worm, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_target / "delivery" / "delivery_manifest.json").write_text(json.dumps(delivery, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    env = _py_env(repo_root)
    p = subprocess.run(
        ["python", "-m", "tools.operator.bindingloop_verify", "--run-dir", str(run_target), "--run-root", str(root / "binding")],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode != 0
    assert (root / "binding" / "reports" / "errortaxonomy.json").exists()
    assert (root / "binding" / "reports" / "nextaction.sh").exists()
    assert (root / "binding" / "reports" / "next_action.sh").exists()


def test_hat_demo_emits_titanium_contract_and_attachment_artifacts(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"hat_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_dir = root / "hat_demo"
    env = _py_env(repo_root)

    p1 = subprocess.run(
        ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_dir), "--allow-dirty", "hat-demo"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p1.returncode == 0, p1.stdout + "\n" + p1.stderr

    required = [
        run_dir / "evidence" / "constitutional_snapshot.json",
        run_dir / "evidence" / "worm_manifest.json",
        run_dir / "evidence" / "evidence_core_merkle.json",
        run_dir / "reports" / "operator_fingerprint.json",
        run_dir / "reports" / "operator_intent.json",
        run_dir / "reports" / "bindingloop_check.json",
        run_dir / "reports" / "real_path_attachment_receipt.json",
        run_dir / "reports" / "real_path_trace.json",
        run_dir / "reports" / "real_path_trace.md",
        run_dir / "reports" / "real_path_attachment_matrix.json",
        run_dir / "reports" / "runtime_attach_assertions.json",
        run_dir / "delivery" / "delivery_manifest.json",
        run_dir / "delivery" / "delivery_lint_report.json",
    ]
    missing = [p.as_posix() for p in required if not p.exists()]
    assert not missing, missing

    p2 = subprocess.run(
        ["python", "-m", "tools.delivery.delivery_contract_validator", "--delivery-dir", str(run_dir / "delivery"), "--run-root", str(root / "validate")],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p2.returncode == 0, p2.stdout + "\n" + p2.stderr

    p3 = subprocess.run(
        ["python", "-m", "tools.operator.bindingloop_verify", "--run-dir", str(run_dir), "--run-root", str(root / "binding_verify")],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p3.returncode == 0, p3.stdout + "\n" + p3.stderr


def test_safe_run_hat_demo_marks_safe_run_enforced(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"safe_hat_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_dir = root / "safe_hat_demo"
    env = _py_env(repo_root)

    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--safe-run",
            "--profile",
            "v1",
            "--allow-dirty",
            "--run-root",
            str(run_dir),
            "--assurance-mode",
            "practice",
            "--program",
            "program.hat_demo",
            "--config",
            "{}",
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr

    nested = run_dir / "program_run"
    matrix = json.loads((nested / "reports" / "real_path_attachment_matrix.json").read_text(encoding="utf-8"))
    assertions = json.loads((nested / "reports" / "runtime_attach_assertions.json").read_text(encoding="utf-8"))
    assert matrix["rows"][0]["safe_run_enforced"] is True
    safe_marker = next(x for x in assertions["checks"] if x["check"] == "safe_run_marker_present")
    assert safe_marker["status"] == "PASS"


def test_hermetic_replay_linter_passes_with_matching_mve_environment(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"replay_ok_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_dir = root / "hat_demo"
    env = _py_env(repo_root)

    p1 = subprocess.run(
        ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_dir), "--allow-dirty", "hat-demo"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p1.returncode == 0, p1.stdout + "\n" + p1.stderr

    fingerprint = json.loads((run_dir / "reports" / "operator_fingerprint.json").read_text(encoding="utf-8"))
    mve = {
        "container_image_digest": "local://pytest",
        "python_version": "3.10",
        "os_release": "pytest",
        "mve_environment_fingerprint": fingerprint["mve_environment_fingerprint"],
    }
    mve_path = root / "mve.json"
    mve_path.write_text(json.dumps(mve, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    p2 = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.hermetic_replay_linter",
            "--delivery-dir",
            str(run_dir / "delivery"),
            "--mve",
            str(mve_path),
            "--run-root",
            str(root / "replay"),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p2.returncode == 0, p2.stdout + "\n" + p2.stderr
    receipt = json.loads((root / "replay" / "reports" / "replay_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "PASS"


def test_hermetic_replay_linter_fails_on_mve_environment_mismatch(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"replay_fail_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    run_dir = root / "hat_demo"
    env = _py_env(repo_root)

    p1 = subprocess.run(
        ["python", "-m", "tools.operator.kt_cli", "--run-root", str(run_dir), "--allow-dirty", "hat-demo"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p1.returncode == 0, p1.stdout + "\n" + p1.stderr

    mve = {
        "container_image_digest": "local://pytest",
        "python_version": "3.10",
        "os_release": "pytest",
        "mve_environment_fingerprint": "0" * 64,
    }
    mve_path = root / "mve_bad.json"
    mve_path.write_text(json.dumps(mve, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    p2 = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.hermetic_replay_linter",
            "--delivery-dir",
            str(run_dir / "delivery"),
            "--mve",
            str(mve_path),
            "--run-root",
            str(root / "replay"),
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p2.returncode != 0
    assert (root / "replay" / "reports" / "errortaxonomy.json").exists()
    assert (root / "replay" / "reports" / "next_action.sh").exists()


def test_safe_run_practice_dispatches_catalog_verify(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    root = write_root(repo_root=repo_root) / "titanium_substrate" / f"safe_{tmp_path.name}_{os.getpid()}_{time.time_ns()}"
    root.mkdir(parents=True, exist_ok=False)
    env = _py_env(repo_root)
    p = subprocess.run(
        [
            "python",
            "-m",
            "tools.operator.kt_cli",
            "--safe-run",
            "--profile",
            "v1",
            "--allow-dirty",
            "--run-root",
            str(root / "safe"),
            "--assurance-mode",
            "practice",
            "--program",
            "program.catalog.verify",
            "--config",
            "{}",
        ],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
    )
    assert p.returncode == 0, p.stdout + "\n" + p.stderr
    assert (root / "safe" / "reports" / "operator_preflight.json").exists()


def test_twocleanclone_normalizes_volatile_fields(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(repo_root / "KT_PROD_CLEANROOM"))
    from tools.operator.two_clean_clone_proof import compare_runs

    def build_run(root: Path, label: str, created_suffix: str) -> Path:
        run_dir = root / label
        (run_dir / "delivery" / "PACK").mkdir(parents=True, exist_ok=True)
        (run_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (run_dir / "reports").mkdir(parents=True, exist_ok=True)
        (run_dir / "verdict.txt").write_text("PASS\n", encoding="utf-8")
        (run_dir / "delivery" / "delivery_manifest.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.operator.delivery_manifest.unbound.v1",
                    "profile": "v1",
                    "lane": "canonical_hmac",
                    "lane_id": "KT_OPERATOR_CERTIFY_CANONICAL_HMAC",
                    "program_id": "program.certify.canonical_hmac",
                    "head": "abc123",
                    "pins": {"sealed_commit": "x"},
                    "sweep": {"sweep_id": "X", "sweep_summary_sha256": "y"},
                    "safe_run_enforced": True,
                    "replay_command": "python -m tools.delivery.delivery_linter --delivery-dir .",
                    "run_id": label,
                    "evidence_dir": f"{label}/evidence",
                    "delivery_dir": "delivery/PACK",
                    "delivery_zip": {"path": f"{label}.zip", "sha256": "z"},
                    "verdict": f"VERDICT {label}",
                    "operator_intent_hash": f"intent-{label}",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "delivery" / "delivery_lint_report.json").write_text(
            json.dumps({"status": "PASS", "checks": {"manifest_verified": True}, "inputs": {"delivery_dir": f"/tmp/{label}"}}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (run_dir / "delivery" / "PACK" / "delivery_pack_manifest.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.delivery_pack_manifest.v1",
                    "schema_version_hash": "svh",
                    "bundle_root_hash": "bundle",
                    "created_at": f"2026-03-08T00:00:0{created_suffix}Z",
                    "delivery_pack_id": f"pack-{created_suffix}",
                    "run_protocol_json_hash": "rph",
                    "redaction_rules_version": "v1",
                    "files": [{"path": "a.txt", "sha256": "1", "bytes": 1, "redacted": False}],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "evidence" / "constitutional_snapshot.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.operator.constitutional_snapshot.v1",
                    "created_utc": f"2026-03-08T00:00:0{created_suffix}Z",
                    "program_id": "program.certify.canonical_hmac",
                    "lane_id": "KT_OPERATOR_CERTIFY_CANONICAL_HMAC",
                    "lane_label": "canonical_hmac",
                    "head": "abc123",
                    "constitution_epoch": 1,
                    "governance_manifest_path": f"/tmp/{label}/governance_manifest.json",
                    "governance_manifest_sha256": "govsha",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "evidence" / "worm_manifest.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.operator.worm_manifest.v1",
                    "created_utc": f"2026-03-08T00:00:0{created_suffix}Z",
                    "run_id": label,
                    "program_id": "program.certify.canonical_hmac",
                    "artifacts": [{"path": "x", "sha256": "y"}],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "evidence" / "replay_receipt.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.replay_receipt.v1",
                    "schema_version_hash": "rvh",
                    "lane_id": "KT_OPERATOR_CERTIFY_CANONICAL_HMAC",
                    "replay_command": "python -m tools.delivery.delivery_linter --delivery-dir .",
                    "replay_sh_sha256": "sh",
                    "replay_ps1_sha256": "ps1",
                    "replay_script_hash": "script",
                    "replay_receipt_id": "receipt",
                    "created_at": f"2026-03-08T00:00:0{created_suffix}Z",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "evidence" / "secret_scan_report.json").write_text(
            json.dumps(
                {
                    "schema_id": "kt.secret_scan_report.v1",
                    "status": "PASS",
                    "report_hash": "scanhash",
                    "findings": [],
                    "created_at": f"2026-03-08T00:00:0{created_suffix}Z",
                    "run_id": label,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "reports" / "bindingloop_check.json").write_text(
            json.dumps({"status": "PASS", "claims": {"a": "1"}, "actual": {"a": "1"}}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (run_dir / "reports" / "operator_fingerprint.json").write_text(
            json.dumps(
                {
                    "created_utc": f"2026-03-08T00:00:0{created_suffix}Z",
                    "machine_fingerprint": "machine",
                    "mve_environment_fingerprint": "mve",
                    "operator_id": "op",
                    "runtime_fingerprint": f"volatile-{created_suffix}",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (run_dir / "reports" / "operator_intent.json").write_text(
            json.dumps(
                {
                    "operator_id": "op",
                    "operator_intent_class": "AUDIT",
                    "operator_intent_hash": "intent",
                    "program_id": "program.certify.canonical_hmac",
                    "config_sha256": "cfg",
                    "assurance_mode": "practice",
                    "constitution_epoch": 1,
                    "created_utc": f"2026-03-08T00:00:0{created_suffix}Z",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return run_dir

    run_a = build_run(tmp_path, "run_a", "1")
    run_b = build_run(tmp_path, "run_b", "2")
    report = compare_runs(run_a, run_b)
    assert report["status"] == "PASS", report
