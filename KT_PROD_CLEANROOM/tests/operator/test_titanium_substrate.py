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
    p = subprocess.run(
        ["python", "-m", "tools.operator.governance_manifest_verify", "--run-root", str(root / "gov")],
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
