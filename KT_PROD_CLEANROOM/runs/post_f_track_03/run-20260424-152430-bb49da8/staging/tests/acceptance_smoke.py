from __future__ import annotations
import hashlib
import io
import json
import os
import shutil
import signal
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        out, err = proc.communicate(timeout=5)
        raise TimeoutError(f"command timed out: {' '.join(cmd)}\nstdout={out}\nstderr={err}")
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)

def _expected_bundle_digest() -> str:
    include = ["reports", "governance", "packet", "runtime", "docs"]
    bio = io.BytesIO()
    epoch = 1704067200
    with tarfile.open(fileobj=bio, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        for top in include:
            base = ROOT / top
            for path in sorted([p for p in base.rglob("*") if p.is_file()], key=lambda p: p.relative_to(ROOT).as_posix()):
                arcname = f"{top}/{path.relative_to(base).as_posix()}"
                info = tf.gettarinfo(str(path), arcname=arcname)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                tf.addfile(info, io.BytesIO(path.read_bytes()))
    return hashlib.sha256(bio.getvalue()).hexdigest()


def _find_gnu_tar() -> str:
    candidates = []
    direct = shutil.which("tar")
    if direct:
        candidates.append(direct)
    candidates.extend(
        [
            r"C:\Program Files\Git\usr\bin\tar.exe",
            r"C:\Program Files\Git\bin\tar.exe",
        ]
    )
    for candidate in candidates:
        if not candidate or not Path(candidate).exists():
            continue
        probe = subprocess.run([candidate, "--version"], capture_output=True, text=True)
        if probe.returncode == 0 and "GNU tar" in probe.stdout:
            return candidate
    raise FileNotFoundError("GNU tar not found for deterministic bundle validation")

def test_smoke_run_and_bundle_publish():
    proc = _run(["bash", "scripts/run_h1_smoke.sh"], timeout=60)
    assert proc.returncode == 0, proc.stderr
    receipt = json.loads((ROOT / "work/smoke/receipt.json").read_text(encoding="utf-8"))
    assert receipt["provider_calls"]
    assert receipt["receipt"]["signature"]
    rekor = json.loads((ROOT / "mock_rekor/index.json").read_text(encoding="utf-8"))
    assert any(item["bundle"].startswith("proof_bundle_") for item in rekor)



def test_reproducible_bundle_same_seed(tmp_path):
    run_id = json.loads((ROOT / "governance/H1_EXPERIMENT_MANIFEST.json").read_text(encoding="utf-8"))["run_id"]
    tmp_inputs = tmp_path / "inputs"
    tmp_inputs.mkdir()
    for top in ["reports", "governance", "packet", "runtime", "docs"]:
        src = ROOT / top
        dest = tmp_inputs / top
        shutil.copytree(src, dest)
    out_bundle = tmp_path / f"proof_bundle_{run_id}.tar.gz"
    tar_bin = _find_gnu_tar()
    proc = subprocess.run([
        tar_bin,"--sort=name","--mtime=UTC 2024-01-01","--owner=0","--group=0","--numeric-owner",
        "-czf", str(out_bundle), "-C", str(tmp_inputs), "."
    ], cwd=ROOT)
    assert proc.returncode == 0
    actual = hashlib.sha256((ROOT / "bundle" / f"proof_bundle_{run_id}.tar.gz").read_bytes()).hexdigest()
    expected = hashlib.sha256(out_bundle.read_bytes()).hexdigest()
    assert actual == expected


def test_beta_contamination_exit_40(tmp_path):
    packet = json.loads((ROOT / "packet/residual_alpha_packet_spec.json").read_text(encoding="utf-8"))
    packet["rows"][0]["beta"] = True
    packet["rows"][0]["counted"] = True
    p = tmp_path / "beta_packet.json"
    p.write_text(json.dumps(packet), encoding="utf-8")
    proc = _run(["bash", "scripts/run_h1_counted.sh", "--input", str(p)], timeout=60)
    assert proc.returncode == 40

def test_holdout_leakage_exit_50(tmp_path):
    packet = json.loads((ROOT / "packet/residual_alpha_packet_spec.json").read_text(encoding="utf-8"))
    packet["rows"][0]["case_id"] = "CASE-0009"
    packet["rows"][0]["counted"] = True
    packet["rows"][0]["holdout"] = False
    p = tmp_path / "holdout_packet.json"
    p.write_text(json.dumps(packet), encoding="utf-8")
    proc = _run(["bash", "scripts/run_h1_counted.sh", "--input", str(p)], timeout=60)
    assert proc.returncode == 50
