from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "tests"))
import schema_validator as sv  # noqa

def test_schema_examples_validate():
    sv.validate_schema_examples(ROOT / "governance/RMR_SCHEMA_v1.json")

def test_manifest_expected_schema_digest_matches():
    sv.validate_manifest_schema_digest(ROOT / "governance/RMR_SCHEMA_v1.json", ROOT / "governance/H1_EXPERIMENT_MANIFEST.json")

def test_schema_drift_exit_code_30(tmp_path):
    manifest = json.loads((ROOT / "governance/H1_EXPERIMENT_MANIFEST.json").read_text(encoding="utf-8"))
    manifest["expected_schema_digest"] = "0" * 64
    mf = tmp_path / "manifest.json"
    mf.write_text(json.dumps(manifest), encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ROOT / "tests/schema_validator.py"),
                           "--schema", str(ROOT / "governance/RMR_SCHEMA_v1.json"),
                           "--manifest", str(mf)])
    assert proc.returncode == 30

def test_freshness_exit_code_20(tmp_path):
    receipt = json.loads((ROOT / "reports/cohort0_current_head_receipt.json").read_text(encoding="utf-8"))
    receipt["timestamp"] = "2020-01-01T00:00:00Z"
    rp = tmp_path / "receipt.json"
    rp.write_text(json.dumps(receipt), encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ROOT / "tests/schema_validator.py"),
                           "--receipt", str(rp),
                           "--manifest", str(ROOT / "governance/H1_EXPERIMENT_MANIFEST.json")])
    assert proc.returncode == 20

def test_runtime_integrity_exit_code_60(tmp_path):
    bad = {"provider_calls": [], "receipt": {}}
    p = tmp_path / "bad_receipt.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    proc = subprocess.run([sys.executable, str(ROOT / "tests/schema_validator.py"),
                           "--receipt", str(p)])
    assert proc.returncode == 60
